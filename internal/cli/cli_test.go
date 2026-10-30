package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EquinoxWN/ebpf-latency-profiler/internal/bpfdump"
	"github.com/EquinoxWN/ebpf-latency-profiler/internal/hist"
)

const fixture = "../bpfdump/testdata/percpu_fixture.json"

// run calls Run and captures its output.
func run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestRenderTextFromFile(t *testing.T) {
	code, out, errs := run(t, "", "render", "-probe", "runqlat", "-in", fixture)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	for _, want := range []string{"runqlat events=278 p50<=3 p99<=63 (usecs, bucket upper bounds)", "usecs : count", "2 -> 3          : 266"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestRenderJSONFromStdin(t *testing.T) {
	h := hist.New("usecs")
	for v := range uint64(1000) {
		h.Observe(v)
	}
	var dump bytes.Buffer
	if err := bpfdump.Encode(&dump, h, 4); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, dump.String(), "render", "-probe", "biolatency", "-format", "json")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var s Summary
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		t.Fatal(err)
	}
	if s.Events != 1000 || s.Probe != "biolatency" || *s.P50 != 511 || *s.P99 != 1023 || len(s.Counts) != hist.MaxSlots {
		t.Fatalf("summary %+v", s)
	}
}

func TestRenderMinCount(t *testing.T) {
	code, out, _ := run(t, "[]", "render", "-probe", "fsynclat", "-format", "line", "-min-count", "1")
	if code != ExitTooFew || strings.TrimSpace(out) != "fsynclat events=0" {
		t.Fatalf("exit %d out %q", code, out)
	}
	if code, _, _ := run(t, "", "render", "-probe", "runqlat", "-in", fixture, "-min-count", "278"); code != ExitOK {
		t.Fatalf("exactly min-count events must pass, got %d", code)
	}
}

func TestRenderErrors(t *testing.T) {
	cases := []struct {
		stdin string
		args  []string
		code  int
	}{
		{"", []string{"render", "-probe", "nope", "-in", fixture}, ExitUsage},
		{"", []string{"render", "-probe", "runqlat", "-format", "xml", "-in", fixture}, ExitUsage},
		{"{", []string{"render", "-probe", "runqlat"}, ExitError},
		{"", []string{"render", "-probe", "runqlat", "-in", "does-not-exist.json"}, ExitError},
		{"", []string{"render", "-probe", "runqlat", "-in", "."}, ExitError},
		{"", []string{"render", "-bogus"}, ExitUsage},
	}
	for _, c := range cases {
		if code, _, _ := run(t, c.stdin, c.args...); code != c.code {
			t.Errorf("%v: exit %d, want %d", c.args, code, c.code)
		}
	}
}

func TestCheckFormatFixturesAndMismatch(t *testing.T) {
	code, out, errs := run(t, "", "check-format", "-tracefs", "../tpformat/testdata/tracefs")
	if code != ExitOK || !strings.HasPrefix(out, "OK 5 tracepoint layouts match") {
		t.Fatalf("exit %d out %q err %q", code, out, errs)
	}
	dir := t.TempDir()
	src := "../tpformat/testdata/tracefs/events"
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.Contains(p, "sched_switch") {
			b = bytes.Replace(b, []byte("long prev_state;\toffset:32;\tsize:8"), []byte("unsigned int prev_state;\toffset:32;\tsize:4"), 1)
		}
		rel, _ := filepath.Rel(src, p)
		dst := filepath.Join(dir, "events", rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	code, out, _ = run(t, "", "check-format", "-tracefs", dir)
	if code != ExitMismatch || !strings.Contains(out, "MISMATCH sched_switch: field prev_state at offset 32 size 4") {
		t.Fatalf("exit %d out %q", code, out)
	}
	if code, _, _ := run(t, "", "check-format", "-tracefs", filepath.Join(dir, "missing")); code != ExitError {
		t.Fatalf("missing tracefs: exit %d", code)
	}
}

func TestProbesAndUsage(t *testing.T) {
	code, out, _ := run(t, "", "probes")
	if code != ExitOK || !strings.Contains(out, "kretprobe/vfs_fsync_range") || !strings.Contains(out, "runq_hist") {
		t.Fatalf("probes output %q", out)
	}
	if code, _, _ := run(t, ""); code != ExitUsage {
		t.Fatal("no command must be a usage error")
	}
	if code, _, _ := run(t, "", "frobnicate"); code != ExitUsage {
		t.Fatal("unknown command must be a usage error")
	}
	if code, out, _ := run(t, "", "help"); code != ExitOK || !strings.Contains(out, "check-format") {
		t.Fatal("help must print usage")
	}
}
