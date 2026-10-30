package probes

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/EquinoxWN/ebpf-latency-profiler/internal/hist"
)

// source returns the BPF C program the catalog describes.
func source(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../bpf/latency.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestEveryProgramExistsInBPFSource(t *testing.T) {
	src := source(t)
	re := regexp.MustCompile(`SEC\("([a-z_]+/[a-z_/]+)"\)\s*\nint (\w+)\(`)
	inSource := map[string]string{}
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		inSource[m[1]] = m[2]
	}
	inCatalog := 0
	for _, p := range All {
		for _, prog := range p.Programs {
			inCatalog++
			if fn, ok := inSource[prog.Section]; !ok || fn != prog.Func {
				t.Errorf("%s: section %s func %s not in latency.bpf.c (found %q)", p.Name, prog.Section, prog.Func, fn)
			}
		}
	}
	if inCatalog != len(inSource) {
		t.Errorf("catalog lists %d programs, source has %d", inCatalog, len(inSource))
	}
}

func TestEveryMapExistsInBPFSource(t *testing.T) {
	src := source(t)
	for _, p := range All {
		for _, m := range []string{p.HistMap, p.StartMap} {
			if !strings.Contains(src, "} "+m+` SEC(".maps");`) {
				t.Errorf("%s: map %s not declared", p.Name, m)
			}
			if len(m) > 15 {
				t.Errorf("map name %s longer than the kernel's 15-character limit", m)
			}
		}
		idx := strings.Index(src, "} "+p.HistMap+" SEC")
		decl := src[strings.LastIndex(src[:idx], "struct {"):idx]
		if !strings.Contains(decl, "BPF_MAP_TYPE_PERCPU_ARRAY") || !strings.Contains(decl, "MAX_SLOTS") {
			t.Errorf("%s must be a per-CPU array of MAX_SLOTS entries", p.HistMap)
		}
	}
}

func TestMaxSlotsMatchesGo(t *testing.T) {
	m := regexp.MustCompile(`#define MAX_SLOTS (\d+)`).FindStringSubmatch(source(t))
	if m == nil {
		t.Fatal("MAX_SLOTS not defined")
	}
	if n, _ := strconv.Atoi(m[1]); n != hist.MaxSlots {
		t.Fatalf("MAX_SLOTS %d in C, %d in Go", n, hist.MaxSlots)
	}
}

func TestFieldAssertsMatchCatalog(t *testing.T) {
	re := regexp.MustCompile(`(?m)^FIELD_ASSERT\((\w+), (\w+), (\d+), (\d+)\);`)
	asserted := map[string]string{}
	for _, m := range re.FindAllStringSubmatch(source(t), -1) {
		asserted[m[1]+"."+m[2]] = m[3] + "/" + m[4]
	}
	used := map[string]bool{}
	for _, p := range All {
		for _, tp := range p.Tracepoints {
			for _, f := range tp.Fields {
				key := tp.CStruct + "." + f.Name
				used[key] = true
				if want := strconv.Itoa(f.Offset) + "/" + strconv.Itoa(f.Size); asserted[key] != want {
					t.Errorf("%s/%s: C asserts %q, catalog expects %s", tp.Group, tp.Event, asserted[key], want)
				}
			}
		}
	}
	for key := range asserted {
		if !used[key] {
			t.Errorf("FIELD_ASSERT %s is not in the catalog", key)
		}
	}
}

func TestCheckKernelAgainstFixtures(t *testing.T) {
	checked, problems, err := CheckKernel(os.DirFS("../tpformat/testdata/tracefs"))
	if err != nil || len(problems) != 0 || checked != 5 {
		t.Fatalf("checked %d, problems %v, err %v", checked, problems, err)
	}
}

func TestCheckKernelReportsLayoutChange(t *testing.T) {
	fsys := fstest.MapFS{}
	for _, p := range All {
		for _, tp := range p.Tracepoints {
			name := "events/" + tp.Group + "/" + tp.Event + "/format"
			body := "name: " + tp.Event + "\n"
			for _, f := range tp.Fields {
				off := f.Offset
				if tp.Event == "sched_switch" && f.Name == "next_pid" {
					off += 8 // simulate a kernel that added a field
				}
				body += "\tfield:int " + f.Name + ";\toffset:" + strconv.Itoa(off) + ";\tsize:" + strconv.Itoa(f.Size) + ";\tsigned:1;\n"
			}
			fsys[name] = &fstest.MapFile{Data: []byte(body)}
		}
	}
	_, problems, err := CheckKernel(fsys)
	if err != nil || len(problems) != 1 || !strings.Contains(problems[0], "next_pid at offset 64") {
		t.Fatalf("problems %v err %v", problems, err)
	}
	delete(fsys, "events/block/block_rq_issue/format")
	if _, _, err := CheckKernel(fsys); err == nil {
		t.Fatal("missing tracepoint must be an error")
	}
}

func TestByName(t *testing.T) {
	for _, name := range []string{"runqlat", "biolatency", "fsynclat"} {
		if p, err := ByName(name); err != nil || p.Name != name {
			t.Errorf("ByName(%q) = %v, %v", name, p.Name, err)
		}
	}
	if _, err := ByName("tcpretrans"); err == nil {
		t.Error("unknown probe must fail")
	}
}
