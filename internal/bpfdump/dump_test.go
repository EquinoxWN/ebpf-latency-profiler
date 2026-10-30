package bpfdump

import (
	"bytes"
	"errors"
	"math/rand"
	"os"
	"strings"
	"testing"

	"github.com/EquinoxWN/ebpf-latency-profiler/internal/hist"
)

// open reads a fixture from testdata.
func open(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestParsePerCPUSumsAllCPUs(t *testing.T) {
	h, err := Parse(open(t, "percpu_fixture.json"), "usecs")
	if err != nil {
		t.Fatal(err)
	}
	if h.Counts[0] != 5 || h.Counts[1] != 266 || h.Counts[5] != 7 || h.Total() != 278 {
		t.Fatalf("unexpected counts %v", h.Counts[:6])
	}
}

func TestParsePlainArray(t *testing.T) {
	h, err := Parse(open(t, "array_fixture.json"), "usecs")
	if err != nil {
		t.Fatal(err)
	}
	if h.Counts[2] != 42 || h.Counts[3] != 1 || h.Total() != 43 {
		t.Fatalf("unexpected counts %v", h.Counts[:4])
	}
}

func TestParseEmptyDump(t *testing.T) {
	h, err := Parse(strings.NewReader("[]"), "usecs")
	if err != nil || h.Total() != 0 {
		t.Fatalf("empty dump: %v %v", h, err)
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	u64 := `["0x01","0x00","0x00","0x00","0x00","0x00","0x00","0x00"]`
	cases := map[string]string{
		"not json":       `{`,
		"object":         `{"key":1}`,
		"short key":      `[{"key":["0x00"],"value":` + u64 + `}]`,
		"slot too big":   `[{"key":["0x20","0x00","0x00","0x00"],"value":` + u64 + `}]`,
		"bad hex":        `[{"key":["0xzz","0x00","0x00","0x00"],"value":` + u64 + `}]`,
		"no prefix":      `[{"key":["00","0x00","0x00","0x00"],"value":` + u64 + `}]`,
		"short value":    `[{"key":["0x00","0x00","0x00","0x00"],"value":["0x01"]}]`,
		"no value":       `[{"key":["0x00","0x00","0x00","0x00"]}]`,
		"both values":    `[{"key":["0x00","0x00","0x00","0x00"],"value":` + u64 + `,"values":[]}]`,
		"duplicate slot": `[{"key":["0x00","0x00","0x00","0x00"],"value":` + u64 + `},{"key":["0x00","0x00","0x00","0x00"],"value":` + u64 + `}]`,
	}
	for name, in := range cases {
		if _, err := Parse(strings.NewReader(in), "usecs"); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: want ErrFormat, got %v", name, err)
		}
	}
}

func TestParseRejectsOversizedInput(t *testing.T) {
	big := bytes.Repeat([]byte(" "), MaxInput+10)
	if _, err := Parse(bytes.NewReader(big), "usecs"); !errors.Is(err, ErrFormat) {
		t.Fatalf("want ErrFormat, got %v", err)
	}
}

func TestPerCPUOverflowDetected(t *testing.T) {
	max := `["0xff","0xff","0xff","0xff","0xff","0xff","0xff","0xff"]`
	in := `[{"key":["0x00","0x00","0x00","0x00"],"values":[{"cpu":0,"value":` + max + `},{"cpu":1,"value":` + max + `}]}]`
	if _, err := Parse(strings.NewReader(in), "usecs"); !errors.Is(err, ErrFormat) {
		t.Fatalf("want overflow error, got %v", err)
	}
}

func TestEncodeParseRoundTrip(t *testing.T) {
	r := rand.New(rand.NewSource(5))
	for _, cpus := range []int{1, 2, 7, 64} {
		h := hist.New("usecs")
		for range 3000 {
			h.Observe(uint64(r.ExpFloat64() * 2000))
		}
		var buf bytes.Buffer
		if err := Encode(&buf, h, cpus); err != nil {
			t.Fatal(err)
		}
		got, err := Parse(&buf, "usecs")
		if err != nil {
			t.Fatal(err)
		}
		if got.Counts != h.Counts {
			t.Fatalf("cpus=%d: round trip mismatch", cpus)
		}
	}
	if err := Encode(&bytes.Buffer{}, hist.New("usecs"), 0); err == nil {
		t.Fatal("zero CPUs must be rejected")
	}
}

func FuzzParse(f *testing.F) {
	for _, name := range []string{"percpu_fixture.json", "array_fixture.json"} {
		b, err := os.ReadFile("testdata/" + name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte(`[{"key":["0x00","0x00","0x00","0x00"],"values":[{"cpu":0}]}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := Parse(bytes.NewReader(data), "usecs")
		if err == nil && h == nil {
			t.Fatal("nil histogram without error")
		}
	})
}
