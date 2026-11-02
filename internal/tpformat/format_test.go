package tpformat

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// load parses a fixture format file.
func load(t *testing.T, group, event string) *Format {
	t.Helper()
	f, err := os.Open("testdata/tracefs/events/" + group + "/" + event + "/format")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	format, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	return format
}

func TestParseSchedSwitch(t *testing.T) {
	f := load(t, "sched", "sched_switch")
	if f.Name != "sched_switch" || f.ID != 316 || len(f.Fields) != 11 {
		t.Fatalf("got name %q id %d fields %d", f.Name, f.ID, len(f.Fields))
	}
	want := map[string][3]int{"common_pid": {4, 4, 1}, "prev_comm": {8, 16, 0}, "prev_state": {32, 8, 1}, "next_pid": {56, 4, 1}}
	for name, w := range want {
		fld, ok := f.Field(name)
		signed := 0
		if fld.Signed {
			signed = 1
		}
		if !ok || fld.Offset != w[0] || fld.Size != w[1] || signed != w[2] {
			t.Errorf("%s = %+v, want %v", name, fld, w)
		}
	}
}

func TestParseDataLocField(t *testing.T) {
	f := load(t, "block", "block_rq_issue")
	fld, ok := f.Field("cmd")
	if !ok || fld.Decl != "__data_loc char[] cmd" || fld.Offset != 60 {
		t.Fatalf("cmd = %+v", fld)
	}
	if fld, ok := f.Field("rwbs"); !ok || fld.Size != 8 {
		t.Fatalf("rwbs = %+v", fld)
	}
}

func TestCheckAcceptsMatchingLayout(t *testing.T) {
	f := load(t, "block", "block_rq_complete")
	if p := f.Check([]Expect{{"dev", 8, 4}, {"sector", 16, 8}}); len(p) != 0 {
		t.Fatalf("unexpected problems %v", p)
	}
}

func TestCheckReportsMovedAndMissingFields(t *testing.T) {
	f := load(t, "sched", "sched_switch")
	p := f.Check([]Expect{{"prev_state", 32, 4}, {"next_pid", 60, 4}, {"no_such", 0, 4}})
	if len(p) != 3 || !strings.Contains(p[0], "size 8") || !strings.Contains(p[2], "missing") {
		t.Fatalf("problems %v", p)
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"empty":       "",
		"no fields":   "name: x\nID: 1\nformat:\n",
		"bad id":      "name: x\nID: one\n",
		"bad offset":  "name: x\n\tfield:int a;\toffset:x;\tsize:4;\tsigned:1;\n",
		"no size":     "name: x\n\tfield:int a;\toffset:4;\tsigned:1;\n",
		"negative":    "name: x\n\tfield:int a;\toffset:-4;\tsize:4;\tsigned:1;\n",
		"bad name":    "name: x\n\tfield:int a-b;\toffset:4;\tsize:4;\tsigned:1;\n",
		"long line":   "name: x\n\tfield:int a;" + strings.Repeat("x", 2<<20) + "\n",
		"no field id": "name: x\n\tfield:;\toffset:4;\tsize:4;\tsigned:1;\n",
	}
	for name, in := range cases {
		if _, err := Parse(strings.NewReader(in)); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: want ErrFormat, got %v", name, err)
		}
	}
}

func TestFieldNameForms(t *testing.T) {
	cases := map[string]string{
		"char comm[16]":         "comm",
		"__data_loc char[] cmd": "cmd",
		"const char * name":     "name",
		"void *skbaddr":         "skbaddr",
		"unsigned long long ts": "ts",
		// An unsized array outside __data_loc has no fixed size to read by offset.
		"char flex[]": "",
	}
	for decl, want := range cases {
		if got := fieldName(decl); got != want {
			t.Errorf("fieldName(%q) = %q, want %q", decl, got, want)
		}
	}
}

func FuzzParse(f *testing.F) {
	b, err := os.ReadFile("testdata/tracefs/events/sched/sched_switch/format")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte("name: a\n\tfield:int x;\toffset:1;\tsize:2;\tsigned:0;\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		format, err := Parse(strings.NewReader(string(data)))
		if err == nil && (format.Name == "" || len(format.Fields) == 0) {
			t.Fatal("accepted a format without name or fields")
		}
	})
}
