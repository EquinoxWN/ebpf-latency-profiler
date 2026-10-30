// Package probes lists the eBPF programs in bpf/latency.bpf.c and the kernel layouts they assume.
package probes

import (
	"fmt"
	"io/fs"
	"path"

	"github.com/EquinoxWN/ebpf-latency-profiler/internal/tpformat"
)

// Program is one BPF program: its ELF section (attach point) and C function name.
type Program struct {
	Section string
	Func    string
}

// Tracepoint is a tracepoint read by offset, with the C struct that mirrors its record.
type Tracepoint struct {
	Group   string
	Event   string
	CStruct string
	Fields  []tpformat.Expect
}

// Probe is one latency measurement: the programs that feed it and the histogram it fills.
type Probe struct {
	Name        string
	Description string
	Unit        string
	HistMap     string
	StartMap    string
	Programs    []Program
	Tracepoints []Tracepoint
}

// wakeupFields is the sched_wakeup layout used by both wakeup tracepoints.
var wakeupFields = []tpformat.Expect{{Name: "pid", Offset: 24, Size: 4}}

// blockFields is the leading block_rq_* layout used as the in-flight request key.
var blockFields = []tpformat.Expect{{Name: "dev", Offset: 8, Size: 4}, {Name: "sector", Offset: 16, Size: 8}}

// All is the probe catalog; it must match bpf/latency.bpf.c (checked by tests).
var All = []Probe{
	{
		Name:        "runqlat",
		Description: "run-queue latency: time from a task becoming runnable to running on a CPU",
		Unit:        "usecs",
		HistMap:     "runq_hist",
		StartMap:    "runq_start",
		Programs: []Program{
			{Section: "tracepoint/sched/sched_wakeup", Func: "tp_wakeup"},
			{Section: "tracepoint/sched/sched_wakeup_new", Func: "tp_wakeup_new"},
			{Section: "tracepoint/sched/sched_switch", Func: "tp_switch"},
		},
		Tracepoints: []Tracepoint{
			{Group: "sched", Event: "sched_wakeup", CStruct: "sched_wakeup_args", Fields: wakeupFields},
			{Group: "sched", Event: "sched_wakeup_new", CStruct: "sched_wakeup_args", Fields: wakeupFields},
			{Group: "sched", Event: "sched_switch", CStruct: "sched_switch_args", Fields: []tpformat.Expect{
				{Name: "prev_pid", Offset: 24, Size: 4},
				{Name: "prev_state", Offset: 32, Size: 8},
				{Name: "next_pid", Offset: 56, Size: 4},
			}},
		},
	},
	{
		Name:        "biolatency",
		Description: "block I/O latency: time from a request being issued to the device to its completion",
		Unit:        "usecs",
		HistMap:     "bio_hist",
		StartMap:    "bio_start",
		Programs: []Program{
			{Section: "tracepoint/block/block_rq_issue", Func: "tp_rq_issue"},
			{Section: "tracepoint/block/block_rq_complete", Func: "tp_rq_complete"},
		},
		Tracepoints: []Tracepoint{
			{Group: "block", Event: "block_rq_issue", CStruct: "block_rq_args", Fields: blockFields},
			{Group: "block", Event: "block_rq_complete", CStruct: "block_rq_args", Fields: blockFields},
		},
	},
	{
		Name:        "fsynclat",
		Description: "fsync latency: time spent in vfs_fsync_range, timed with a kprobe and kretprobe",
		Unit:        "usecs",
		HistMap:     "fsync_hist",
		StartMap:    "fsync_start",
		Programs: []Program{
			{Section: "kprobe/vfs_fsync_range", Func: "kp_fsync"},
			{Section: "kretprobe/vfs_fsync_range", Func: "kr_fsync"},
		},
	},
}

// ByName finds a probe by name.
func ByName(name string) (Probe, error) {
	for _, p := range All {
		if p.Name == name {
			return p, nil
		}
	}
	return Probe{}, fmt.Errorf("unknown probe %q (want runqlat, biolatency or fsynclat)", name)
}

// CheckKernel compares every tracepoint layout with the format files under a tracefs root.
func CheckKernel(tracefs fs.FS) (checked int, problems []string, err error) {
	for _, p := range All {
		for _, tp := range p.Tracepoints {
			name := path.Join("events", tp.Group, tp.Event, "format")
			f, err := tracefs.Open(name)
			if err != nil {
				return checked, problems, fmt.Errorf("%s: %w", name, err)
			}
			format, perr := tpformat.Parse(f)
			_ = f.Close()
			if perr != nil {
				return checked, problems, fmt.Errorf("%s: %w", name, perr)
			}
			problems = append(problems, format.Check(tp.Fields)...)
			checked++
		}
	}
	return checked, problems, nil
}
