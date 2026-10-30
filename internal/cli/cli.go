// Package cli implements the ebpf-latency-profiler command line.
package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/EquinoxWN/ebpf-latency-profiler/internal/bpfdump"
	"github.com/EquinoxWN/ebpf-latency-profiler/internal/hist"
	"github.com/EquinoxWN/ebpf-latency-profiler/internal/probes"
)

// Exit codes.
const (
	ExitOK       = 0
	ExitError    = 1
	ExitUsage    = 2
	ExitTooFew   = 3
	ExitMismatch = 4
)

const usage = `usage: ebpf-latency-profiler <command> [flags]

commands:
  probes        list the eBPF probes, their attach points and histogram maps
  check-format  compare tracepoint layouts the programs assume with the running kernel
  render        print a histogram from 'bpftool map dump -j' output
`

// Summary is the machine-readable result of render.
type Summary struct {
	Probe  string   `json:"probe"`
	Unit   string   `json:"unit"`
	Events uint64   `json:"events"`
	P50    *uint64  `json:"p50_upper_bound,omitempty"`
	P99    *uint64  `json:"p99_upper_bound,omitempty"`
	Counts []uint64 `json:"counts"`
}

// Run executes one command and returns the process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	switch args[0] {
	case "probes":
		return listProbes(stdout)
	case "check-format":
		return checkFormat(args[1:], stdout, stderr)
	case "render":
		return render(args[1:], stdin, stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return ExitOK
	default:
		fmt.Fprintf(stderr, "unknown command %q\n%s", args[0], usage)
		return ExitUsage
	}
}

// listProbes prints the catalog.
func listProbes(w io.Writer) int {
	for _, p := range probes.All {
		fmt.Fprintf(w, "%s: %s\n  histogram map: %s (%s, log2 buckets)\n", p.Name, p.Description, p.HistMap, p.Unit)
		for _, prog := range p.Programs {
			fmt.Fprintf(w, "  %-36s %s\n", prog.Section, prog.Func)
		}
	}
	return ExitOK
}

// checkFormat verifies the tracepoint layouts under a tracefs root.
func checkFormat(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check-format", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("tracefs", "", "tracefs root (default: /sys/kernel/tracing, then /sys/kernel/debug/tracing)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	dir := *root
	if dir == "" {
		dir = "/sys/kernel/tracing"
		if _, err := os.Stat(dir + "/events"); err != nil {
			dir = "/sys/kernel/debug/tracing"
		}
	}
	checked, problems, err := probes.CheckKernel(os.DirFS(dir))
	if err != nil {
		fmt.Fprintf(stderr, "check-format: %v\n", err)
		return ExitError
	}
	for _, p := range problems {
		fmt.Fprintf(stdout, "MISMATCH %s\n", p)
	}
	if len(problems) > 0 {
		return ExitMismatch
	}
	fmt.Fprintf(stdout, "OK %d tracepoint layouts match %s\n", checked, dir)
	return ExitOK
}

// render reads a bpftool dump and prints the histogram.
func render(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("render", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("probe", "", "probe the map belongs to: runqlat, biolatency or fsynclat")
	in := fs.String("in", "-", "bpftool JSON dump file, - for stdin")
	format := fs.String("format", "text", "output: text, line or json")
	minCount := fs.Uint64("min-count", 0, "exit 3 if fewer events were counted")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	probe, err := probes.ByName(*name)
	if err != nil {
		fmt.Fprintf(stderr, "render: %v\n", err)
		return ExitUsage
	}
	if *format != "text" && *format != "line" && *format != "json" {
		fmt.Fprintf(stderr, "render: unknown format %q\n", *format)
		return ExitUsage
	}
	h, err := readDump(*in, stdin, probe.Unit)
	if err != nil {
		fmt.Fprintf(stderr, "render: %v\n", err)
		return ExitError
	}
	s := summarize(probe.Name, h)
	if err := write(stdout, *format, probe, h, s); err != nil {
		fmt.Fprintf(stderr, "render: %v\n", err)
		return ExitError
	}
	if s.Events < *minCount {
		fmt.Fprintf(stderr, "render: %s counted %d events, want at least %d\n", probe.Name, s.Events, *minCount)
		return ExitTooFew
	}
	return ExitOK
}

// readDump parses a dump from a file or stdin.
func readDump(path string, stdin io.Reader, unit string) (*hist.Hist, error) {
	if path == "-" {
		return bpfdump.Parse(stdin, unit)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New(path + " is not a regular file")
	}
	return bpfdump.Parse(f, unit)
}

// summarize computes event count and percentile bucket bounds.
func summarize(name string, h *hist.Hist) Summary {
	s := Summary{Probe: name, Unit: h.Unit, Events: h.Total(), Counts: h.Counts[:]}
	if v, ok := h.Percentile(50); ok {
		s.P50 = &v
	}
	if v, ok := h.Percentile(99); ok {
		s.P99 = &v
	}
	return s
}

// write prints the result in the chosen format.
func write(w io.Writer, format string, p probes.Probe, h *hist.Hist, s Summary) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(s)
	case "line":
		_, err := fmt.Fprintln(w, line(s))
		return err
	default:
		if _, err := fmt.Fprintf(w, "%s: %s\n%s\n\n", p.Name, p.Description, line(s)); err != nil {
			return err
		}
		return h.Render(w)
	}
}

// line formats the one-line summary used in CI annotations.
func line(s Summary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s events=%d", s.Probe, s.Events)
	if s.P50 != nil {
		fmt.Fprintf(&b, " p50<=%d p99<=%d (%s, bucket upper bounds)", *s.P50, *s.P99, s.Unit)
	}
	return b.String()
}
