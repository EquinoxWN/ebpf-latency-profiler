// Command ebpf-latency-profiler checks probe layouts and renders in-kernel latency histograms.
package main

import (
	"os"

	"github.com/EquinoxWN/ebpf-latency-profiler/internal/cli"
)

// main runs the command line and exits with its status.
func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
