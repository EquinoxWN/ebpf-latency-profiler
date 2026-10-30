# RFC 0001: ebpf-latency-profiler design

- **Status:** Accepted for M1
- **Author:** EquinoxWN
- **Created:** 2026-10-23

## Problem

A service's p99 latency rises while CPU, memory and request rates look normal. The delay is often
outside the application: a runnable thread waits for a CPU, a disk request sits in the device queue,
or an `fsync` blocks on the journal. Application metrics cannot see these waits, and tracing every
kernel event to user space costs too much to leave on.

**Users:** engineers who debug latency on Linux hosts and want kernel-side evidence without changing
application code.

**Critical-to-quality measures (Define):**

| CTQ | Target | M1 status |
|---|---|---|
| Kernel-side aggregation: user space reads only histogram counters, never single events | 32 counters per CPU per probe | Met by design: per-CPU array maps of `MAX_SLOTS` (32) entries |
| Bounded kernel memory | Start-time maps capped at 10,240 entries each (LRU eviction) | Met by design; checked by a test that reads the C source |
| Program layout matches the kernel it runs on | 0 field mismatches before loading | `check-format` gate in CI on the runner kernel |
| Probes load, attach and count events on a real kernel | ≥1 event per probe in the CI workload | CI-only (`probes` job); not verified on the author's Windows machine |
| User-space parsers never crash on bad input | 0 panics under fuzzing | Fuzzed locally (see results) |
| Overhead per event | Measured against bcc in M3 | Not measured yet |

## Goals (M1)

- Small eBPF programs attach to kernel tracepoints and kprobes to time three waits:
  run-queue delay (`sched_wakeup`, `sched_wakeup_new`, `sched_switch` tracepoints),
  block I/O latency (`block_rq_issue`, `block_rq_complete` tracepoints) and
  fsync latency (`kprobe`/`kretprobe` on `vfs_fsync_range`).
- Latency histograms are built inside the kernel in per-CPU BPF array maps (log2 buckets in
  microseconds), so the per-event cost is a hash lookup, a subtraction and a counter increment.
- A Go command line that checks the tracepoint layouts the programs assume against the running
  kernel and renders the histograms from `bpftool map dump -j` output.

## Non-goals (M1)

- A Go loader with cilium/ebpf, CO-RE relocations and a Prometheus exporter (M2).
- uprobes that link kernel delays to requests (M2).
- The fault-injection lab and the comparison against bcc's `runqlat` and `biolatency` (M3).
- TCP retransmit tracing (later).
- Running as a hosted service.

## Design

```
bpf/latency.bpf.c ──clang -target bpf──▶ latency.bpf.o ──bpftool prog loadall … autoattach──▶ kernel
                                                                                               │
   tracepoint / kprobe fires ─▶ start time in LRU hash ─▶ end event: delta ─▶ log2 slot ─▶ per-CPU array
                                                                                               │
bpftool -j map dump ─▶ ebpf-latency-profiler render ─▶ histogram, event count, p50/p99 bucket bounds
```

1. **Start events** store `bpf_ktime_get_ns()` in a bounded `BPF_MAP_TYPE_LRU_HASH`, keyed by pid
   (run queue), by `(dev, sector)` (block request) or by `pid_tgid` (fsync).
2. **End events** look the start time up, compute the delta, convert it to microseconds, take
   `floor(log2)` with a branch-free bit trick (no loops for the verifier) and increment that slot of
   a `BPF_MAP_TYPE_PERCPU_ARRAY`. Per-CPU copies avoid cache-line contention between CPUs.
3. **Run-queue rules** follow bcc's `runqlat`: a task is enqueued on wakeup, and on `sched_switch`
   when it leaves the CPU still runnable (low byte of `prev_state` is 0, which covers preemption).
4. **Tracepoint records are read by fixed offsets.** Each record is mirrored by a C struct whose
   field offsets and sizes are pinned with `_Static_assert` (`FIELD_ASSERT`). The Go catalog
   (`internal/probes`) holds the same numbers; a Go test checks that the catalog and the C
   asserts agree, and `check-format` checks the catalog against
   `/sys/kernel/tracing/events/*/*/format` on the running kernel. A layout change fails fast.
5. **User space** parses bpftool's JSON (hex byte arrays for keys and values, one value per CPU for
   per-CPU maps), sums the CPUs, and prints a bcc-style histogram plus bucket-bound percentiles.

## Alternatives considered

| Option | Why not (for M1) |
|---|---|
| Send every event to user space through a ring buffer and aggregate in Go | Per-event copies and wakeups cost far more than a counter increment, and a busy host produces millions of scheduler events per second. In-kernel histograms keep the transfer to 32 counters per CPU. |
| `tp_btf` / BTF-enabled raw tracepoints with CO-RE (`BPF_CORE_READ` on `struct task_struct`) | The most portable option and the plan for M2, but it needs `vmlinux.h` generation and a CO-RE-aware loader. Classic tracepoints with offset checks need neither and the layouts used have been stable for years; `check-format` makes the assumption explicit. |
| bpftrace one-liners (`hist()` built in) | Quick to write, but the result is not a reusable program with tests, and it adds a runtime (LLVM) on every target host. |
| Global (shared) array with atomic adds instead of per-CPU arrays | Simpler to read, but every CPU writes the same cache lines. Per-CPU arrays cost a little more memory (32 × 8 bytes × CPUs) and the reader sums the copies. |
| Load with cilium/ebpf from Go already in M1 | See ADR 0002: M1 uses bpftool so the loader and its portability work stay one M2 deliverable. |

## Measurement plan

- **Locally (Windows, no eBPF):** unit, property and fuzz tests for the histogram model, the bpftool
  dump parser, the tracefs format parser, the catalog-to-C consistency and the CLI.
- **CI (ubuntu-24.04, sudo):** compile with clang, run `check-format` against the runner kernel,
  load and attach with `bpftool prog loadall … autoattach`, run a CPU-contention, direct-I/O and
  `O_DSYNC` workload, dump the maps and require at least one event per probe. Results are printed as
  `::notice` annotations.
- **M3:** inject CPU contention, a slow disk and packet loss; compare against bcc `runqlat` and
  `biolatency`; measure per-event overhead.

## Milestones

- **M1:** eBPF programs on tracepoints and kprobes; in-kernel log2 histograms; layout check and
  histogram rendering in Go.
- **M2:** Go loader with cilium/ebpf (CO-RE, one binary across kernels) and a Prometheus exporter;
  uprobes on a sample service.
- **M3:** fault-injection lab and cross-check against bcc tools.

## Risks and open questions

- **Block request key.** `(dev, sector)` identifies a request in flight; two requests to the same
  sector on the same device at once would share a slot, and a partially completed request reports
  the remaining sector. bcc keys by `struct request *`, which needs BTF or kprobes (M2).
- **Tracepoint layout drift.** A kernel that moves `prev_state` or `next_pid` breaks the offsets;
  `check-format` detects it, and M2's CO-RE path removes the dependency.
- **bpftool availability.** The CI job installs `linux-tools-$(uname -r)`; a runner image without a
  matching package falls back to `linux-tools-azure`. If both fail the job fails visibly.
- **Overhead** is argued from design, not measured, until M3.
