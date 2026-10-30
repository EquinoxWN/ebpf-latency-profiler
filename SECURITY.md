# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub:
**Security > Report a vulnerability** on this repository
(`https://github.com/EquinoxWN/ebpf-latency-profiler/security/advisories/new`). Do not open a public issue.

Include what you found, how to reproduce it, and the impact you expect. You will get an answer
within 7 days. Fixes are released as soon as they are ready, and you are credited unless you ask
not to be.

## Supported versions

This project is pre-1.0. Only the latest commit on `main` receives fixes.

## Scope

- **In scope:** crashes, hangs or unbounded memory use in the Go parsers on crafted input
  (`bpftool` dumps, tracefs format files); eBPF programs that read outside their tracepoint record,
  grow maps without bound or leave programs attached after `scripts/probe-run.sh` exits.
- **Out of scope:** the fact that loading eBPF programs needs root (that is how the kernel works),
  performance problems and missing features listed on the roadmap.

## How this repository protects itself

- Every GitHub Action is pinned to a full commit SHA, and workflows run with read-only
  permissions and without persisted credentials.
- Dependabot update pull requests are paused (`open-pull-requests-limit: 0`) so the repository keeps a single `main` branch; dependencies are updated by hand and checked by the CI audit.
- CI runs lint, tests and a known-vulnerability audit (`make audit`) on every push and pull request.
- The Go module has no third-party dependencies; parsers bound their input size and are fuzzed.
