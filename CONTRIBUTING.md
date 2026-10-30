# Contributing

Thanks for helping. This is a Go and eBPF (C) project; issues and pull requests are welcome.

## Set up and check your change

The Go side needs Go 1.23 or newer (CI uses 1.26.10) and runs on any OS. Caches stay in git-ignored
folders inside the repo.

```bash
make setup   # download modules (none today beyond the standard library)
make lint    # gofmt, go vet for the host and for linux
make test    # full Go test suite
make audit   # known-vulnerability check (as in CI)
make fuzz    # optional: 30 s of fuzzing per parser
```

Changes to `bpf/latency.bpf.c` need Linux, root, clang, libbpf headers and bpftool v7+:

```bash
make bpf check-format probe-run
```

If you change a tracepoint struct or a map, update `internal/probes/catalog.go` too: the catalog
tests fail until the C `FIELD_ASSERT`s, `SEC()` names and maps match it.

A pull request is ready when `make lint` and `make test` pass and both CI jobs are green.

## Guidelines

- Keep each change focused; explain the problem it solves in the pull request.
- Add or update a test for every behaviour change, and update `docs/results/` when numbers change.
- Significant design changes need an ADR in `docs/adr/` (copy `0001` for the format).
- Keep function comments to one short phrase; let names and tests explain the rest.
- Report security problems privately, as described in [SECURITY.md](SECURITY.md).

By contributing you agree that your work is released under the [MIT License](LICENSE).
