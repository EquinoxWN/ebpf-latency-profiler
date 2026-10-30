.PHONY: setup lint test fuzz audit build bpf check-format probe-run ci

ARCH := $(shell uname -m 2>/dev/null)
BPF_CLANG ?= clang

setup:
	go mod download

lint:
	@files="$$(gofmt -l cmd internal)"; test -z "$$files" || (echo "$$files"; echo "run gofmt -w"; exit 1)
	go vet ./...
	GOOS=linux go vet ./...

test:
	go test -count=1 ./...

fuzz:
	go test -run '^$$' -fuzz FuzzParse -fuzztime 30s ./internal/bpfdump
	go test -run '^$$' -fuzz FuzzParse -fuzztime 30s ./internal/tpformat

# Known vulnerabilities in the code paths actually called (needs Go 1.26.10, as in CI).
audit:
	go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...

build:
	go build -trimpath -o bin/ebpf-latency-profiler ./cmd/ebpf-latency-profiler

# Linux with clang and libbpf headers: compile the eBPF programs (BTF via -g).
bpf: bin/latency.bpf.o

bin/latency.bpf.o: bpf/latency.bpf.c
	mkdir -p bin
	$(BPF_CLANG) -O2 -g -Wall -Werror -target bpf -I/usr/include/$(ARCH)-linux-gnu -c $< -o $@

# Linux, root: compare tracepoint layouts with the running kernel.
check-format: build
	sudo ./bin/ebpf-latency-profiler check-format

# Linux, root, bpftool: load, attach, run the workloads, render the histograms.
probe-run: bpf build
	sudo BPFTOOL="$${BPFTOOL:-bpftool}" ./scripts/probe-run.sh bin/latency.bpf.o bin/ebpf-latency-profiler .tmp/probe-run

ci: setup lint test
