#!/usr/bin/env bash
# Loads the probes with bpftool, runs one workload per probe, then dumps and renders the
# in-kernel histograms. Linux only, run as root (CI runs it with sudo on ubuntu-24.04).
# usage: probe-run.sh <bpf object> <ebpf-latency-profiler binary> <output dir>
set -euo pipefail

OBJ=${1:?bpf object}
BIN=${2:?profiler binary}
OUT=${3:?output dir}
BPFTOOL=${BPFTOOL:-bpftool}
PIN=/sys/fs/bpf/ebpf-latency-profiler

[ "$(id -u)" -eq 0 ] || { echo "probe-run.sh must run as root" >&2; exit 1; }
mkdir -p "$OUT/work"

# Removing the pinned links detaches the programs; removing the pinned maps frees them.
cleanup() { rm -rf "$PIN" "$OUT/work"; }
trap cleanup EXIT

mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
cleanup
mkdir -p "$PIN" "$OUT/work"
if ! out=$("$BPFTOOL" prog loadall "$OBJ" "$PIN/progs" pinmaps "$PIN/maps" autoattach 2>&1); then
  echo "$out"
  echo "::error title=bpftool prog loadall::$(echo "$out" | tail -n 8 | tr '\n' ' ')"
  exit 1
fi
echo "loaded and attached:"
ls "$PIN/progs" "$PIN/maps"

# runqlat: twice as many busy loops as CPUs for 3 seconds, so runnable tasks wait for a CPU.
n=$(( $(nproc) * 2 ))
for _ in $(seq "$n"); do timeout 3 sh -c 'while :; do :; done' & done
wait

# biolatency: direct I/O bypasses the page cache, so every block becomes a device request.
dd if=/dev/zero of="$OUT/work/io.bin" bs=4k count=4096 oflag=direct status=none
dd if="$OUT/work/io.bin" of=/dev/null bs=4k iflag=direct status=none

# fsynclat: O_DSYNC writes call vfs_fsync_range after every block.
dd if=/dev/zero of="$OUT/work/sync.bin" bs=4k count=200 oflag=dsync status=none

status=0
for probe in runqlat:runq_hist biolatency:bio_hist fsynclat:fsync_hist; do
  name=${probe%%:*}
  map=${probe##*:}
  "$BPFTOOL" -j map dump pinned "$PIN/maps/$map" > "$OUT/$name.json"
  "$BIN" render -probe "$name" -in "$OUT/$name.json" | tee "$OUT/$name.txt"
  if line=$("$BIN" render -probe "$name" -in "$OUT/$name.json" -format line -min-count 1); then
    echo "::notice title=$name on kernel $(uname -r)::$line"
  else
    echo "::error title=$name on kernel $(uname -r)::no events counted ($line)"
    status=1
  fi
done
chmod -R a+rX "$OUT"
exit "$status"
