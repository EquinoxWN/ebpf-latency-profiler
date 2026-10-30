// Package bpfdump turns `bpftool map dump -j` output of a histogram map into a hist.Hist.
package bpfdump

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/EquinoxWN/ebpf-latency-profiler/internal/hist"
)

// MaxInput bounds the bytes read from a dump (a 32-slot map on 4096 CPUs stays far below it).
const MaxInput = 16 << 20

// maxCPUs bounds the per-CPU values accepted for one entry.
const maxCPUs = 8192

// ErrFormat reports a dump that does not look like a histogram map.
var ErrFormat = errors.New("bpfdump: unexpected format")

// cpuValue is one CPU's copy of a per-CPU map value.
type cpuValue struct {
	CPU   int      `json:"cpu"`
	Value []string `json:"value"`
}

// entry is one key of a bpftool JSON dump; Value is set for plain maps, Values for per-CPU maps.
type entry struct {
	Key    []string   `json:"key"`
	Value  []string   `json:"value"`
	Values []cpuValue `json:"values"`
}

// Parse reads a bpftool JSON dump of a u32 -> u64 array and sums per-CPU copies into a histogram.
func Parse(r io.Reader, unit string) (*hist.Hist, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxInput+1))
	if err != nil {
		return nil, fmt.Errorf("bpfdump: read: %w", err)
	}
	if len(data) > MaxInput {
		return nil, fmt.Errorf("%w: input larger than %d bytes", ErrFormat, MaxInput)
	}
	var entries []entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if len(entries) > hist.MaxSlots {
		return nil, fmt.Errorf("%w: %d entries, histogram has %d slots", ErrFormat, len(entries), hist.MaxSlots)
	}
	h := hist.New(unit)
	seen := make(map[uint32]bool, len(entries))
	for i, e := range entries {
		slot, err := decodeU32(e.Key)
		if err != nil {
			return nil, fmt.Errorf("entry %d key: %w", i, err)
		}
		if seen[slot] {
			return nil, fmt.Errorf("%w: duplicate key %d", ErrFormat, slot)
		}
		seen[slot] = true
		total, err := entryTotal(e)
		if err != nil {
			return nil, fmt.Errorf("entry %d (slot %d): %w", i, slot, err)
		}
		if err := h.Add(int(slot), total); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrFormat, err)
		}
	}
	return h, nil
}

// entryTotal sums an entry's value over all CPUs.
func entryTotal(e entry) (uint64, error) {
	switch {
	case e.Value != nil && e.Values == nil:
		return decodeU64(e.Value)
	case e.Values != nil && e.Value == nil:
		if len(e.Values) > maxCPUs {
			return 0, fmt.Errorf("%w: %d CPU values", ErrFormat, len(e.Values))
		}
		var sum uint64
		for _, cv := range e.Values {
			v, err := decodeU64(cv.Value)
			if err != nil {
				return 0, fmt.Errorf("cpu %d: %w", cv.CPU, err)
			}
			if sum+v < sum {
				return 0, fmt.Errorf("%w: count overflow", ErrFormat)
			}
			sum += v
		}
		return sum, nil
	default:
		return 0, fmt.Errorf("%w: entry needs exactly one of value or values", ErrFormat)
	}
}

// decodeBytes turns bpftool's ["0x2a", ...] hex strings into bytes.
func decodeBytes(hexes []string, size int) ([]byte, error) {
	if len(hexes) != size {
		return nil, fmt.Errorf("%w: %d bytes, want %d", ErrFormat, len(hexes), size)
	}
	out := make([]byte, size)
	for i, s := range hexes {
		if !strings.HasPrefix(s, "0x") || len(s) != 4 {
			return nil, fmt.Errorf("%w: byte %q", ErrFormat, s)
		}
		b, err := strconv.ParseUint(s[2:], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("%w: byte %q", ErrFormat, s)
		}
		out[i] = byte(b)
	}
	return out, nil
}

// decodeU32 decodes a 4-byte little-endian key.
func decodeU32(hexes []string) (uint32, error) {
	b, err := decodeBytes(hexes, 4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

// decodeU64 decodes an 8-byte little-endian value.
func decodeU64(hexes []string) (uint64, error) {
	b, err := decodeBytes(hexes, 8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

// Encode writes a histogram as bpftool would dump a per-CPU array on the given CPU count (test fixtures).
func Encode(w io.Writer, h *hist.Hist, cpus int) error {
	if cpus < 1 || cpus > maxCPUs {
		return fmt.Errorf("cpus %d out of range", cpus)
	}
	entries := make([]entry, 0, hist.MaxSlots)
	for slot, count := range h.Counts {
		e := entry{Key: hexBytes(binary.LittleEndian.AppendUint32(nil, uint32(slot)))}
		for cpu := range cpus {
			share := count / uint64(cpus)
			if cpu == 0 {
				share += count % uint64(cpus)
			}
			e.Values = append(e.Values, cpuValue{CPU: cpu, Value: hexBytes(binary.LittleEndian.AppendUint64(nil, share))})
		}
		entries = append(entries, e)
	}
	enc := json.NewEncoder(w)
	return enc.Encode(entries)
}

// hexBytes formats bytes the way bpftool does.
func hexBytes(b []byte) []string {
	out := make([]string, len(b))
	for i, x := range b {
		out[i] = fmt.Sprintf("0x%02x", x)
	}
	return out
}
