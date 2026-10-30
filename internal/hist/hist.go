// Package hist models the log2 latency histograms that the eBPF programs build in the kernel.
package hist

import (
	"errors"
	"fmt"
	"io"
	"math/bits"
	"strings"
)

// MaxSlots is the number of buckets per histogram; it must equal MAX_SLOTS in bpf/latency.bpf.c.
const MaxSlots = 32

// barWidth is the width of the distribution column, as in the bcc tools.
const barWidth = 40

// Hist is a log2 histogram: Counts[i] holds values in [Low(i), High(i)].
type Hist struct {
	Unit   string
	Counts [MaxSlots]uint64
}

// ErrSlot reports a slot index outside the histogram.
var ErrSlot = errors.New("slot out of range")

// Log2 mirrors log2_u64 in bpf/latency.bpf.c: floor(log2(v)), 0 for v == 0.
func Log2(v uint64) uint32 {
	hi := uint32(v >> 32)
	if hi != 0 {
		return log2u32(hi) + 32
	}
	return log2u32(uint32(v))
}

// log2u32 mirrors the branch-free log2_u32 in the BPF program.
func log2u32(v uint32) uint32 {
	b := func(c bool) uint32 {
		if c {
			return 1
		}
		return 0
	}
	r := b(v > 0xFFFF) << 4
	v >>= r
	shift := b(v > 0xFF) << 3
	v >>= shift
	r |= shift
	shift = b(v > 0xF) << 2
	v >>= shift
	r |= shift
	shift = b(v > 0x3) << 1
	v >>= shift
	r |= shift
	r |= v >> 1
	return r
}

// SlotFor returns the bucket the kernel uses for a value, clamped to the last slot.
func SlotFor(v uint64) int {
	s := int(Log2(v))
	if s >= MaxSlots {
		return MaxSlots - 1
	}
	return s
}

// Low returns the smallest value counted in slot i.
func Low(i int) uint64 {
	if i <= 0 {
		return 0
	}
	return 1 << uint(i)
}

// High returns the largest value counted in slot i (the last slot is open-ended).
func High(i int) uint64 {
	if i >= MaxSlots-1 {
		return ^uint64(0)
	}
	return (uint64(1) << uint(i+1)) - 1
}

// New returns an empty histogram in the given unit.
func New(unit string) *Hist { return &Hist{Unit: unit} }

// Add counts n more values in slot i.
func (h *Hist) Add(slot int, n uint64) error {
	if slot < 0 || slot >= MaxSlots {
		return fmt.Errorf("%w: %d", ErrSlot, slot)
	}
	sum, carry := bits.Add64(h.Counts[slot], n, 0)
	if carry != 0 {
		return fmt.Errorf("slot %d: count overflow", slot)
	}
	h.Counts[slot] = sum
	return nil
}

// Observe counts one raw value the way the kernel program would.
func (h *Hist) Observe(v uint64) { h.Counts[SlotFor(v)]++ }

// Merge adds every bucket of o into h.
func (h *Hist) Merge(o *Hist) error {
	for i, c := range o.Counts {
		if err := h.Add(i, c); err != nil {
			return err
		}
	}
	return nil
}

// Total returns the number of values counted.
func (h *Hist) Total() uint64 {
	var t uint64
	for _, c := range h.Counts {
		t += c
	}
	return t
}

// Percentile returns the upper bound of the bucket holding the p-th percentile (0 < p <= 100).
func (h *Hist) Percentile(p float64) (uint64, bool) {
	total := h.Total()
	if total == 0 || p <= 0 || p > 100 {
		return 0, false
	}
	// Rank of the target value, rounded up so p=100 is the last value.
	rank := uint64(p / 100 * float64(total))
	if float64(rank) < p/100*float64(total) {
		rank++
	}
	if rank == 0 {
		rank = 1
	}
	var seen uint64
	for i, c := range h.Counts {
		seen += c
		if seen >= rank {
			return High(i), true
		}
	}
	return High(MaxSlots - 1), true
}

// lastUsed returns the index of the highest non-empty slot, or -1.
func (h *Hist) lastUsed() int {
	for i := MaxSlots - 1; i >= 0; i-- {
		if h.Counts[i] != 0 {
			return i
		}
	}
	return -1
}

// Render writes the histogram in the layout of bcc's print_log2_hist.
func (h *Hist) Render(w io.Writer) error {
	last := h.lastUsed()
	if last < 0 {
		_, err := fmt.Fprintf(w, "(no events)\n")
		return err
	}
	var peak uint64
	for _, c := range h.Counts[:last+1] {
		peak = max(peak, c)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%24s : count     distribution\n", h.Unit)
	for i := 0; i <= last; i++ {
		stars := int(float64(h.Counts[i]) / float64(peak) * barWidth)
		hi := fmt.Sprint(High(i))
		if i == MaxSlots-1 {
			hi = "inf"
		}
		fmt.Fprintf(&b, "%10d -> %-10s : %-9d |%-*s|\n", Low(i), hi, h.Counts[i], barWidth, strings.Repeat("*", stars))
	}
	_, err := io.WriteString(w, b.String())
	return err
}
