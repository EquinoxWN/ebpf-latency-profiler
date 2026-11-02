package hist

import (
	"bytes"
	"errors"
	"math/bits"
	"math/rand"
	"strings"
	"testing"
)

func TestLog2MatchesMathBits(t *testing.T) {
	cases := []uint64{0, 1, 2, 3, 4, 7, 8, 1023, 1024, 1 << 31, 1<<32 - 1, 1 << 32, 1<<63 + 5, ^uint64(0)}
	r := rand.New(rand.NewSource(1))
	for range 100000 {
		cases = append(cases, r.Uint64()>>uint(r.Intn(64)))
	}
	for _, v := range cases {
		want := uint32(0)
		if v > 0 {
			want = uint32(bits.Len64(v) - 1)
		}
		if got := Log2(v); got != want {
			t.Fatalf("Log2(%d) = %d, want %d", v, got, want)
		}
	}
}

func TestSlotBoundaries(t *testing.T) {
	cases := []struct {
		v    uint64
		slot int
	}{{0, 0}, {1, 0}, {2, 1}, {3, 1}, {4, 2}, {1000, 9}, {1023, 9}, {1024, 10}, {1 << 31, 31}, {1 << 32, 31}, {1<<33 - 1, 31}, {1 << 40, 31}}
	for _, c := range cases {
		if got := SlotFor(c.v); got != c.slot {
			t.Errorf("SlotFor(%d) = %d, want %d", c.v, got, c.slot)
		}
	}
}

func TestEveryValueFallsInsideItsBucket(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	for range 50000 {
		v := r.Uint64() >> uint(r.Intn(64))
		s := SlotFor(v)
		if v < Low(s) || v > High(s) {
			t.Fatalf("value %d in slot %d outside [%d, %d]", v, s, Low(s), High(s))
		}
	}
}

func TestBucketsTileTheRange(t *testing.T) {
	for i := 1; i < MaxSlots; i++ {
		if Low(i) != High(i-1)+1 {
			t.Fatalf("gap between slot %d and %d", i-1, i)
		}
	}
	if High(MaxSlots-1) != ^uint64(0) {
		t.Fatal("last slot must be open-ended")
	}
}

func TestAddRejectsBadSlotAndOverflow(t *testing.T) {
	h := New("usecs")
	if err := h.Add(MaxSlots, 1); !errors.Is(err, ErrSlot) {
		t.Fatalf("want ErrSlot, got %v", err)
	}
	if err := h.Add(-1, 1); !errors.Is(err, ErrSlot) {
		t.Fatalf("want ErrSlot, got %v", err)
	}
	if err := h.Add(3, ^uint64(0)); err != nil {
		t.Fatal(err)
	}
	if err := h.Add(3, 1); err == nil {
		t.Fatal("want overflow error")
	}
}

func TestMergeReportsOverflow(t *testing.T) {
	a, b := New("usecs"), New("usecs")
	if err := a.Add(4, ^uint64(0)); err != nil {
		t.Fatal(err)
	}
	b.Observe(20) // slot 4
	if err := a.Merge(b); err == nil {
		t.Fatal("merge into a full slot must fail")
	}
}

func TestMergeIsCommutative(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	a, b := New("usecs"), New("usecs")
	for range 1000 {
		a.Observe(uint64(r.Intn(1 << 20)))
		b.Observe(uint64(r.Intn(1 << 10)))
	}
	ab, ba := New("usecs"), New("usecs")
	for _, step := range []struct{ dst, x, y *Hist }{{ab, a, b}, {ba, b, a}} {
		if err := step.dst.Merge(step.x); err != nil {
			t.Fatal(err)
		}
		if err := step.dst.Merge(step.y); err != nil {
			t.Fatal(err)
		}
	}
	if ab.Counts != ba.Counts || ab.Total() != 2000 {
		t.Fatalf("merge mismatch: total %d", ab.Total())
	}
}

func TestPercentileBucketBounds(t *testing.T) {
	h := New("usecs")
	for range 90 {
		h.Observe(5) // slot 2: 4..7
	}
	for range 10 {
		h.Observe(3000) // slot 11: 2048..4095
	}
	cases := []struct {
		p    float64
		want uint64
	}{{1, 7}, {50, 7}, {90, 7}, {90.5, 4095}, {99, 4095}, {100, 4095}}
	for _, c := range cases {
		got, ok := h.Percentile(c.p)
		if !ok || got != c.want {
			t.Errorf("p%v = %d,%v want %d", c.p, got, ok, c.want)
		}
	}
	if _, ok := New("usecs").Percentile(50); ok {
		t.Error("empty histogram has no percentile")
	}
	if _, ok := h.Percentile(0); ok {
		t.Error("p0 is not defined")
	}
}

func TestPercentileIsMonotonic(t *testing.T) {
	r := rand.New(rand.NewSource(4))
	h := New("usecs")
	for range 5000 {
		h.Observe(uint64(r.ExpFloat64() * 500))
	}
	prev := uint64(0)
	for p := 1.0; p <= 100; p += 0.5 {
		v, ok := h.Percentile(p)
		if !ok || v < prev {
			t.Fatalf("p%v = %d below previous %d", p, v, prev)
		}
		prev = v
	}
}

func TestRenderLayout(t *testing.T) {
	h := New("usecs")
	_ = h.Add(0, 2)
	_ = h.Add(2, 8)
	_ = h.Add(3, 4)
	var buf bytes.Buffer
	if err := h.Render(&buf); err != nil {
		t.Fatal(err)
	}
	want := "                   usecs : count     distribution\n" +
		"         0 -> 1          : 2         |**********                              |\n" +
		"         2 -> 3          : 0         |                                        |\n" +
		"         4 -> 7          : 8         |****************************************|\n" +
		"         8 -> 15         : 4         |********************                    |\n"
	if buf.String() != want {
		t.Fatalf("render mismatch:\n%s\nwant:\n%s", buf.String(), want)
	}
}

func TestRenderEmptyAndLastSlot(t *testing.T) {
	var buf bytes.Buffer
	if err := New("usecs").Render(&buf); err != nil || buf.String() != "(no events)\n" {
		t.Fatalf("got %q, %v", buf.String(), err)
	}
	h := New("usecs")
	h.Observe(1 << 50)
	buf.Reset()
	if err := h.Render(&buf); err != nil || !strings.Contains(buf.String(), "-> inf") {
		t.Fatalf("last slot should render as open-ended: %q", buf.String())
	}
}
