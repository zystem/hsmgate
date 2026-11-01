package main

import (
	"strings"
	"testing"
	"time"
)

func series(n int, f func(i int) sample) []sample {
	out := make([]sample, n)
	for i := range out {
		out[i] = f(i)
		out[i].T = float64(i) * 15
	}
	return out
}

func newHarness(rounds, errs uint64) *harness {
	h := &harness{o: options{duration: 40 * 15 * time.Second, warmup: 0.25, maxErrRate: 0.0005, maxGoroutines: 25, maxFDs: 10, maxHeapMiB: 8, maxRSSMiB: 16, maxGrowthPct: 20, maxLatencyX: 3},
		errMsg: map[string]int{}, lat: map[string][]latency{}}
	h.rounds.Store(rounds)
	h.errs.Store(errs)
	return h
}

func joined(f []string) string { return strings.Join(f, "\n") }

func TestJudgeSeesALeakAndNotNoise(t *testing.T) {
	const mib = 1 << 20
	flat := func(i int) sample {
		return sample{Goroutines: 14 + float64(i%3), HeapAlloc: (20 + float64(i%4)) * mib, Resident: (60 + float64(i%5)) * mib, FDs: 11}
	}
	if f := newHarness(1000, 0).judge(series(40, flat)); len(f) != 0 {
		t.Errorf("a flat run failed: %s", joined(f))
	}
	for name, c := range map[string]struct {
		f    func(i int) sample
		want string
	}{
		"goroutines": {func(i int) sample { s := flat(i); s.Goroutines += float64(i * 3); return s }, "goroutines grew"},
		"fds":        {func(i int) sample { s := flat(i); s.FDs += float64(i * 2); return s }, "open fds grew"},
		"heap":       {func(i int) sample { s := flat(i); s.HeapAlloc += float64(i*2) * mib; return s }, "live heap grew"},
		"resident":   {func(i int) sample { s := flat(i); s.Resident += float64(i*4) * mib; return s }, "resident grew"},
	} {
		if f := newHarness(1000, 0).judge(series(40, c.f)); !strings.Contains(joined(f), c.want) {
			t.Errorf("%s: a leak was not seen: %s", name, joined(f))
		}
	}
	// a big heap that grew a little is not a leak (the percentage guards it), and neither is a small one that doubled by a few MiB
	big := func(i int) sample { s := flat(i); s.HeapAlloc = (400 + float64(i)) * mib; return s }
	if f := newHarness(1000, 0).judge(series(40, big)); len(f) != 0 {
		t.Errorf("slow growth of a large heap failed: %s", joined(f))
	}
	small := func(i int) sample {
		s := flat(i)
		s.HeapAlloc = 2 * mib
		if i > 30 {
			s.HeapAlloc = 6 * mib
		}
		return s
	}
	if f := newHarness(1000, 0).judge(series(40, small)); len(f) != 0 {
		t.Errorf("a few MiB failed: %s", joined(f))
	}
}

func TestJudgeCountsErrorsAndNeedsSamples(t *testing.T) {
	flat := func(i int) sample { return sample{Goroutines: 14, HeapAlloc: 1 << 21, Resident: 1 << 26, FDs: 11} }
	if f := newHarness(10000, 50).judge(series(40, flat)); !strings.Contains(joined(f), "rounds failed") {
		t.Errorf("errors were not counted: %s", joined(f))
	}
	if f := newHarness(0, 0).judge(nil); len(f) == 0 {
		t.Error("a run with no round passed")
	}
	if f := newHarness(1000, 0).judge(series(3, flat)); !strings.Contains(joined(f), "too few samples") {
		t.Errorf("too few samples: %s", joined(f))
	}
}
