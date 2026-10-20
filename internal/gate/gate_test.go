package gate

import (
	"context"
	"testing"
	"time"
)

func TestTheLineIsFinite(t *testing.T) {
	g := New(2, 100*time.Millisecond)
	r1, ok1 := g.Take(context.Background())
	r2, ok2 := g.Take(context.Background())
	if !ok1 || !ok2 || g.Running() != 2 {
		t.Fatalf("two places run: %v %v %d", ok1, ok2, g.Running())
	}
	// two more may wait (the line is twice as long as the number that run); they give up after the wait
	done := make(chan bool, 4)
	for i := 0; i < 2; i++ {
		go func() { _, ok := g.Take(context.Background()); done <- ok }()
	}
	time.Sleep(20 * time.Millisecond)
	if g.InLine() != 4 {
		t.Errorf("in line: %d", g.InLine())
	}
	// the fifth is refused at once, not made to wait
	start := time.Now()
	if _, ok := g.Take(context.Background()); ok || time.Since(start) > 50*time.Millisecond {
		t.Errorf("the line was full: ok=%v after %v", ok, time.Since(start))
	}
	for i := 0; i < 2; i++ {
		if <-done {
			t.Error("a waiter got a place that was not free")
		}
	}
	r1()
	r2()
	if g.Running() != 0 || g.InLine() != 0 {
		t.Errorf("after the release: %d %d", g.Running(), g.InLine())
	}
	// a waiter whose caller is gone gives up and takes nothing
	r1, _ = g.Take(context.Background())
	r2, _ = g.Take(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := g.Take(ctx); ok {
		t.Error("a cancelled caller was given a place")
	}
	r1()
	r2()
	if g.InLine() != 0 {
		t.Errorf("a cancelled caller left its place: %d", g.InLine())
	}
}

func TestNoGateIsNoLimit(t *testing.T) {
	var g *Gate
	if r, ok := g.Take(context.Background()); !ok {
		t.Error("a nil gate refused")
	} else {
		r()
	}
}
