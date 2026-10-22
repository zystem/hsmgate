package generation

import (
	"testing"
	"time"
)

func TestARequestHoldsItsGenerationAndSetWaitsForIt(t *testing.T) {
	var h Holder[string]
	if _, _, ok := h.Acquire(); ok {
		t.Fatal("a generation before the first Set")
	}
	h.Set("one")
	v, release, ok := h.Acquire()
	if !ok || v != "one" {
		t.Fatal(v, ok)
	}
	wait := h.Set("two")
	if v2, rel2, _ := h.Acquire(); v2 != "two" {
		t.Errorf("a new request got %q", v2)
	} else {
		rel2()
	}
	done := make(chan struct{})
	go func() { wait(); close(done) }()
	select {
	case <-done:
		t.Fatal("Set did not wait for the request of the old generation")
	case <-time.After(100 * time.Millisecond):
	}
	release()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the wait did not end when the request did")
	}
}
