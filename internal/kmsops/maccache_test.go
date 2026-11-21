package kmsops

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/zystem/hsmgate/internal/backend"
)

// An expired entry is wiped by the cache at its time, with nobody asking for it (the review of 2026-11-21, finding 3).
func TestMacCacheWipesTheExpiredByItself(t *testing.T) {
	k := NewMacCache()
	key := bytes.Repeat([]byte{7}, 32)
	k.Put("a", key, time.Now(), 60*time.Millisecond, 0)
	k.Put("b", key, time.Now(), time.Hour, 0)
	if k.Len() != 2 {
		t.Fatalf("%d entries", k.Len())
	}
	deadline := time.Now().Add(3 * time.Second)
	for k.Len() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if k.Len() != 1 {
		t.Fatalf("the expired entry is still held after its time: %d entries", k.Len())
	}
	if _, ok := k.Get("b", time.Now(), 0); !ok {
		t.Error("the live entry was wiped with the expired one")
	}
	k.Clear()
	if k.Len() != 0 || k.timer != nil {
		t.Error("a clear leaves an entry or a timer")
	}
}

// With a clock of the caller's own (a test gives the face one), Sweep wipes by that clock.
func TestMacCacheSweepByTheClockOfTheCaller(t *testing.T) {
	k := NewMacCache()
	fake := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	k.Put("a", []byte("0123456789abcdef0123456789abcdef"), fake, time.Minute, 0)
	k.Sweep(fake.Add(30 * time.Second))
	if k.Len() != 1 {
		t.Fatal("swept before its time")
	}
	k.Sweep(fake.Add(time.Minute))
	if k.Len() != 0 {
		t.Fatal("not swept at its time")
	}
}

// A request of the generation before a reload reads nothing and puts nothing.
func TestMacCacheEpochs(t *testing.T) {
	k := NewMacCache()
	key := []byte("0123456789abcdef0123456789abcdef")
	now := time.Now()
	k.Put("id", key, now, time.Hour, 0)
	next := k.Next()
	if next != 1 {
		t.Fatalf("next epoch %d", next)
	}
	k.Advance(next)
	if k.Len() != 0 {
		t.Error("a reload left what the old generation derived")
	}
	k.Put("late", key, now, time.Hour, 0) // the old generation, after the reload
	if k.Len() != 0 {
		t.Error("the old generation put a key after the reload")
	}
	k.Put("new", key, now, time.Hour, 1)
	if _, ok := k.Get("new", now, 0); ok {
		t.Error("the old generation read what the new one derived")
	}
	if _, ok := k.Get("new", now, 1); !ok {
		t.Error("the new generation cannot read its own key")
	}
}

// slowToken stops in the ECDH of the token until it is let go: a request that is in the middle of deriving a MAC key when a reload comes.
type slowToken struct {
	backend.Token
	in      chan struct{}
	proceed chan struct{}
}

func (s slowToken) Derive(label string, peer []byte) ([]byte, error) {
	s.in <- struct{}{}
	<-s.proceed
	return s.Token.Derive(label, peer)
}

// The case of the review: a request of the previous generation finishes its derivation after the reload, and must not leave its key in the cache of the new generation.
func TestMacKeyOfThePreviousGenerationIsNotCachedAfterAReload(t *testing.T) {
	s := rig(t)
	slow := slowToken{Token: s.Tokens["soft"], in: make(chan struct{}, 1), proceed: make(chan struct{})}
	s.Tokens = map[string]backend.Token{"soft": slow}
	done := make(chan error, 1)
	go func() {
		_, _, e := s.MacGenerate(context.Background(), "app", "mac", 0, []byte("m"))
		if e != nil {
			done <- e
			return
		}
		done <- nil
	}()
	select {
	case <-slow.in:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never reached the token")
	}
	// the reload: the new generation is published, then the epoch moves on
	s.Macs.Advance(s.Macs.Next())
	close(slow.proceed)
	if err := <-done; err != nil {
		t.Fatalf("%v", err)
	}
	if s.Macs.Len() != 0 {
		t.Errorf("the key derived under the previous generation is in the cache of the next: %d entries", s.Macs.Len())
	}
}
