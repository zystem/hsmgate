// Package gate is the finite line to the tokens that all faces share: at most `concurrent` operations run and as many wait; the next is refused at once, and one that
// waits longer than the queue time gives up. A card does one operation at a time, so without a line a crowd of requests would pile up in front of it.
package gate

import (
	"context"
	"time"
)

type Gate struct {
	sem   chan struct{} // running
	adm   chan struct{} // running and waiting: twice as many
	queue time.Duration
}

func New(concurrent int, wait time.Duration) *Gate {
	return &Gate{sem: make(chan struct{}, concurrent), adm: make(chan struct{}, 2*concurrent), queue: wait}
}

// Take waits for a turn. ok is false when the line is full or the wait is over or ctx is done; the caller then answers "busy". release must be called when the work is done.
func (g *Gate) Take(ctx context.Context) (release func(), ok bool) {
	if g == nil {
		return func() {}, true
	}
	select {
	case g.adm <- struct{}{}:
	default:
		return nil, false
	}
	t := time.NewTimer(g.queue)
	defer t.Stop()
	select {
	case g.sem <- struct{}{}:
		return func() { <-g.sem; <-g.adm }, true
	case <-t.C:
	case <-ctx.Done():
	}
	<-g.adm
	return nil, false
}

// Running and InLine are for tests and for status: how many operations are running, and how many places of the line are taken.
func (g *Gate) Running() int { return len(g.sem) }
func (g *Gate) InLine() int  { return len(g.adm) }
