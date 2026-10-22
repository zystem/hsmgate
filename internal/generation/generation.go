// Package generation holds the current generation of a face (its configuration, tokens, policy, credentials) and lets a reload replace it without cutting requests that are being served:
// a request takes the generation that is current when it starts and holds it until it ends; Set returns a function that waits for the requests of the generation it replaced.
package generation

import "sync"

type tracker struct{ wg sync.WaitGroup }

// Holder is the current generation of type T.
type Holder[T any] struct {
	mu    sync.RWMutex
	cur   T
	have  bool
	track *tracker
}

// Set makes v the current generation. The returned function waits until every request that took the previous generation has released it.
func (h *Holder[T]) Set(v T) (waitOld func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	old := h.track
	h.cur, h.have, h.track = v, true, &tracker{}
	if old == nil {
		return func() {}
	}
	return old.wg.Wait
}

// Acquire takes the current generation for one request; ok is false before the first Set. release must be called when the request ends.
func (h *Holder[T]) Acquire() (v T, release func(), ok bool) {
	h.mu.RLock()
	if !h.have {
		h.mu.RUnlock()
		return v, func() {}, false
	}
	t := h.track
	t.wg.Add(1) // under the read lock, so that Set cannot swap and wait between the read and the Add
	v = h.cur
	h.mu.RUnlock()
	return v, t.wg.Done, true
}
