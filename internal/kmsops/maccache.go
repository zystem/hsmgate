package kmsops

import (
	"sync"
	"time"
)

type macEntry struct {
	key     []byte
	expires time.Time // by the clock of the caller (a test may give the face its own)
	due     time.Time // by the clock of the process: when the timer wipes it
}

// MacCache keeps the MAC keys derived from the keys on the token for kmsjson.mac_cache_seconds. It is shared by the faces that make MACs (the KMS-JSON, gRPC and REST faces each
// have one); an entry is named by the name, the version and the fingerprint of the public key, so a key that was replaced is never answered from the old entry. Get returns a copy
// made under the lock (the audit of 2026-10-21, CR-03).
//
// What the cache promises about the memory it holds (the review of 2026-11-21, finding 3):
//   - an expired entry is wiped by the cache itself, at its time, not when somebody asks for it: a timer is set for the earliest expiry (Sweep does the same on demand);
//   - the cache belongs to a generation of the configuration: a generation has an epoch, only the requests of the current epoch read or write, and a reload moves the epoch on and
//     wipes everything (Advance). A request of the previous generation that finishes its derivation after that cannot put its key back: it was derived with the previous tokens.
type MacCache struct {
	mu    sync.Mutex
	m     map[string]macEntry
	epoch uint64
	timer *time.Timer
}

func NewMacCache() *MacCache { return &MacCache{m: map[string]macEntry{}} }

// Next is the epoch the next generation will have; it goes into the generation before the generation is published, and Advance takes it after.
func (k *MacCache) Next() uint64 {
	if k == nil {
		return 0
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.epoch + 1
}

// Advance makes epoch the current one and wipes every derived key: a reload (the configuration, the clients or the tokens may have changed). It is called after the new
// generation is published; from then on the requests of the generation before get nothing from the cache and put nothing into it.
func (k *MacCache) Advance(epoch uint64) {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.epoch = epoch
	for id, e := range k.m {
		Wipe(e.key)
		delete(k.m, id)
	}
	k.stopTimer()
}

// Clear wipes every derived key and keeps the epoch (for a test, or a caller with one generation).
func (k *MacCache) Clear() {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for id, e := range k.m {
		Wipe(e.key)
		delete(k.m, id)
	}
	k.stopTimer()
}

// Get gives a copy of a live entry, for a request of the epoch.
func (k *MacCache) Get(id string, now time.Time, epoch uint64) ([]byte, bool) {
	if k == nil {
		return nil, false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if epoch != k.epoch {
		return nil, false
	}
	e, ok := k.m[id]
	if !ok {
		return nil, false
	}
	if !now.Before(e.expires) {
		Wipe(e.key)
		delete(k.m, id)
		return nil, false
	}
	return append([]byte{}, e.key...), true
}

// Put keeps a copy of a derived key for ttl from now (the clock of the caller), for a request of the epoch; for any other epoch it keeps nothing.
func (k *MacCache) Put(id string, key []byte, now time.Time, ttl time.Duration, epoch uint64) {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if epoch != k.epoch {
		return
	}
	if k.m == nil {
		k.m = map[string]macEntry{}
	}
	if old, ok := k.m[id]; ok {
		Wipe(old.key)
	}
	k.m[id] = macEntry{key: append([]byte{}, key...), expires: now.Add(ttl), due: time.Now().Add(ttl)}
	k.arm(time.Now())
}

// Len is the number of entries held, expired or not (for a test and for the metrics, if they ever want it).
func (k *MacCache) Len() int {
	if k == nil {
		return 0
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.m)
}

// Sweep wipes the entries that have expired by now.
func (k *MacCache) Sweep(now time.Time) {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.sweep(now)
}

// sweep is Sweep with the lock held; it arms the timer for what is left.
func (k *MacCache) sweep(now time.Time) {
	for id, e := range k.m {
		if !now.Before(e.expires) {
			Wipe(e.key)
			delete(k.m, id)
		}
	}
	k.arm(time.Now())
}

// sweepDue wipes what the clock of the process says is due (the timer's work).
func (k *MacCache) sweepDue() {
	now := time.Now()
	for id, e := range k.m {
		if !now.Before(e.due) {
			Wipe(e.key)
			delete(k.m, id)
		}
	}
	k.arm(now)
}

// arm sets the timer for the earliest due time of what is held; with the lock held. The time used is the one of the process: an entry is wiped when its time comes, whatever clock
// the callers gave it.
func (k *MacCache) arm(now time.Time) {
	k.stopTimer()
	var first time.Time
	for _, e := range k.m {
		if first.IsZero() || e.due.Before(first) {
			first = e.due
		}
	}
	if first.IsZero() {
		return
	}
	d := first.Sub(now)
	if d < time.Millisecond {
		d = time.Millisecond
	}
	var t *time.Timer
	t = time.AfterFunc(d, func() {
		k.mu.Lock()
		defer k.mu.Unlock()
		if k.timer != t { // stopped or replaced while it was waiting for the lock
			return
		}
		k.timer = nil
		k.sweepDue()
	})
	k.timer = t
}

func (k *MacCache) stopTimer() {
	if k.timer != nil {
		k.timer.Stop()
		k.timer = nil
	}
}
