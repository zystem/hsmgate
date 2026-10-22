package kmsops

import (
	"sync"
	"time"
)

type macEntry struct {
	key     []byte
	expires time.Time
}

// MacCache keeps the MAC keys derived from the keys on the token for kmsjson.mac_cache_seconds. It is shared by the generations and by the faces; an entry is named by the name, the
// version and the fingerprint of the public key, so a key that was replaced is never answered from the old entry. get returns a copy made under the lock (the audit, CR-03).
type MacCache struct {
	mu sync.Mutex
	m  map[string]macEntry
}

func NewMacCache() *MacCache { return &MacCache{m: map[string]macEntry{}} }

func (k *MacCache) get(id string, now time.Time) ([]byte, bool) {
	if k == nil {
		return nil, false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
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

// Clear drops every derived key (a reload: the configuration, the clients or the tokens may have changed).
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
}

func (k *MacCache) put(id string, key []byte, until time.Time) {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.m == nil {
		k.m = map[string]macEntry{}
	}
	if old, ok := k.m[id]; ok {
		Wipe(old.key)
	}
	k.m[id] = macEntry{append([]byte{}, key...), until}
}
