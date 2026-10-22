// Package peer is what the faces know about the other end of a connection: its address as the TCP connection shows it (a header is never believed), whether it is in a list of
// allowed addresses, and how many requests of an address were refused lately.
package peer

import (
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// Addr is the address of the TCP peer of a request.
func Addr(r *http.Request) netip.Addr {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		h = r.RemoteAddr
	}
	a, err := netip.ParseAddr(h)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap().WithZone("") // a zone (fe80::1%eth0) would make a prefix never contain the address
}

// Allowed: is the address within one of the prefixes?
func Allowed(from []netip.Prefix, a netip.Addr) bool {
	for _, p := range from {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Failures counts the refused credentials by the address of the peer: from an address with too many in a minute nothing is judged for the next minute. It bounds the guessing of a
// secret (which a secret of 20 bytes or more already makes pointless) and the cost of a noisy client.
type Failures struct {
	mu sync.Mutex
	by map[netip.Addr][]time.Time
}

const (
	Limit  = 20
	Window = time.Minute
)

func NewFailures() *Failures { return &Failures{by: map[netip.Addr][]time.Time{}} }

func (x *Failures) recent(a netip.Addr, now time.Time) []time.Time {
	keep := x.by[a][:0]
	for _, t := range x.by[a] {
		if now.Sub(t) < Window {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(x.by, a)
	} else {
		x.by[a] = keep
	}
	return keep
}

// Add notes a refusal. A nil Failures notes nothing.
func (x *Failures) Add(a netip.Addr, now time.Time) {
	if x == nil || !a.IsValid() {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if len(x.by) > 10000 { // a flood from many addresses must not grow the table without end
		x.by = map[netip.Addr][]time.Time{}
	}
	x.by[a] = append(x.recent(a, now), now)
}

// Blocked: has the address had Limit refusals in the last Window?
func (x *Failures) Blocked(a netip.Addr, now time.Time) bool {
	if x == nil || !a.IsValid() {
		return false
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	return len(x.recent(a, now)) >= Limit
}
