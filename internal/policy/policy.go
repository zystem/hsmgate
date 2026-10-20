// Package policy decides: deny by default, per client and key, with operations and rate limits.
package policy

import (
	"strings"
	"sync"
	"time"

	"github.com/zystem/hsmgate/internal/config"
)

type Decision int

const (
	Allow Decision = iota
	Forbidden
	Throttled
)

// Counters outlive a reload: a new policy shares them, and a request of the old generation that finishes late is counted in the same place.
type Counters struct {
	mu  sync.Mutex
	win map[string]*window
}

func NewCounters() *Counters { return &Counters{win: map[string]*window{}} }

type Policy struct {
	cfg *config.Config
	now func() time.Time
	c   *Counters
}

// MetaPerMinute bounds reads of key information (public keys), which are free of the operation budget but not of any budget.
const MetaPerMinute = 120

type window struct {
	minute, day   int64
	minuteN, dayN int
}

func New(cfg *config.Config, c *Counters) *Policy {
	if c == nil {
		c = NewCounters()
	}
	return &Policy{cfg: cfg, now: time.Now, c: c}
}

// Counters is what a reload hands to the next policy.
func (p *Policy) Counters() *Counters { return p.c }

// Check spends the budget when it allows.
func (p *Policy) Check(client, key, op string) Decision {
	var g *config.Grant
	for i := range p.cfg.Clients {
		if p.cfg.Clients[i].Name == client {
			if v, ok := p.cfg.Clients[i].Keys[key]; ok {
				g = &v
			}
		}
	}
	if g == nil {
		return Forbidden
	}
	ok := false
	for _, o := range g.Ops {
		ok = ok || o == op
	}
	if !ok {
		return Forbidden
	}
	return p.spend(client+"\x00"+key, g.PerMinute, g.PerDay)
}

// CheckMeta spends the small budget of key-information reads; the client must have some grant on the key.
func (p *Policy) CheckMeta(client, key string) Decision {
	if !p.Allowed(client, key) {
		return Forbidden
	}
	return p.spend(client+"\x00"+key+"\x00meta", MetaPerMinute, 0)
}

func (p *Policy) spend(id string, perMinute, perDay int) Decision {
	now := p.now().Unix()
	p.c.mu.Lock()
	defer p.c.mu.Unlock()
	w := p.c.win[id]
	if w == nil {
		w = &window{}
		p.c.win[id] = w
	}
	if m := now / 60; m != w.minute {
		w.minute, w.minuteN = m, 0
	}
	if d := now / 86400; d != w.day {
		w.day, w.dayN = d, 0
	}
	if (perMinute > 0 && w.minuteN >= perMinute) || (perDay > 0 && w.dayN >= perDay) {
		return Throttled
	}
	w.minuteN++
	w.dayN++
	return Allow
}

// ContextAllowed: does the key accept this context? (Mode context only.)
func ContextAllowed(k config.Key, ctx []byte) bool {
	for _, a := range k.AAD.Allow {
		if strings.HasPrefix(string(ctx), a) {
			return true
		}
	}
	return false
}

// Names lists the keys a client may use.
func (p *Policy) Allowed(client, key string) bool {
	for _, c := range p.cfg.Clients {
		if c.Name == client {
			_, ok := c.Keys[key]
			return ok
		}
	}
	return false
}

// ContextOK: is this context within what the grant of the client allows? Empty contexts in the grant mean no narrowing.
func (p *Policy) ContextOK(client, key string, ctx []byte) bool {
	for _, c := range p.cfg.Clients {
		if c.Name != client {
			continue
		}
		g, ok := c.Keys[key]
		if !ok {
			return false
		}
		if len(g.Contexts) == 0 {
			return true
		}
		for _, x := range g.Contexts {
			if strings.HasPrefix(string(ctx), x) {
				return true
			}
		}
		return false
	}
	return false
}

// CheckList spends the small budget of listing calls of a client (they touch no token).
func (p *Policy) CheckList(client string) Decision {
	return p.spend(client+"\x00list", MetaPerMinute, 0)
}
