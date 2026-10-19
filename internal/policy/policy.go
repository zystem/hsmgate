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

type Policy struct {
	cfg *config.Config
	now func() time.Time
	mu  sync.Mutex
	win map[string]*window
}

type window struct {
	minute, day   int64
	minuteN, dayN int
}

func New(cfg *config.Config) *Policy {
	return &Policy{cfg: cfg, now: time.Now, win: map[string]*window{}}
}

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
	now := p.now().Unix()
	p.mu.Lock()
	defer p.mu.Unlock()
	w := p.win[client+"\x00"+key]
	if w == nil {
		w = &window{}
		p.win[client+"\x00"+key] = w
	}
	if m := now / 60; m != w.minute {
		w.minute, w.minuteN = m, 0
	}
	if d := now / 86400; d != w.day {
		w.day, w.dayN = d, 0
	}
	if (g.PerMinute > 0 && w.minuteN >= g.PerMinute) || (g.PerDay > 0 && w.dayN >= g.PerDay) {
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

// Inherit takes over the counters of a policy that a reload replaces, so that a reload does not give a client a new budget.
func (p *Policy) Inherit(old *Policy) {
	old.mu.Lock()
	defer old.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, w := range old.win {
		c := *w
		p.win[k] = &c
	}
}
