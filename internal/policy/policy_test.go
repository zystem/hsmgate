package policy

import (
	"testing"
	"time"

	"github.com/zystem/hsmgate/internal/config"
)

func cfg() *config.Config {
	return &config.Config{
		Keys: map[string]config.Key{
			"k":   {AAD: config.AAD{Mode: "context", Allow: []string{"app/dek/", "app/check"}}},
			"two": {AAD: config.AAD{Mode: "fixed"}},
		},
		Clients: []config.Client{
			{Name: "a", Keys: map[string]config.Grant{"k": {Ops: []string{"encrypt"}, PerMinute: 3, PerDay: 5, Contexts: []string{"app/dek/shop/"}}}},
			{Name: "b", Keys: map[string]config.Grant{"k": {Ops: []string{"encrypt", "decrypt"}}, "two": {Ops: []string{"decrypt"}}}},
		},
	}
}

func TestDenyByDefault(t *testing.T) {
	p := New(cfg(), nil)
	for _, c := range []struct{ client, key, op string }{
		{"nobody", "k", "encrypt"}, // an unknown client
		{"a", "two", "encrypt"},    // a key it has no grant on
		{"a", "k", "decrypt"},      // an operation it has no grant for
		{"a", "k", ""},             // no operation
		{"", "k", "encrypt"},
	} {
		if d := p.Check(c.client, c.key, c.op); d != Forbidden {
			t.Errorf("%+v: %v", c, d)
		}
	}
	if p.Allowed("nobody", "k") || p.Allowed("a", "two") || !p.Allowed("a", "k") {
		t.Error("Allowed")
	}
	if d := p.CheckMeta("a", "two"); d != Forbidden {
		t.Errorf("key information of a key without a grant: %v", d)
	}
}

func TestBudgetsPerMinuteAndPerDay(t *testing.T) {
	p := New(cfg(), nil)
	now := time.Date(2026, 10, 21, 12, 0, 30, 0, time.UTC)
	p.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if d := p.Check("a", "k", "encrypt"); d != Allow {
			t.Fatalf("call %d: %v", i, d)
		}
	}
	if d := p.Check("a", "k", "encrypt"); d != Throttled {
		t.Errorf("over the minute budget: %v", d)
	}
	// a refusal does not spend; the next minute has a new budget, the day does not
	now = now.Add(time.Minute)
	for i := 0; i < 2; i++ {
		if d := p.Check("a", "k", "encrypt"); d != Allow {
			t.Fatalf("next minute, call %d: %v", i, d)
		}
	}
	if d := p.Check("a", "k", "encrypt"); d != Throttled {
		t.Errorf("over the day budget: %v", d)
	}
	now = now.Add(24 * time.Hour)
	if d := p.Check("a", "k", "encrypt"); d != Allow {
		t.Errorf("next day: %v", d)
	}
	// the budget of one client does not touch another's, and without limits nothing is throttled
	for i := 0; i < 1000; i++ {
		if d := p.Check("b", "k", "encrypt"); d != Allow {
			t.Fatalf("a client with no limits: %v", d)
		}
	}
}

func TestCountersSurviveANewPolicy(t *testing.T) {
	p := New(cfg(), nil)
	p.now = func() time.Time { return time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC) }
	for i := 0; i < 3; i++ {
		p.Check("a", "k", "encrypt")
	}
	q := New(cfg(), p.Counters()) // a reload
	q.now = p.now
	if d := q.Check("a", "k", "encrypt"); d != Throttled {
		t.Errorf("a reload gave a fresh budget: %v", d)
	}
}

func TestContextRulesArePrefixes(t *testing.T) {
	c := cfg()
	p := New(c, nil)
	k := c.Keys["k"]
	if !ContextAllowed(k, []byte("app/dek/shop/1")) || !ContextAllowed(k, []byte("app/check")) || ContextAllowed(k, []byte("other/")) || ContextAllowed(k, nil) {
		t.Error("ContextAllowed")
	}
	if !p.ContextOK("a", "k", []byte("app/dek/shop/7")) || p.ContextOK("a", "k", []byte("app/dek/other/7")) {
		t.Error("the grant of a narrows the context to its prefix")
	}
	if !p.ContextOK("b", "k", []byte("anything")) {
		t.Error("an empty list of contexts means no narrowing")
	}
	if p.ContextOK("nobody", "k", []byte("app/dek/shop/")) || p.ContextOK("a", "two", []byte("x")) {
		t.Error("no grant, no context")
	}
	// a prefix is a prefix: "app/dek/shop/" also allows "app/dek/shop/anything", which is how the rule is written
	if !p.ContextOK("a", "k", []byte("app/dek/shop/../other")) {
		t.Error("prefix semantics changed")
	}
}

func TestListingHasASmallBudget(t *testing.T) {
	p := New(cfg(), nil)
	p.now = func() time.Time { return time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC) }
	for i := 0; i < MetaPerMinute; i++ {
		if d := p.CheckList("a"); d != Allow {
			t.Fatalf("call %d: %v", i, d)
		}
	}
	if d := p.CheckList("a"); d != Throttled {
		t.Errorf("over the budget of listing: %v", d)
	}
	if d := p.CheckList("b"); d != Allow {
		t.Errorf("another client: %v", d)
	}
}
