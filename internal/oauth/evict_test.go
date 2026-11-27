package oauth

import (
	"fmt"
	"testing"
	"time"
)

// A full table with issuers of unequal size: the one that holds the most gives up its oldest token; of two that hold as many, the one whose name sorts first. The smaller ones keep all of theirs.
func TestTokensTableFullTakesFromTheLargest(t *testing.T) {
	ts := NewTokens()
	now := time.Now()
	held := map[string][]string{}
	issue := func(iss string, n int) {
		for i := 0; i < n; i++ {
			tok, _ := ts.Issue(iss, "s", now)
			held[iss] = append(held[iss], tok)
		}
	}
	issue("big-b", maxPerIssuer)
	issue("big-a", maxPerIssuer)
	for i := 0; i < (maxTokens-2*maxPerIssuer)/50; i++ {
		issue(fmt.Sprintf("small-%03d", i), 50)
	}
	if len(ts.m) != maxTokens {
		t.Fatalf("the table holds %d tokens, not %d", len(ts.m), maxTokens)
	}
	if c, f := ts.Evicted(); c != 0 || f != 0 {
		t.Fatalf("evicted %d and %d before the table was over its limit", c, f)
	}
	for i, want := range []struct {
		iss string
		n   int
	}{{"big-a", 0}, {"big-b", 0}, {"big-a", 1}} {
		ts.Issue(fmt.Sprintf("new-%d", i), "s", now)
		if _, _, ok := ts.Lookup(held[want.iss][want.n], now); ok {
			t.Fatalf("newcomer %d: token %d of %s is still live", i, want.n, want.iss)
		}
	}
	gone := map[string]int{}
	for iss, toks := range held {
		for _, tok := range toks {
			if _, _, ok := ts.Lookup(tok, now); !ok {
				gone[iss]++
			}
		}
	}
	if len(gone) != 2 || gone["big-a"] != 2 || gone["big-b"] != 1 {
		t.Errorf("given up: %v, want 2 of big-a and 1 of big-b", gone)
	}
	if c, f := ts.Evicted(); c != 0 || f != 3 {
		t.Errorf("evicted: %d at the client limit and %d at a full table, want 0 and 3", c, f)
	}
}

func TestTokensEvictedAtTheClientLimit(t *testing.T) {
	ts := NewTokens()
	now := time.Now()
	for i := 0; i < maxPerIssuer+3; i++ {
		ts.Issue("busy", "s", now)
	}
	if c, f := ts.Evicted(); c != 3 || f != 0 {
		t.Errorf("evicted: %d and %d, want 3 and 0", c, f)
	}
	ts.Issue("busy", "s", now.Add(time.Hour)) // all of them have expired: nothing live is given up
	if c, _ := ts.Evicted(); c != 3 {
		t.Errorf("an expired token was counted: %d", c)
	}
}

func TestStampAudiences(t *testing.T) {
	m := []byte("key")
	a := Stamp("c", "i", m, "one", "two")
	if Stamp("c", "i", m, "two", "one", "two") != a {
		t.Error("the order of the list changed the stamp")
	}
	for name, b := range map[string]string{"a value less": Stamp("c", "i", m, "one"), "a value more": Stamp("c", "i", m, "one", "two", "three"), "no list": Stamp("c", "i", m)} {
		if a == b {
			t.Errorf("%s: the same stamp", name)
		}
	}
}
