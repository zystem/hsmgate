package metrics

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/zystem/hsmgate/internal/audit"
)

func TestCountersAndGauges(t *testing.T) {
	r := New()
	r.Observe(audit.Event{Face: "kmsjson", Op: "encrypt", Result: "ok", Client: "secret-client", Key: "secret-key"}, nil)
	r.Observe(audit.Event{Face: "kmsjson", Op: "encrypt", Result: "ok"}, nil)
	r.Observe(audit.Event{Face: "transit", Op: "decrypt", Result: "forbidden"}, errors.New("disk full"))
	r.Observe(audit.Event{Face: "kmsjson", Op: strings.Repeat("x", 100), Result: "a\"b"}, nil)
	var b bytes.Buffer
	r.Write(&b, []Gauge{{Name: "hsmgate_gate_running", Help: "h", Value: 2}, {Name: "hsmgate_token_state", Help: "s", Labels: `token="card",state="ready"`, Value: 1}})
	out := b.String()
	for _, want := range []string{
		`hsmgate_requests_total{face="kmsjson",op="encrypt",result="ok"} 2`,
		`hsmgate_requests_total{face="transit",op="decrypt",result="forbidden"} 1`,
		`hsmgate_requests_total{face="kmsjson",op="other",result="other"} 1`,
		"hsmgate_audit_write_failures_total 1",
		"hsmgate_gate_running 2",
		`hsmgate_token_state{token="card",state="ready"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// no client, key or address is ever a label
	if strings.Contains(out, "secret-client") || strings.Contains(out, "secret-key") {
		t.Errorf("a client or key leaked into the metrics:\n%s", out)
	}
}

func TestTheTableIsBounded(t *testing.T) {
	r := New()
	for i := 0; i < 5000; i++ {
		r.Observe(audit.Event{Face: "f", Op: "o", Result: strings.Repeat("r", i%35) + string(rune('a'+i%26)) + string(rune('a'+i/26%26))}, nil)
	}
	r.mu.Lock()
	n := len(r.requests)
	r.mu.Unlock()
	if n > 2000 {
		t.Errorf("%d series", n)
	}
}
