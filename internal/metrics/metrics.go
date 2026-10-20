// Package metrics counts what the service decides and says how busy it is, in the text format that Prometheus reads. It has no dependency and no label that a peer can choose: the
// counters are named by face, operation and result, all of which are fixed sets (an operation the service does not know is counted as "unknown"); a client, a key or an address
// is never a label. It is served on the admin socket (mode 0600), not on the network.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/zystem/hsmgate/internal/audit"
)

type key struct{ face, op, result string }

// Registry holds the counters.
type Registry struct {
	mu        sync.Mutex
	requests  map[key]uint64
	auditFail uint64
}

func New() *Registry { return &Registry{requests: map[key]uint64{}} }

// Observe is the observer of the audit log: every decision is one line, and every line is counted.
func (r *Registry) Observe(e audit.Event, err error) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.requests) < 2000 { // a bound, whatever the results are
		r.requests[key{clean(e.Face), clean(e.Op), clean(e.Result)}]++
	}
	if err != nil {
		r.auditFail++
	}
}

func clean(s string) string {
	if len(s) > 40 || strings.ContainsAny(s, "\"\\\n") {
		return "other"
	}
	return s
}

// Gauge is a value read at the time of the scrape.
type Gauge struct {
	Name   string
	Help   string
	Labels string // already in the form `a="b",c="d"`, or empty
	Value  float64
}

// Write renders the counters and the gauges.
func (r *Registry) Write(w io.Writer, gauges []Gauge) {
	r.mu.Lock()
	keys := make([]key, 0, len(r.requests))
	for k := range r.requests {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.face != b.face {
			return a.face < b.face
		}
		if a.op != b.op {
			return a.op < b.op
		}
		return a.result < b.result
	})
	counts := make([]uint64, len(keys))
	for i, k := range keys {
		counts[i] = r.requests[k]
	}
	fail := r.auditFail
	r.mu.Unlock()

	fmt.Fprintln(w, "# HELP hsmgate_requests_total Decisions of the service, by face, operation and result.")
	fmt.Fprintln(w, "# TYPE hsmgate_requests_total counter")
	for i, k := range keys {
		fmt.Fprintf(w, "hsmgate_requests_total{face=%q,op=%q,result=%q} %d\n", k.face, k.op, k.result, counts[i])
	}
	fmt.Fprintln(w, "# HELP hsmgate_audit_write_failures_total Audit lines that could not be written.")
	fmt.Fprintln(w, "# TYPE hsmgate_audit_write_failures_total counter")
	fmt.Fprintf(w, "hsmgate_audit_write_failures_total %d\n", fail)
	seen := map[string]bool{}
	for _, g := range gauges {
		if !seen[g.Name] {
			seen[g.Name] = true
			fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", g.Name, g.Help, g.Name)
		}
		if g.Labels != "" {
			fmt.Fprintf(w, "%s{%s} %g\n", g.Name, g.Labels, g.Value)
		} else {
			fmt.Fprintf(w, "%s %g\n", g.Name, g.Value)
		}
	}
}
