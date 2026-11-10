package metrics

import (
	"os"
	"strings"
	"testing"
)

// docs/audit-log.md names the class of each result word: the page must say what Outcome says.
func TestAuditLogDocNamesTheClassOfEachResult(t *testing.T) {
	raw, err := os.ReadFile("../../docs/audit-log.md")
	if err != nil {
		t.Fatal(err)
	}
	rows := strings.Split(string(raw), "\n")
	words := map[string]string{
		"ok": "ok", "attempt": "ok",
		"forbidden": "denied", "forbidden_context": "denied", "unauthenticated": "denied", "unknown_access_key": "denied", "bad_signature": "denied",
		"unsigned": "denied", "malformed_signature": "denied", "credential_mismatch": "denied", "address_refused": "denied", "bad_usage": "denied",
		"bad_algorithm": "denied", "not_lockable": "denied",
		"refused": "invalid", "throttled": "throttled", "throttled_auth": "throttled", "busy": "throttled",
		"locked": "error", "unavailable": "error", "internal_error": "error",
		"bad_request": "invalid", "bad_context": "invalid", "too_large": "invalid", "invalid_ciphertext": "invalid", "unsupported": "invalid", "probe": "invalid",
	}
	for w, class := range words {
		if got := Outcome(w); got != class {
			t.Errorf("Outcome(%q) = %q, this test and docs/audit-log.md say %q", w, got, class)
		}
		found := false
		for _, r := range rows {
			if strings.HasPrefix(r, "|") && strings.Contains(r, "`"+w+"`") && strings.Contains(r, "| "+class+" |") {
				found = true
			}
		}
		if !found {
			t.Errorf("docs/audit-log.md has no row for %q with the class %q", w, class)
		}
	}
}

// Every metric the service writes is named in docs/operations.md or docs/long-running-checks.md (the gauges of the process itself).
func TestEveryMetricIsDocumented(t *testing.T) {
	var raw []byte
	for _, f := range []string{"../../docs/operations.md", "../../docs/long-running-checks.md"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, b...)
	}
	var b strings.Builder
	New(false).Write(&b, RuntimeGauges())
	names := []string{"hsmgate_token_state", "hsmgate_gate_running", "hsmgate_gate_waiting"} // the gauges the server adds
	for _, l := range strings.Split(b.String(), "\n") {
		if strings.HasPrefix(l, "# TYPE ") {
			names = append(names, strings.Fields(l)[2])
		}
	}
	for _, n := range names {
		if !strings.Contains(string(raw), n) {
			t.Errorf("the metric %s is in neither docs/operations.md nor docs/long-running-checks.md", n)
		}
	}
}
