package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type failing struct{ fail bool }

func (f *failing) Write(p []byte) (int, error) {
	if f.fail {
		return 0, errors.New("disk full")
	}
	return len(p), nil
}

func TestOneJSONLinePerEventAndHostileValuesStayOnTheirLine(t *testing.T) {
	var b bytes.Buffer
	l := New(&b)
	if err := l.Write(Event{Client: "c", Face: "f", Op: "encrypt", Result: "ok", Context: "a\nb\"c{\"result\":\"forged\"}"}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("a hostile value made %d lines", len(lines))
	}
	var e Event
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil || e.Result != "ok" || e.Time.IsZero() {
		t.Errorf("%v %+v", err, e)
	}
}

func TestAFailedWriteMakesTheLogUnhealthyUntilOneSucceeds(t *testing.T) {
	w := &failing{}
	l := New(w)
	var seen []error
	l.Observer = func(_ Event, err error) { seen = append(seen, err) }
	if !l.Healthy() {
		t.Fatal("a new log is healthy")
	}
	w.fail = true
	if err := l.Write(Event{Op: "x"}); err == nil || l.Healthy() {
		t.Fatalf("the failure was hidden: %v %v", err, l.Healthy())
	}
	w.fail = false
	if err := l.Write(Event{Op: "x"}); err != nil || !l.Healthy() {
		t.Fatalf("the log did not recover: %v %v", err, l.Healthy())
	}
	if len(seen) != 2 || seen[0] == nil || seen[1] != nil {
		t.Errorf("the observer saw %v", seen)
	}
}
