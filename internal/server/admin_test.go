package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zystem/hsmgate/internal/audit"
	"github.com/zystem/hsmgate/internal/backend"
	"github.com/zystem/hsmgate/internal/metrics"
)

type lockable struct {
	backend.Token
	pin    string
	opened bool
}

func (l *lockable) Unlock(p []byte) error {
	if string(p) != l.pin {
		return errors.New("refused")
	}
	l.opened = true
	return nil
}
func (l *lockable) State() string {
	if l.opened {
		return "ready"
	}
	return "locked"
}

func TestAdminUnlockAndAudit(t *testing.T) {
	// letters, not digits: a digit string can appear in a timestamp of the audit log (nanoseconds), and the test would fail now and then
	tk := &lockable{pin: "pin-secret"}
	buf := &bytes.Buffer{}
	h := adminHandler(func() map[string]backend.Token { return map[string]backend.Token{"card": tk} }, audit.New(buf), nil)
	post := func(body string) int {
		r := httptest.NewRequest("POST", "/unlock", strings.NewReader(body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if c := post(`{"token":"card","pin":"0000"}`); c != 403 || tk.opened {
		t.Errorf("wrong PIN: %d", c)
	}
	if c := post(`{"token":"card","pin":"pin-secret"}`); c != 200 || !tk.opened {
		t.Errorf("right PIN: %d", c)
	}
	if c := post(`{"token":"nobody","pin":"pin-secret"}`); c != 400 {
		t.Errorf("unknown token: %d", c)
	}
	if strings.Contains(buf.String(), "pin-secret") || strings.Count(buf.String(), `"op":"unlock"`) != 5 {
		t.Errorf("audit: %s", buf.String())
	}
}

func TestAdminSocketNeverRemovesAFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "s")
	os.WriteFile(f, []byte("precious"), 0o600)
	if err := (&Server{}).ServeAdmin(f); err == nil {
		t.Error("a regular file at admin_socket was accepted")
	}
	if b, _ := os.ReadFile(f); string(b) != "precious" {
		t.Error("the file was removed")
	}
}

type failingLog struct{}

func (failingLog) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// With no audit log the PIN is not tried at all.
func TestUnlockNeedsTheAuditLog(t *testing.T) {
	tk := &lockable{pin: "pin-secret"}
	h := adminHandler(func() map[string]backend.Token { return map[string]backend.Token{"card": tk} }, audit.New(failingLog{}), nil)
	r := httptest.NewRequest("POST", "/unlock", strings.NewReader(`{"token":"card","pin":"pin-secret"}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 503 || tk.opened {
		t.Errorf("%d opened=%v", w.Code, tk.opened)
	}
}

func TestMetricsOnTheAdminSocket(t *testing.T) {
	tk := &lockable{pin: "1"}
	buf := &bytes.Buffer{}
	log := audit.New(buf)
	reg := metrics.New(true)
	log.Observer = reg.Observe
	log.Write(audit.Event{Face: "transit", Op: "encrypt", Result: "ok", Client: "someone"})
	h := adminHandler(func() map[string]backend.Token { return map[string]backend.Token{"card": tk} }, log, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reg.Write(w, []metrics.Gauge{{Name: "hsmgate_gate_running", Help: "x", Value: 0}})
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `hsmgate_requests_total{face="transit",op="encrypt",result="ok"} 1`) || strings.Contains(rec.Body.String(), "someone") {
		t.Errorf("%d %s", rec.Code, rec.Body.String())
	}
}

// The PIN is read as bytes, never as a Go string (the review of 2026-11-21, finding 3): the unescaping must give what encoding/json gives.
func TestJSONStringBytesAgreesWithEncodingJSON(t *testing.T) {
	for _, in := range []string{
		`"1234"`, `""`, `"pin-secret"`, `"a\"b\\c\/d"`, `"tab\there\nnew\rret\bback\fform"`, `"12é中"`, `"😀 pair"`, `"é中 raw utf-8"`,
	} {
		var want string
		if err := json.Unmarshal([]byte(in), &want); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		got, err := jsonStringBytes([]byte(in))
		if err != nil || string(got) != want {
			t.Errorf("%s: %q %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{`1234`, `"abc`, `abc"`, `"\x41"`, `"\u12"`, `"\uZZZZ"`, `"abc\"`, `null`, `"`} {
		if _, err := jsonStringBytes([]byte(bad)); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
	if got, err := jsonStringBytes(nil); err != nil || len(got) != 0 {
		t.Errorf("an absent field: %q %v", got, err)
	}
}

// spy keeps the slice it was given, to see what became of it.
type spy struct {
	lockable
	got []byte
}

func (s *spy) Unlock(p []byte) error {
	s.got = p
	return s.lockable.Unlock(p)
}

// The buffers that held the PIN are zeroed when the request is done, whether the card took it or not; a PIN with JSON escapes arrives as what it means.
func TestAdminUnlockWipesThePIN(t *testing.T) {
	for _, tc := range []struct {
		body string
		ok   bool
	}{
		{`{"token":"card","pin":"pin-secret"}`, true},
		{`{"token":"card","pin":"pin-secret"}`, true},
		{`{"token":"card","pin":"wrong-one"}`, false},
	} {
		tk := &spy{lockable: lockable{pin: "pin-secret"}}
		h := adminHandler(func() map[string]backend.Token { return map[string]backend.Token{"card": tk} }, audit.New(&bytes.Buffer{}), nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/unlock", strings.NewReader(tc.body)))
		if (w.Code == 200) != tc.ok {
			t.Errorf("%s: %d", tc.body, w.Code)
		}
		if len(tk.got) == 0 {
			t.Fatalf("%s: the token was not given a PIN", tc.body)
		}
		if !bytes.Equal(tk.got, make([]byte, len(tk.got))) {
			t.Errorf("%s: the PIN buffer was not zeroed: %q", tc.body, tk.got)
		}
	}
	// a body that is too large, and a body that is not JSON, are refused before the card is asked
	tk := &spy{lockable: lockable{pin: "pin-secret"}}
	h := adminHandler(func() map[string]backend.Token { return map[string]backend.Token{"card": tk} }, audit.New(&bytes.Buffer{}), nil)
	for _, body := range []string{`{"token":"card","pin":"` + strings.Repeat("x", 2000) + `"}`, `not json`, `{"token":"card","pin":7}`} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/unlock", strings.NewReader(body)))
		if w.Code != 400 || tk.got != nil {
			t.Errorf("%.30s...: %d, token asked: %v", body, w.Code, tk.got != nil)
		}
	}
}
