package server

import (
	"bytes"
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
	tk := &lockable{pin: "1234"}
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
	if c := post(`{"token":"card","pin":"1234"}`); c != 200 || !tk.opened {
		t.Errorf("right PIN: %d", c)
	}
	if c := post(`{"token":"nobody","pin":"1234"}`); c != 400 {
		t.Errorf("unknown token: %d", c)
	}
	if strings.Contains(buf.String(), "1234") || strings.Count(buf.String(), `"op":"unlock"`) != 5 {
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
	tk := &lockable{pin: "1234"}
	h := adminHandler(func() map[string]backend.Token { return map[string]backend.Token{"card": tk} }, audit.New(failingLog{}), nil)
	r := httptest.NewRequest("POST", "/unlock", strings.NewReader(`{"token":"card","pin":"1234"}`))
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
