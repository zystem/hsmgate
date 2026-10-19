package server

import (
	"bytes"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zystem/hsmgate/internal/audit"
	"github.com/zystem/hsmgate/internal/backend"
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
	h := adminHandler(func() map[string]backend.Token { return map[string]backend.Token{"card": tk} }, audit.New(buf))
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
	if strings.Contains(buf.String(), "1234") || strings.Count(buf.String(), `"op":"unlock"`) != 3 {
		t.Errorf("audit: %s", buf.String())
	}
}
