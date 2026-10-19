package server

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"sort"

	"github.com/zystem/hsmgate/internal/audit"
	"github.com/zystem/hsmgate/internal/backend"
)

// Unlocker is a token that waits for a PIN.
type Unlocker interface {
	Unlock(pin []byte) error
	State() string
}

// adminHandler: POST /unlock {"token": name, "pin": "..."} and GET /status. The door is the file mode of the socket; there is no other authentication.
func adminHandler(tokens map[string]backend.Token, log *audit.Log) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		st := map[string]string{}
		names := []string{}
		for n := range tokens {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			st[n] = tokens[n].State()
		}
		json.NewEncoder(w).Encode(st)
	})
	mux.HandleFunc("POST /unlock", func(w http.ResponseWriter, r *http.Request) {
		var b struct{ Token, Pin string }
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&b) != nil {
			http.Error(w, "bad request", 400)
			return
		}
		u, ok := tokens[b.Token].(Unlocker)
		ev := audit.Event{Client: "admin", Face: "admin", Key: b.Token, Op: "unlock"}
		if !ok {
			ev.Result = "not_lockable"
			log.Write(ev)
			http.Error(w, "this token takes no PIN", 400)
			return
		}
		pin := []byte(b.Pin)
		err := u.Unlock(pin)
		for i := range pin {
			pin[i] = 0
		}
		if err != nil {
			ev.Result = "refused"
			log.Write(ev)
			http.Error(w, err.Error(), 403)
			return
		}
		ev.Result = "ok"
		log.Write(ev)
		json.NewEncoder(w).Encode(map[string]string{"state": u.State()})
	})
	return mux
}

// ServeAdmin listens on the unix socket of the configuration (mode 0600) and serves until the listener closes.
func (s *Server) ServeAdmin(path string) error {
	os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return err
	}
	return (&http.Server{Handler: adminHandler(s.Tokens, s.audit)}).Serve(l)
}
