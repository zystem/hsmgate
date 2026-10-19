package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"syscall"
	"time"

	"github.com/zystem/hsmgate/internal/audit"
	"github.com/zystem/hsmgate/internal/backend"
)

// Unlocker is a token that waits for a PIN.
type Unlocker interface {
	Unlock(pin []byte) error
	State() string
}

// adminHandler: POST /unlock {"token": name, "pin": "..."} and GET /status. The door is the file mode of the socket; there is no other authentication.
func adminHandler(current func() map[string]backend.Token, log *audit.Log) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		tokens := current()
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
		u, ok := current()[b.Token].(Unlocker)
		ev := audit.Event{Client: "admin", Face: "admin", Key: b.Token, Op: "unlock"}
		if !ok {
			ev.Result = "not_lockable"
			log.Write(ev)
			http.Error(w, "this token takes no PIN", 400)
			return
		}
		// the attempt is written down before the card is touched: with no log there is no unlock
		ev.Result = "attempt"
		if err := log.Write(ev); err != nil {
			http.Error(w, "audit log unavailable", 503)
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
	// a stale socket of an earlier run is replaced; anything else at that path is left alone
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("admin_socket %s exists and is not a socket", path)
		}
		os.Remove(path)
	}
	// the socket is created with mode 0600 from the start, whatever the umask of the process
	old := syscall.Umask(0o177)
	l, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return err
	}
	srv := &http.Server{Handler: adminHandler(s.Tokens, s.audit), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	return srv.Serve(l)
}
