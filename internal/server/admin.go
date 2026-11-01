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

// adminHandler: POST /unlock {"token": name, "pin": "..."}, GET /status and GET /metrics (the counters in the text format of Prometheus). The door is the file mode of the socket; there is no other authentication.
func adminHandler(current func() map[string]backend.Token, log *audit.Log, metrics http.Handler) http.Handler {
	mux := http.NewServeMux()
	if metrics != nil {
		mux.Handle("GET /metrics", metrics)
	}
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
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		u, ok := current()[b.Token].(Unlocker)
		ev := audit.Event{Client: "admin", Face: "admin", Key: b.Token, Op: "unlock"}
		if !ok {
			ev.Result = "not_lockable"
			log.Write(ev)
			http.Error(w, "this token takes no PIN", http.StatusBadRequest)
			return
		}
		// the attempt is written down before the card is touched: with no log there is no unlock
		ev.Result = "attempt"
		if err := log.Write(ev); err != nil {
			http.Error(w, "audit log unavailable", http.StatusServiceUnavailable)
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
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		ev.Result = "ok"
		if err := log.Write(ev); err != nil {
			// the token is unlocked and the attempt was written; say that the result line was not
			http.Error(w, "unlocked, but the audit log could not record the result: "+err.Error(), http.StatusInternalServerError)
			return
		}
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
	var h http.Handler = adminHandler(s.Tokens, s.audit, s.metricsHandler())
	s.mu.RLock()
	pprofOn := s.gen.cfg.Debug.Pprof
	s.mu.RUnlock()
	if pprofOn {
		h = withPprof(h)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	return srv.Serve(l)
}
