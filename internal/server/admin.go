package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"syscall"
	"time"
	"unicode/utf16"
	"unicode/utf8"

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
		// The PIN is read as bytes and never as a Go string (a string cannot be wiped): the body is read into a buffer of its own, the PIN is cut out of it as raw JSON and
		// unescaped into another, and both are zeroed when the request is done.
		body, n, err := readSmallBody(r.Body, 1024)
		defer wipe(body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var b struct {
			Token string
			Pin   json.RawMessage
		}
		err = json.Unmarshal(body[:n], &b)
		defer wipe(b.Pin)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		pin, err := jsonStringBytes(b.Pin)
		defer wipe(pin)
		if err != nil {
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
		if err := u.Unlock(pin); err != nil {
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

// readSmallBody reads a body of at most max bytes into one buffer that is not grown (a grown buffer leaves copies behind), and gives the buffer and the number of bytes in it. The
// buffer is returned whatever happens, so that the caller can wipe it.
func readSmallBody(r io.Reader, max int) ([]byte, int, error) {
	buf := make([]byte, max+1)
	n, err := io.ReadFull(r, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return buf, 0, err
	}
	if n > max {
		return buf, 0, errors.New("the body is too large")
	}
	return buf, n, nil
}

// jsonStringBytes unescapes a JSON string into a new buffer of bytes without making a Go string of it. Nothing (an absent field) is an empty value; anything but a string is an error.
func jsonStringBytes(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return []byte{}, nil
	}
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, errors.New("not a string")
	}
	in := raw[1 : len(raw)-1]
	out := make([]byte, 0, len(in))
	for i := 0; i < len(in); i++ {
		c := in[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		if i++; i >= len(in) {
			return out, errors.New("bad escape")
		}
		switch in[i] {
		case '"', '\\', '/':
			out = append(out, in[i])
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, ok := hex4(in, i+1)
			if !ok {
				return out, errors.New("bad escape")
			}
			i += 4
			if utf16.IsSurrogate(r) { // a pair: \uD83D\uDE00
				if i+6 < len(in) && in[i+1] == '\\' && in[i+2] == 'u' {
					if r2, ok := hex4(in, i+3); ok {
						if dec := utf16.DecodeRune(r, r2); dec != utf8.RuneError {
							out = utf8.AppendRune(out, dec)
							i += 6
							break
						}
					}
				}
				r = utf8.RuneError
			}
			out = utf8.AppendRune(out, r)
		default:
			return out, errors.New("bad escape")
		}
	}
	return out, nil
}

func hex4(b []byte, at int) (rune, bool) {
	if at+4 > len(b) {
		return 0, false
	}
	var r rune
	for _, c := range b[at : at+4] {
		switch {
		case c >= '0' && c <= '9':
			r = r<<4 | rune(c-'0')
		case c >= 'a' && c <= 'f':
			r = r<<4 | rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			r = r<<4 | rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	return r, true
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
