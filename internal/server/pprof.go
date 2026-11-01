package server

import (
	"net/http"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"
)

// pprofHandler serves the profiles of the process on the admin socket (debug.pprof in the configuration; off by default). It is the part of net/http/pprof that is needed, written
// out so that nothing is registered on a default mux by an import. A profile of the heap holds the memory of the process, secrets included: it is for the operator who holds the
// socket (mode 0600), never for the network.
//
//	GET /debug/pprof/NAME[?debug=1|2][&gc=1]   NAME: heap, allocs, goroutine, threadcreate, block, mutex (gc=1 collects first, so that heap profiles of two moments compare)
//	GET /debug/pprof/profile?seconds=N         CPU, 1 to 120 seconds
func pprofHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/debug/pprof/")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if name == "profile" {
			secs, err := strconv.Atoi(r.URL.Query().Get("seconds"))
			if err != nil || secs < 1 || secs > 120 {
				http.Error(w, "seconds must be 1 to 120", http.StatusBadRequest)
				return
			}
			// the server's write timeout is short; a profile takes as long as it was asked to
			if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Duration(secs+30) * time.Second)); err != nil {
				http.Error(w, "cannot extend the deadline", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			if err := pprof.StartCPUProfile(w); err != nil { // one at a time: the runtime says so
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			select {
			case <-time.After(time.Duration(secs) * time.Second):
			case <-r.Context().Done():
			}
			pprof.StopCPUProfile()
			return
		}
		switch name {
		case "heap", "allocs", "goroutine", "threadcreate", "block", "mutex":
		default:
			http.NotFound(w, r)
			return
		}
		p := pprof.Lookup(name)
		debug, _ := strconv.Atoi(r.URL.Query().Get("debug"))
		if debug < 0 || debug > 2 {
			debug = 0
		}
		if r.URL.Query().Get("gc") == "1" && (name == "heap" || name == "allocs") {
			runtime.GC()
		}
		if debug == 0 {
			w.Header().Set("Content-Type", "application/octet-stream")
		} else {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		p.WriteTo(w, debug)
	})
}

// withPprof adds the profiles to an admin handler.
func withPprof(next http.Handler) http.Handler {
	prof := pprofHandler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/debug/pprof/") {
			prof.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
