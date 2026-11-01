package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func get(h http.Handler, path string) (int, []byte, http.Header) {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	b, _ := io.ReadAll(rec.Result().Body)
	return rec.Code, b, rec.Header()
}

func TestPprofProfiles(t *testing.T) {
	h := withPprof(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("admin")) }))
	// the admin paths are untouched
	if st, b, _ := get(h, "/status"); st != 200 || string(b) != "admin" {
		t.Errorf("admin: %d %q", st, b)
	}
	// a heap profile is gzip data (the pprof format); debug=1 is text with the header of the profile
	if st, b, _ := get(h, "/debug/pprof/heap?gc=1"); st != 200 || len(b) < 2 || b[0] != 0x1f || b[1] != 0x8b {
		t.Errorf("heap: %d %d bytes", st, len(b))
	}
	if st, b, hd := get(h, "/debug/pprof/goroutine?debug=1"); st != 200 || !strings.Contains(string(b), "goroutine profile:") || !strings.HasPrefix(hd.Get("Content-Type"), "text/plain") {
		t.Errorf("goroutine: %d %.40q", st, b)
	}
	for _, name := range []string{"allocs", "threadcreate", "block", "mutex"} {
		if st, _, _ := get(h, "/debug/pprof/"+name); st != 200 {
			t.Errorf("%s: %d", name, st)
		}
	}
	// what is not a profile, and what is not GET
	for _, p := range []string{"/debug/pprof/", "/debug/pprof/cmdline", "/debug/pprof/../x", "/debug/pprof/trace", "/debug/pprof/profile", "/debug/pprof/profile?seconds=0", "/debug/pprof/profile?seconds=999", "/debug/pprof/profile?seconds=x"} {
		if st, _, _ := get(h, p); st == 200 {
			t.Errorf("%s was served", p)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/debug/pprof/heap", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", rec.Code)
	}
}

func TestCPUProfile(t *testing.T) {
	srv := httptest.NewServer(withPprof(http.NotFoundHandler()))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/debug/pprof/profile?seconds=1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || len(b) < 2 || b[0] != 0x1f || b[1] != 0x8b {
		t.Errorf("cpu: %d %d bytes", resp.StatusCode, len(b))
	}
}
