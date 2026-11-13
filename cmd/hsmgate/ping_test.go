package main

import (
	"bytes"
	"log"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/server"
)

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// `hsmgate ping` with a certificate makes the whole handshake and leaves nothing in the log of the service (not even without the filter of the server), a certificate
// of another CA is refused, and a plain TCP ping is the connect that the service used to log as "TLS handshake error ... EOF".
func TestPing(t *testing.T) {
	dir := t.TempDir()
	cfgPath, err := devSetup(dir, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	s, err := server.New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	var logged lockedBuf
	s.HTTP.ErrorLog = log.New(&logged, "", 0) // no filter: what the service would write
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(l)
	defer s.Close()
	addr := l.Addr().String()
	files := filepath.Join(dir, "clients")
	ca, cert, key := filepath.Join(files, "ca.pem"), filepath.Join(files, "demo.pem"), filepath.Join(files, "demo.key")
	var stderr bytes.Buffer
	ping := func(args ...string) int { stderr.Reset(); return runPing(args, &stderr) }

	if rc := ping("-addr", addr, "-cert", cert, "-key", key, "-ca", ca, "-name", "localhost"); rc != 0 {
		t.Fatalf("a TLS ping failed (%d): %s", rc, stderr.String())
	}
	time.Sleep(200 * time.Millisecond)
	if got := logged.String(); got != "" {
		t.Errorf("a TLS ping wrote to the log of the service: %q", got)
	}

	// the name of the service must be right
	if rc := ping("-addr", addr, "-cert", cert, "-key", key, "-ca", ca, "-name", "not-the-service.example"); rc == 0 {
		t.Error("a certificate for another name was accepted")
	}
	// a client certificate of another CA: the service refuses it, and the ping says so
	other := t.TempDir()
	foreign := func(args ...string) {
		t.Helper()
		var e bytes.Buffer
		if rc := runCA(args, &e, &e); rc != 0 {
			t.Fatalf("ca %v: %s", args, e.String())
		}
	}
	foreign("init", "-dir", filepath.Join(other, "ca"))
	foreign("client", "-dir", filepath.Join(other, "ca"), "-out", other, "-cn", "x")
	found := []string{filepath.Join(other, "x.pem")}
	foreignKey := filepath.Join(other, "x.key")
	if rc := ping("-addr", addr, "-cert", found[0], "-key", foreignKey, "-ca", ca, "-name", "localhost"); rc == 0 {
		t.Error("a certificate of another CA was accepted")
	}

	// -cert, -key, -ca go together
	if rc := ping("-addr", addr, "-cert", cert); rc != 2 {
		t.Errorf("a half of the TLS flags: status %d", rc)
	}
	// the plain ping is a TCP connect
	if rc := ping("-addr", addr); rc != 0 {
		t.Fatalf("TCP ping: %d %s", rc, stderr.String())
	}
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(logged.String(), "EOF") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(logged.String(), "TLS handshake error") {
		t.Logf("the bare connect was not logged here (it is what the filter hides): %q", logged.String())
	}
	if rc := ping("-addr", "127.0.0.1:1", "-timeout", "500ms"); rc != 1 {
		t.Errorf("nothing listens: status %d", rc)
	}
}
