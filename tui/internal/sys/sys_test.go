package sys

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewSoftKeyWritesAKeyTheServiceCanRead(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "k.hex")
	pt, err := NewSoftKey(p, "")
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o400 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	raw, _ := os.ReadFile(p)
	if b, err := hex.DecodeString(strings.TrimSpace(string(raw))); err != nil || len(b) != 32 {
		t.Errorf("not 64 hex digits: %v %q", err, raw)
	}
	if !strings.HasPrefix(pt, "04") || len(pt) != 16 {
		t.Errorf("point %q", pt)
	}
	if _, err := NewSoftKey(p, ""); err == nil {
		t.Error("a key file was written over another")
	}
}

func TestShredRemovesTheFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k")
	os.WriteFile(p, []byte("secret-secret"), 0o600)
	if err := Shred(p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err == nil {
		t.Error("still there")
	}
	if err := Shred(p); err == nil {
		t.Error("shredded a file that is not there")
	}
}

// a fake admin socket: the status and the unlock answers of the service
func fakeAdmin(t *testing.T, pinOK string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "a.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"card": "locked", "soft": "ready"})
	})
	mux.HandleFunc("POST /unlock", func(w http.ResponseWriter, r *http.Request) {
		var b struct{ Token, Pin string }
		json.NewDecoder(r.Body).Decode(&b)
		if b.Pin != pinOK {
			http.Error(w, "the card refused the PIN", http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"state": "ready"})
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return sock
}

func TestStatusAndUnlockThroughTheAdminSocket(t *testing.T) {
	sock := fakeAdmin(t, "1234")
	st, err := Status(sock)
	if err != nil || st["card"] != "locked" || st["soft"] != "ready" {
		t.Fatalf("%v %v", st, err)
	}
	pin := []byte("0000")
	if err := Unlock(sock, "card", pin); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("a wrong PIN: %v", err)
	}
	if err := Unlock(sock, "card", []byte("1234")); err != nil {
		t.Errorf("the right PIN: %v", err)
	}
}

func TestNotRunningIsRecognised(t *testing.T) {
	_, err := Status(filepath.Join(t.TempDir(), "nothing.sock"))
	if !ErrNotRunning(err) {
		t.Errorf("a missing socket is not 'not running': %v", err)
	}
	if ErrNotRunning(nil) {
		t.Error("nil is not an error")
	}
}

func TestRunReportsTheOutputOfAFailure(t *testing.T) {
	out, err := Run(context.Background(), "sh", "-c", "echo boom >&2; exit 3")
	if err == nil || !strings.Contains(err.Error(), "boom") || !strings.Contains(out, "boom") {
		t.Errorf("%q %v", out, err)
	}
	if out, err := Run(context.Background(), "echo", "fine"); err != nil || strings.TrimSpace(out) != "fine" {
		t.Errorf("%q %v", out, err)
	}
}

func TestRunAsWithoutRootIsRun(t *testing.T) {
	if IsRoot() {
		t.Skip("root can change user")
	}
	if out, err := RunAs(context.Background(), "nobody", "echo", "x"); err != nil || strings.TrimSpace(out) != "x" {
		t.Errorf("%q %v", out, err)
	}
}

func TestBinaryFindsTheProgramInTheEnvironmentOrNextToTheTool(t *testing.T) {
	t.Setenv("HSMGATE_BIN", "/somewhere/hsmgate")
	if b, err := Binary(); err != nil || b != "/somewhere/hsmgate" {
		t.Errorf("%q %v", b, err)
	}
	t.Setenv("HSMGATE_BIN", "")
	t.Setenv("PATH", t.TempDir())
	if _, err := Binary(); err == nil {
		t.Error("found a program that is not there")
	}
}
