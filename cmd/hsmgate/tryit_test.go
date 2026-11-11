package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/server"
)

// The commands of "Try it in a minute" in README.md are run here against the service that `hsmgate dev` makes, and what they print is what the README shows:
// each line of output that the README shows must be what the command printed, and must be in the README. A change of a message fails this test until the README follows.
func TestTryItOutputsAreWhatTheReadmeShows(t *testing.T) {
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
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(l)
	defer s.Close()

	files := filepath.Join(dir, "clients")
	conn := []string{"-addr", "https://" + l.Addr().String(), "-ca", filepath.Join(files, "ca.pem"), "-cert", filepath.Join(files, "demo.pem"), "-keyfile", filepath.Join(files, "demo.key")}
	run := func(f func([]string, *bytes.Reader, *bytes.Buffer, *bytes.Buffer) int, stdin string, args ...string) (code int, out, errOut string) {
		var o, e bytes.Buffer
		code = f(append(append([]string{}, conn...), args...), bytes.NewReader([]byte(stdin)), &o, &e)
		return code, o.String(), e.String()
	}
	enc := func(args []string, in *bytes.Reader, o, e *bytes.Buffer) int { return runEncrypt(args, in, o, e) }
	dec := func(args []string, in *bytes.Reader, o, e *bytes.Buffer) int { return runDecrypt(args, in, o, e) }

	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	shown := func(what string) {
		t.Helper()
		if !strings.Contains(string(readme), what) {
			t.Errorf("README.md does not show %q", what)
		}
	}

	// echo 'my secret' | hsmgate encrypt > sealed.txt
	code, sealed, msg := run(enc, "my secret\n", "-transit-key", "demo")
	if code != 0 || !strings.HasPrefix(sealed, "vault:v1:ZWNpZXMy") {
		t.Fatalf("encrypt: %d %q %q", code, sealed, msg)
	}
	shown("vault:v1:ZWNpZXMy")
	if line := strings.TrimSpace(msg); line != `sealed under version 1 of key "demo" with context ""` {
		t.Errorf("encrypt says %q", line)
	} else {
		shown(line)
	}

	// hsmgate decrypt < sealed.txt
	code, plain, msg := run(dec, sealed, "-transit-key", "demo")
	if code != 0 || strings.TrimSpace(plain) != "my secret" {
		t.Fatalf("decrypt: %d %q %q", code, plain, msg)
	}
	shown("my secret")

	// the key with a context: the right one opens, another does not
	code, c, msg := run(enc, "x\n", "-transit-key", "demo-ctx", "-context", "demo/a")
	if code != 0 {
		t.Fatalf("encrypt with a context: %d %q", code, msg)
	}
	if line := strings.TrimSpace(msg); line != `sealed under version 1 of key "demo-ctx" with context "demo/a"` {
		t.Errorf("encrypt with a context says %q", line)
	} else {
		shown(line)
	}
	code, _, msg = run(dec, c, "-transit-key", "demo-ctx", "-context", "demo/b")
	want := `hsmgate decrypt: the ciphertext cannot be opened with key "demo-ctx" and context "demo/b": it was sealed with another key or another context, or it is damaged`
	if code == 0 || strings.TrimSpace(msg) != want {
		t.Errorf("a wrong context: %d %q", code, msg)
	} else {
		shown(want)
	}
}
