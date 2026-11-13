package main

import (
	"bufio"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The test binary runs main() when asked to, so that a real process can be sent a real signal.
func TestMain(m *testing.M) {
	if os.Getenv("HSMGATE_RUN_MAIN") == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

// A stop requested by SIGTERM (what systemd and Docker send) is a clean exit: code 0, and the tokens are logged out first.
func TestSIGTERMIsACleanStop(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "c.yaml")
	os.WriteFile(filepath.Join(dir, "k"), []byte(strings.Repeat("11", 32)), 0o600)
	os.WriteFile(cfg, []byte("listen: 127.0.0.1:0\ninsecure_loopback_client: t\naudit: {file: "+filepath.Join(dir, "a.log")+"}\n"+
		"tokens: [{name: soft, type: soft, keys: {m: "+filepath.Join(dir, "k")+"}}]\n"+
		"keys: {k: {versions: [{token: soft, label: m}], aad: {mode: fixed}}}\n"+
		"clients: [{name: t, identity: {cn: t}, keys: {k: {ops: [encrypt]}}}]\n"), 0o600)
	cmd := exec.Command(os.Args[0], "serve", "-config", cfg)
	cmd.Env = append(os.Environ(), "HSMGATE_RUN_MAIN=1")
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	lines := make(chan string, 20)
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	deadline := time.After(10 * time.Second)
	for ready := false; !ready; {
		select {
		case l := <-lines:
			ready = strings.Contains(l, "listening on")
		case <-deadline:
			cmd.Process.Kill()
			t.Fatal("the service did not start")
		}
	}
	cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var out []string
	all, live := lines, lines // all stays as it is (a closed channel ends a range); live becomes nil when closed, so that select does not spin
	for {
		select {
		case l, ok := <-live:
			if !ok {
				live = nil
				continue
			}
			out = append(out, l)
		case err := <-done:
			for l := range all {
				out = append(out, l)
			}
			if err != nil {
				t.Fatalf("exit: %v\n%s", err, strings.Join(out, "\n"))
			}
			if !strings.Contains(strings.Join(out, "\n"), "tokens logged out") || strings.Contains(strings.Join(out, "\n"), "Server closed") {
				t.Errorf("output: %q", out)
			}
			return
		case <-time.After(10 * time.Second):
			cmd.Process.Kill()
			t.Fatal("the service did not stop")
		}
	}
}

// SIGHUP makes the service open the audit file again: after logrotate renamed it, the lines go to a new file at the path, not to the renamed one. The signal is a real one,
// sent to a real process (the reload itself is refused in this plain mode, which does not matter: the file is reopened first).
func TestSIGHUPReopensTheAuditFile(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "c.yaml")
	logf := filepath.Join(dir, "a.log")
	os.WriteFile(filepath.Join(dir, "k"), []byte(strings.Repeat("11", 32)), 0o600)
	os.WriteFile(cfg, []byte("listen: 127.0.0.1:0\ninsecure_loopback_client: t\naudit: {file: "+logf+"}\n"+
		"tokens: [{name: soft, type: soft, keys: {m: "+filepath.Join(dir, "k")+"}}]\n"+
		"keys: {k: {versions: [{token: soft, label: m}], aad: {mode: fixed}}}\n"+
		"clients: [{name: t, identity: {cn: t}, keys: {k: {ops: [encrypt]}}}]\n"), 0o600)
	cmd := exec.Command(os.Args[0], "serve", "-config", cfg)
	cmd.Env = append(os.Environ(), "HSMGATE_RUN_MAIN=1")
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	lines := make(chan string, 50)
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	var addr string
	deadline := time.After(10 * time.Second)
	for addr == "" {
		select {
		case l := <-lines:
			if i := strings.Index(l, "listening on "); i >= 0 {
				addr = strings.TrimSpace(l[i+len("listening on "):])
			}
		case <-deadline:
			t.Fatal("the service did not start")
		}
	}
	call := func() {
		t.Helper()
		resp, err := http.Post("http://"+addr+"/v1/transit/encrypt/k", "application/json", strings.NewReader(`{"plaintext":"aGVsbG8="}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	count := func(p string) int {
		b, _ := os.ReadFile(p)
		return strings.Count(string(b), "\n")
	}
	call()
	before := count(logf)
	if before == 0 {
		t.Fatal("the first call wrote no audit line")
	}
	if err := os.Rename(logf, logf+".1"); err != nil { // what logrotate does
		t.Fatal(err)
	}
	cmd.Process.Signal(syscall.SIGHUP)
	for end := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if _, err := os.Stat(logf); err == nil { // the reopen creates the file at the path
			break
		}
		if time.Now().After(end) {
			t.Fatal("no new file at the path after SIGHUP")
		}
	}
	call()
	if count(logf) == 0 {
		t.Error("the line after the signal did not go to the new file")
	}
	if count(logf+".1") != before {
		t.Errorf("the renamed file grew: %d lines, was %d", count(logf+".1"), before)
	}
}
