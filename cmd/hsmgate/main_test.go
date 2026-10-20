package main

import (
	"bufio"
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
