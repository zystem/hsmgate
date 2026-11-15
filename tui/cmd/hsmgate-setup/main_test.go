package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runIt runs the tool with files for its output (run takes files) and returns the exit status and what was printed.
func runIt(t *testing.T, env map[string]string, args ...string) (int, string, string) {
	t.Helper()
	for k, v := range env {
		t.Setenv(k, v)
	}
	dir := t.TempDir()
	out, _ := os.Create(filepath.Join(dir, "out"))
	errf, _ := os.Create(filepath.Join(dir, "err"))
	code := run(args, out, errf)
	out.Close()
	errf.Close()
	o, _ := os.ReadFile(out.Name())
	e, _ := os.ReadFile(errf.Name())
	return code, string(o), string(e)
}

func TestVersion(t *testing.T) {
	if code, out, _ := runIt(t, nil, "-version"); code != 0 || !strings.HasPrefix(out, "hsmgate-setup ") {
		t.Errorf("%d %q", code, out)
	}
}

func TestABadFlagIsRefused(t *testing.T) {
	if code, _, e := runIt(t, nil, "-nonsense"); code != 2 || !strings.Contains(e, "flag provided but not defined") {
		t.Errorf("%d %q", code, e)
	}
}

// With no terminal (a pipe, a script, a CI job) the tool does not draw a screen: it says to use -auto, and a package's first run only prints what to do and succeeds.
func TestNoTerminalNoScreen(t *testing.T) {
	if code, _, e := runIt(t, map[string]string{"HSMGATE_SETUP_AUTO": ""}); code != 1 || !strings.Contains(e, "needs a terminal; for an unattended setup use -auto") {
		t.Errorf("no flags: %d %q", code, e)
	}
	code, out, _ := runIt(t, map[string]string{"HSMGATE_SETUP_AUTO": ""}, "-first-run")
	if code != 0 || !strings.Contains(out, "not configured yet") || !strings.Contains(out, "hsmgate-setup -auto") {
		t.Errorf("-first-run: %d %q", code, out)
	}
}

// -auto never writes over a configuration: with one there, it says so and succeeds (a package may run it again).
func TestAutoLeavesAConfigurationAlone(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "hsmgate.yaml")
	os.WriteFile(cfg, []byte("listen: x\n"), 0o640)
	code, out, _ := runIt(t, nil, "-auto", "-config", cfg)
	if code != 0 || !strings.Contains(out, "exists: nothing to do") {
		t.Errorf("%d %q", code, out)
	}
	if b, _ := os.ReadFile(cfg); string(b) != "listen: x\n" {
		t.Error("the configuration was changed")
	}
}

// the same through the environment a package sets
func TestAutoFromTheEnvironment(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "hsmgate.yaml")
	os.WriteFile(cfg, []byte("listen: x\n"), 0o640)
	code, out, _ := runIt(t, map[string]string{"HSMGATE_SETUP_AUTO": "1"}, "-config", cfg)
	if code != 0 || !strings.Contains(out, "exists: nothing to do") {
		t.Errorf("%d %q", code, out)
	}
}

func TestAutoStopsOnWrongAnswers(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "etc", "hsmgate.yaml")
	code, _, e := runIt(t, nil, "-auto", "-config", cfg, "-key", "a b")
	if code != 1 || !strings.Contains(e, "key name") {
		t.Errorf("%d %q", code, e)
	}
	code, _, e = runIt(t, nil, "-auto", "-config", cfg, "-mode", "card")
	if code != 1 || !strings.Contains(e, "a card needs") {
		t.Errorf("card without its fields: %d %q", code, e)
	}
}

func TestDirOf(t *testing.T) {
	if dirOf("/etc/hsmgate/hsmgate.yaml") != "/etc/hsmgate" || dirOf("hsmgate.yaml") != "." || dirOf("/x") != "." {
		t.Error("dirOf")
	}
}
