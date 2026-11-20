package setup

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var hsmgateBin string

func TestMain(m *testing.M) {
	dir, _ := os.MkdirTemp("", "hsmgate-bin")
	hsmgateBin = filepath.Join(dir, "hsmgate")
	build := exec.Command("go", "build", "-o", hsmgateBin, "./cmd/hsmgate")
	build.Dir = "../../.." // the root module: the program is built there, with its own go.mod
	out, err := build.CombinedOutput()
	if err != nil {
		os.Stderr.Write(out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func answers(t *testing.T) Answers {
	dir := t.TempDir()
	a := Defaults()
	a.Dir = filepath.Join(dir, "etc")
	a.Listen = freePort(t)
	a.AuditFile = filepath.Join(dir, "log", "audit.log")
	a.AdminSocket = filepath.Join(dir, "run", "admin.sock")
	a.Enable = false
	a.User = ""
	a.Bin = hsmgateBin
	return a
}

func TestValidateSaysWhatIsWrong(t *testing.T) {
	bad := map[string]func(*Answers){
		"mode":              func(a *Answers) { a.Mode = "cloud" },
		"relative dir":      func(a *Answers) { a.Dir = "etc/hsmgate" },
		"listen":            func(a *Answers) { a.Listen = "8443" },
		"key name":          func(a *Answers) { a.KeyName = "a b" },
		"client name":       func(a *Answers) { a.ClientName = "../x" },
		"context w/o allow": func(a *Answers) { a.ContextMode = true; a.Allow = nil },
		"card w/o fields":   func(a *Answers) { a.Mode = ModeCard },
		"rotation no file":  func(a *Answers) { a.AuditFile = ""; a.AuditMaxMB = 10 },
	}
	for name, f := range bad {
		a := Defaults()
		a.Dir = "/etc/x"
		f(&a)
		if err := a.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	a := Defaults()
	a.Dir = "/etc/x"
	if err := a.Validate(); err != nil {
		t.Errorf("the defaults are refused: %v", err)
	}
}

// The whole quick setup, for real: the answers become a configuration, a key file and certificates; the service started on them seals and opens a text for the client that was made.
func TestQuickSetupEndToEnd(t *testing.T) {
	a := answers(t)
	a.ContextMode, a.Allow = true, []string{"app/"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var lines []string
	res, err := Apply(ctx, a, func(s string) { lines = append(lines, s) })
	if err != nil {
		t.Fatalf("%v\nlog: %v", err, lines)
	}
	for _, f := range append([]string{a.ConfigPath(), filepath.Join(a.Dir, "server.pem"), filepath.Join(a.Dir, "server.key"), filepath.Join(a.Dir, "ca.pem"), filepath.Join(a.Dir, "soft-app-1.hex")}, res.ClientFiles...) {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("not made: %s", f)
		}
	}
	if st, _ := os.Stat(filepath.Join(a.Dir, "soft-app-1.hex")); st.Mode().Perm() != 0o400 {
		t.Errorf("the key file is %v, want 0400", st.Mode().Perm())
	}
	if len(lines) < 3 {
		t.Errorf("the log: %v", lines)
	}

	// serve it
	srv := exec.Command(hsmgateBin, "serve", "-config", a.ConfigPath())
	stderr, _ := srv.StderrPipe()
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { srv.Process.Kill(); srv.Wait() }()
	ready := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			if strings.Contains(sc.Text(), "listening on") {
				ready <- true
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(15 * time.Second):
		t.Fatal("the service did not start on what the setup made")
	}

	cl := res.ClientFiles
	env := append(os.Environ(), "HSMGATE_ADDR=https://"+a.Listen, "HSMGATE_CA="+cl[2], "HSMGATE_CERT="+cl[0], "HSMGATE_KEYFILE="+cl[1], "HSMGATE_TRANSIT_KEY=app")
	enc := exec.Command(hsmgateBin, "encrypt", "-context", "app/x")
	enc.Env = env
	enc.Stdin = strings.NewReader("my secret\n")
	sealed, err := enc.Output()
	if err != nil || !strings.HasPrefix(string(sealed), "vault:v1:") {
		t.Fatalf("encrypt: %v %q", err, sealed)
	}
	dec := exec.Command(hsmgateBin, "decrypt", "-context", "app/x")
	dec.Env = env
	dec.Stdin = strings.NewReader(string(sealed))
	plain, err := dec.Output()
	if err != nil || strings.TrimSpace(string(plain)) != "my secret" {
		t.Fatalf("decrypt: %v %q", err, plain)
	}
	if !strings.Contains(strings.Join(res.TryIt, "\n"), "hsmgate encrypt -context app/x") {
		t.Errorf("the try-it commands: %v", res.TryIt)
	}
}

func TestDoesNotWriteOverAConfiguration(t *testing.T) {
	a := answers(t)
	os.MkdirAll(a.Dir, 0o750)
	os.WriteFile(a.ConfigPath(), []byte("listen: x\n"), 0o640)
	if _, err := Apply(context.Background(), a, nil); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Errorf("err = %v", err)
	}
	if b, _ := os.ReadFile(a.ConfigPath()); string(b) != "listen: x\n" {
		t.Error("the old configuration was changed")
	}
}

func TestPlanNamesWhatIsDone(t *testing.T) {
	a := answers(t)
	a.Enable = true
	p := strings.Join(func() []string {
		var s []string
		for _, x := range a.Plan() {
			s = append(s, string(x))
		}
		return s
	}(), "\n")
	for _, w := range []string{"hsmgate.yaml", "0400", "authority", "audit", "systemctl enable"} {
		if !strings.Contains(p, w) {
			t.Errorf("the plan lacks %q:\n%s", w, p)
		}
	}
}

func TestHostOfNamesTheMachineWhenListeningOnEveryAddress(t *testing.T) {
	if got := hostOf("127.0.0.1:8443"); got != "127.0.0.1:8443" {
		t.Errorf("%q", got)
	}
	got := hostOf("0.0.0.0:8443")
	if !strings.HasSuffix(got, ":8443") || strings.HasPrefix(got, "0.0.0.0") {
		t.Errorf("%q", got)
	}
	if hostOf("junk") != "junk" {
		t.Error("an address without a port was changed")
	}
}

func TestCardAnswersNeedTheirFieldsAndThePlanSaysNoKeyIsMade(t *testing.T) {
	a := Defaults()
	a.Dir = "/etc/x"
	a.Mode = ModeCard
	a.Module, a.TokenLabel, a.CardKeyID = "/usr/lib/opensc-pkcs11.so", "cinim", "5ded83a1"
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	var plan []string
	for _, s := range a.Plan() {
		plan = append(plan, string(s))
	}
	if !strings.Contains(strings.Join(plan, "\n"), "no key is made on the card") {
		t.Errorf("the plan: %v", plan)
	}
}

// A card answer that lacks something says which thing it is (the module, the label, the id), not a list of all three.
func TestCardAnswerNamesWhatIsMissing(t *testing.T) {
	a := Defaults()
	a.Dir = "/etc/x"
	a.Mode = ModeCard
	a.Module, a.TokenLabel, a.CardKeyID = "", "cinim", ""
	err := a.Validate()
	if err == nil {
		t.Fatal("a card with no module and no key id was accepted")
	}
	for _, want := range []string{"-module", "-card-key-id"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q is not in %q", want, err)
		}
	}
	if strings.Contains(err.Error(), "-token-label") {
		t.Errorf("the label was given and is named as missing: %q", err)
	}
}

func TestUnitFailureNoteSaysWhenThereIsNoUnit(t *testing.T) {
	n := unitFailureNote("Failed to enable unit: Unit hsmgate.service does not exist\n")
	for _, want := range []string{"no systemd unit named hsmgate", "deploy/hsmgate.service", "daemon-reload"} {
		if !strings.Contains(n, want) {
			t.Errorf("%q is not in %q", want, n)
		}
	}
	if o := unitFailureNote("Job for hsmgate.service failed"); !strings.Contains(o, "journalctl -u hsmgate") || strings.Contains(o, "no systemd unit") {
		t.Errorf("another failure is told as a missing unit: %q", o)
	}
}
