package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
)

const sample = `listen: 127.0.0.1:8443
tls: {cert: /etc/hsmgate/server.pem, key: /etc/hsmgate/server.key, client_ca: /etc/hsmgate/ca.pem}
tokens:
  - name: soft
    type: soft
    keys: {m1: /etc/hsmgate/soft-m1.hex}
keys:
  orders:
    versions: [{token: soft, label: m1}]
    aad: {mode: fixed}
clients:
  - name: shop
    identity: {cn: shop}
    keys:
      orders: {ops: [encrypt, decrypt]}
`

type rig struct {
	t      *testing.T
	screen tcell.SimulationScreen
	app    *App
	done   chan error
}

func start(t *testing.T, cfg string, first bool) *rig {
	t.Helper()
	p := filepath.Join(t.TempDir(), "hsmgate.yaml")
	if cfg != "" {
		os.WriteFile(p, []byte(cfg), 0o640)
	}
	s := tcell.NewSimulationScreen("UTF-8")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(130, 40)
	a, err := New(Options{ConfigPath: p, Screen: s, FirstRun: first, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, screen: s, app: a, done: make(chan error, 1)}
	go func() { r.done <- a.Run() }()
	t.Cleanup(func() { a.Stop() })
	return r
}

// text is the screen as lines. It is read on the goroutine of the application: the simulation screen is drawn on it, and tcell does not lock it for readers.
func (r *rig) text() string {
	var out string
	r.do(func() { out = r.snapshot() })
	return out
}

func (r *rig) snapshot() string {
	cells, w, h := r.screen.GetContents()
	var b strings.Builder
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := cells[y*w+x]
			if len(c.Runes) > 0 {
				b.WriteRune(c.Runes[0])
			} else {
				b.WriteByte(' ')
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func (r *rig) waitFor(want ...string) string {
	r.t.Helper()
	var last string
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(30 * time.Millisecond) {
		last = r.text()
		ok := true
		for _, w := range want {
			if !strings.Contains(last, w) {
				ok = false
			}
		}
		if ok {
			return last
		}
	}
	r.t.Fatalf("the screen never showed %q:\n%s", want, last)
	return ""
}

// do runs fn on the goroutine of the screen and waits: the document belongs to it.
func (r *rig) do(fn func()) {
	r.t.Helper()
	done := make(chan struct{})
	r.app.app.QueueUpdateDraw(func() { fn(); close(done) })
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		r.t.Fatal("the screen did not run the function")
	}
}

func (r *rig) key(k tcell.Key, ch rune) {
	r.screen.InjectKey(k, ch, tcell.ModNone)
	time.Sleep(60 * time.Millisecond)
}

func TestShowsTheSectionsAndTheFile(t *testing.T) {
	r := start(t, sample, false)
	scr := r.waitFor("Overview", "Tokens", "Keys", "Clients", "Settings and faces", "Audit log", "Review and save", "The configuration is good", "1 token(s)", "1 client(s)")
	if !strings.Contains(scr, "hsmgate.yaml") {
		t.Errorf("the header does not name the file:\n%s", scr)
	}
}

func TestSectionsListWhatTheFileHolds(t *testing.T) {
	r := start(t, sample, false)
	r.waitFor("Overview")
	r.key(tcell.KeyRune, '2')
	r.waitFor("Tokens: where the private keys are", "soft", "m1")
	r.key(tcell.KeyRune, '3')
	r.waitFor("orders", "none (fixed)", "shop")
	r.key(tcell.KeyRune, '4')
	r.waitFor("shop", "CN shop", "orders: encrypt/decrypt")
}

func TestReviewShowsNoChangesThenTheDiff(t *testing.T) {
	r := start(t, sample, false)
	r.waitFor("Overview")
	r.key(tcell.KeyRune, '7')
	r.waitFor("The service accepts this file", "No changes")
	r.do(func() {
		r.app.doc.Set(25, "audit", "max_size_mb")
		r.app.show("apply")
	})
	r.waitFor("max_size_mb: 25", "(unsaved)")
}

// An invalid document is shown as refused, and Save refuses it too.
func TestAnInvalidDocumentIsRefusedOnTheScreen(t *testing.T) {
	r := start(t, sample, false)
	r.waitFor("Overview")
	r.do(func() {
		r.app.doc.Set("many", "limits", "max_concurrent")
		r.app.show("apply")
	})
	r.waitFor("The service would refuse this file")
}

func TestFirstRunStartsTheWizardWhenThereIsNoConfiguration(t *testing.T) {
	r := start(t, "", true)
	r.waitFor("Quick setup", "Where are the private keys?", "In files")
}

func TestFirstRunLeavesAnExistingConfigurationAlone(t *testing.T) {
	r := start(t, sample, true)
	scr := r.waitFor("Overview")
	if strings.Contains(scr, "Quick setup: 1 of 6") {
		t.Error("the wizard started over an existing configuration")
	}
}

func TestQuitAsksWhenThereAreUnsavedChanges(t *testing.T) {
	r := start(t, sample, false)
	r.waitFor("Overview")
	r.do(func() { r.app.doc.Set(1, "limits", "queue_seconds"); r.app.refresh() })
	r.key(tcell.KeyF10, 0)
	r.waitFor("There are changes that are not saved", "Quit without saving")
	select {
	case <-r.done:
		t.Fatal("quit without asking")
	default:
	}
}

func TestQuitIsImmediateWithNothingToLose(t *testing.T) {
	r := start(t, sample, false)
	r.waitFor("Overview")
	r.key(tcell.KeyF10, 0)
	select {
	case <-r.done:
	case <-time.After(3 * time.Second):
		t.Fatal("did not quit")
	}
}

func TestRestartNeeded(t *testing.T) {
	// a reload takes keys and clients; the listen address, the audit and the faces need a restart
	r := start(t, sample, false)
	r.waitFor("Overview")
	r.do(func() {
		a, _ := r.app.doc.Config()
		r.app.doc.Set("0.0.0.0:9443", "listen")
		b, _ := r.app.doc.Config()
		if got := restartNeeded(a, b); len(got) != 1 || got[0] != "listen" {
			t.Errorf("restart needed: %v", got)
		}
		if got := restartNeeded(a, a); len(got) != 0 {
			t.Errorf("restart needed for no change: %v", got)
		}
	})
}

func (r *rig) typeText(s string) {
	for _, c := range s {
		r.screen.InjectKey(tcell.KeyRune, c, tcell.ModNone)
	}
	time.Sleep(60 * time.Millisecond)
}

func (r *rig) tabs(n int) {
	for i := 0; i < n; i++ {
		r.screen.InjectKey(tcell.KeyTab, 0, tcell.ModNone)
	}
	time.Sleep(80 * time.Millisecond)
}

// A person creates a key with the keyboard only: the section, Tab to the buttons, Enter, the name, Tab to Create, Enter.
func TestCreatingAKeyWithTheKeyboard(t *testing.T) {
	r := start(t, sample, false)
	r.waitFor("Overview")
	r.key(tcell.KeyRune, '3')
	r.waitFor("orders")
	r.tabs(2) // the table, then the first button: Create key
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Create a key", "Key name")
	r.typeText("invoices")
	r.tabs(10) // the ten fields of the form, then Create
	r.key(tcell.KeyEnter, 0)
	r.waitFor("The key invoices is in", "public point")
	r.do(func() {
		if cfg, err := r.app.doc.Config(); err != nil || len(cfg.Keys["invoices"].Versions) != 1 {
			t.Errorf("the key is not in the document: %v", err)
		}
		if _, err := os.Stat(filepath.Join(r.app.dir(), "soft-invoices-1.hex")); err != nil {
			t.Errorf("no key file: %v", err)
		}
	})
}

// Deleting a key asks for its name first; a wrong word does nothing, the right word removes the key and its grants.
func TestDeletingAKeyAsksForItsName(t *testing.T) {
	r := start(t, sample, false)
	r.waitFor("Overview")
	r.key(tcell.KeyRune, '3')
	r.waitFor("orders")
	r.tabs(4) // table, Create key, Rotate, Delete
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Delete key orders", "Everything sealed under it cannot be opened")
	r.typeText("nope")
	r.tabs(1) // to "Do it"
	r.key(tcell.KeyEnter, 0)
	r.waitFor("nothing was done")
	r.do(func() {
		cfg, _ := r.app.doc.Config()
		if _, ok := cfg.Keys["orders"]; !ok {
			t.Error("the key was deleted by a wrong word")
		}
	})
}
