package ui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/zystem/hsmgate/tui/internal/card/cardtest"
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

func start(t *testing.T, cfg string, first bool) *rig { return startWith(t, cfg, first, nil) }

// startWith is start with a change to the options (a card made of bytes, for one).
func startWith(t *testing.T, cfg string, first bool, mod func(*Options)) *rig {
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
	opt := Options{ConfigPath: p, Screen: s, FirstRun: first, Version: "test"}
	if mod != nil {
		mod(&opt)
	}
	a, err := New(opt)
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
	scr := r.waitFor("Overview", "Tokens", "Card", "Keys", "Clients", "Settings and faces", "Audit log", "Review and save", "The configuration is good", "1 token(s)", "1 client(s)")
	if !strings.Contains(scr, "hsmgate.yaml") {
		t.Errorf("the header does not name the file:\n%s", scr)
	}
}

func TestSectionsListWhatTheFileHolds(t *testing.T) {
	r := start(t, sample, false)
	r.waitFor("Overview")
	r.key(tcell.KeyRune, '2')
	r.waitFor("Tokens: where the private keys are", "soft", "m1")
	r.key(tcell.KeyRune, '4')
	r.waitFor("orders", "none (fixed)", "shop")
	r.key(tcell.KeyRune, '5')
	r.waitFor("shop", "CN shop", "orders: encrypt/decrypt")
}

func TestReviewShowsNoChangesThenTheDiff(t *testing.T) {
	r := start(t, sample, false)
	r.waitFor("Overview")
	r.key(tcell.KeyRune, '8')
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
	r.key(tcell.KeyRune, '4')
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
	r.key(tcell.KeyRune, '4')
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

// Every section of the menu draws, also the ones that read the disk (the audit log) or build a long form (the settings).
func TestEverySectionDraws(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "audit.log")
	os.WriteFile(log, []byte(`{"time":"2026-11-14T10:00:00Z","client":"shop","face":"transit","key":"orders","op":"encrypt","result":"ok"}
{"time":"2026-11-14T10:00:01Z","client":"shop","face":"transit","key":"orders","op":"encrypt","result":"forbidden"}
`), 0o640)
	r := start(t, sample+"audit: {file: "+log+"}\n", false)
	r.waitFor("Overview")
	for key, want := range map[rune][]string{
		'6': {"Settings and faces", "Listen (restart)", "Apply to the document"},
		'7': {"Audit log", "ok", "forbidden"},
		'1': {"The configuration is good"},
	} {
		r.key(tcell.KeyRune, key)
		r.waitFor(want...)
	}
	// the filter of the audit page: only the problems
	r.key(tcell.KeyRune, '7')
	r.waitFor("forbidden")
	r.tabs(3) // the text, All, Problems
	r.key(tcell.KeyEnter, 0)
	scr := r.waitFor("forbidden")
	if strings.Contains(scr, "10:00:00 ok") {
		t.Errorf("the problems filter shows an ok line:\n%s", scr)
	}
}

func TestSettingsFormChangesTheDocument(t *testing.T) {
	r := start(t, sample, false)
	r.waitFor("Overview")
	r.key(tcell.KeyRune, '6')
	r.waitFor("Apply to the document")
	r.do(func() {
		a := r.app
		a.show("settings")
		f := a.content.(*tview.Form)
		f.GetFormItemByLabel("Listen (restart)").(*tview.InputField).SetText("0.0.0.0:9443")
		f.GetFormItemByLabel("Rotate the audit file at MB (0: never) (restart)").(*tview.InputField).SetText("not a number")
		a.applySettings(f)
	})
	r.waitFor("must be a number")
	r.do(func() {
		a := r.app
		f := a.content.(*tview.Form)
		f.GetFormItemByLabel("Rotate the audit file at MB (0: never) (restart)").(*tview.InputField).SetText("0")
		a.applySettings(f)
		if got := a.doc.Value("listen"); got != "0.0.0.0:9443" {
			t.Errorf("listen = %q", got)
		}
	})
}

// The Card page: nothing is sent to the card until it is asked; then the tree is drawn as a card manager draws it, and the selected line is explained.
func TestCardPageShowsTheTree(t *testing.T) {
	c := cardtest.New(t)
	r := startWith(t, sample, false, func(o *Options) { o.CardRun = c.Run })
	r.waitFor("Overview")
	r.screen.SetSize(170, 40) // the lines of the tree are long
	r.key(tcell.KeyRune, '3')
	r.waitFor("Card: what a SmartCard-HSM holds", "Read the card", "No PIN is sent")
	if len(c.Calls) != 0 {
		t.Fatalf("the card was asked before the person asked: %v", c.Calls)
	}
	r.key(tcell.KeyTab, 0) // into the tree
	r.key(tcell.KeyRune, 'r')
	scr := r.waitFor("demo (DECC1800263)", "User PIN not verified, 3 tries remaining (63C3)", "SO PIN not verified, 15 tries remaining (63CF)",
		"DKEK with KCV AA02030405060708 (first)", "signer (1, EC-256)", "DKEK set-up in progress with 1 of 2 shares missing (second)", "rsa key (2, RSA-4096)",
		"Key domain 2 not created", "Key domain 3 not created", "version 4.1")
	if strings.Contains(scr, "Key domain 4") {
		t.Errorf("a domain that the card does not have:\n%s", scr)
	}
	// the arrow keys move down the tree and the right side explains the line
	r.key(tcell.KeyDown, 0)
	r.waitFor("the PIN that opens the card for use", "3")
	r.key(tcell.KeyDown, 0)
	r.key(tcell.KeyDown, 0)
	r.waitFor("Key check value (KCV)", "AA02030405060708")
	r.key(tcell.KeyDown, 0)
	r.waitFor("CKA_ID", "Not in the configuration")
}

// A key of the card that the configuration names says so.
func TestCardKeyIsMatchedWithTheConfiguration(t *testing.T) {
	c := cardtest.New(t)
	cfg := "tokens:\n  - {name: card, type: pkcs11, module: /m.so, token_label: x, keys: {c1: \"0100000000000000000000000000000000000000\"}}\nkeys:\n  k: {versions: [{token: card, label: c1}], aad: {mode: fixed}}\n"
	r := startWith(t, cfg, false, func(o *Options) { o.CardRun = c.Run })
	r.waitFor("Overview")
	r.screen.SetSize(170, 40)
	r.key(tcell.KeyRune, '3')
	r.key(tcell.KeyTab, 0)
	r.key(tcell.KeyRune, 'r')
	r.waitFor("signer (1, EC-256)")
	for i := 0; i < 4; i++ {
		r.key(tcell.KeyDown, 0)
	}
	r.waitFor("In the configuration: token", "card", "label", "c1")
}

// No reader, no tool, no card: each is said in words and the tree is not drawn.
func TestCardPageSaysWhyItCannotRead(t *testing.T) {
	for name, tc := range map[string]struct {
		run  func(context.Context, string, ...string) (string, error)
		want string
	}{
		"no reader": {func(context.Context, string, ...string) (string, error) { return "No smart card readers found.\n", nil }, "PC/SC shows no card reader"},
		"no tool": {func(context.Context, string, ...string) (string, error) {
			return "", fmt.Errorf(`exec: "opensc-tool": executable file not found in $PATH`)
		}, "apt install opensc"},
		"no card": {func(context.Context, string, ...string) (string, error) {
			return "# Detected readers (pcsc)\nNr.  Card  Features  Name\n0    No              R 00 00\n", nil
		}, "none of the 1 reader(s) has a card in it"},
	} {
		t.Run(name, func(t *testing.T) {
			r := startWith(t, sample, false, func(o *Options) { o.CardRun = tc.run })
			r.waitFor("Overview")
			r.key(tcell.KeyRune, '3')
			r.key(tcell.KeyTab, 0)
			r.key(tcell.KeyRune, 'r')
			r.waitFor("the card could not be read", tc.want)
		})
	}
}

// With more than one card in readers the page does not guess: it shows the menu of the readers. The Reader button shows it again, with the reader in use marked, and a reader
// with no card is refused in words.
func TestCardReaderMenu(t *testing.T) {
	c := cardtest.New(t)
	c.Readers = []cardtest.ReaderInfo{{Name: "Reader A 00 00", HasCard: true, Label: "first-card"}, {Name: "Reader B 01 00", HasCard: true, Label: "second-card"}, {Name: "Reader C 02 00"}}
	r := startWith(t, sample, false, func(o *Options) { o.CardRun = c.Run })
	r.waitFor("Overview")
	r.screen.SetSize(170, 40)
	r.key(tcell.KeyRune, '3')
	r.key(tcell.KeyTab, 0)
	r.key(tcell.KeyRune, 'r')
	r.waitFor("Choose the reader", "automatic: the only reader that has a card", "0  card", "Reader A", "1  card", "Reader B", "2  no card", "Reader C")
	for _, call := range c.Calls {
		t.Errorf("a card was read before a reader was chosen: %v", call)
	}
	r.key(tcell.KeyDown, 0) // from "automatic" to A, then B
	r.key(tcell.KeyDown, 0)
	r.key(tcell.KeyEnter, 0)
	r.waitFor("second-card (DECC1800263)", "the card (reader 1)")

	// the Reader button: the reader in use is marked
	r.key(tcell.KeyTab, 0) // Read the card
	r.key(tcell.KeyTab, 0) // Reader
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Choose the reader", "* 1  card")
	r.key(tcell.KeyUp, 0) // B to A, then to "automatic" (the list wraps round after that)
	r.key(tcell.KeyUp, 0)
	r.key(tcell.KeyEnter, 0) // automatic again: two cards, so the menu comes up
	r.waitFor("Choose the reader", "* automatic")
	r.key(tcell.KeyEsc, 0)

	// a reader with no card
	r.key(tcell.KeyTab, 0)
	r.key(tcell.KeyTab, 0)
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Choose the reader")
	for i := 0; i < 3; i++ { // automatic, A, B, C
		r.key(tcell.KeyDown, 0)
	}
	r.key(tcell.KeyEnter, 0)
	r.waitFor("the card could not be read", "there is no card in the reader 2")
}

// One card among the readers is the one that is meant: no menu.
func TestCardOneCardAmongReadersNeedsNoMenu(t *testing.T) {
	c := cardtest.New(t)
	c.Readers = []cardtest.ReaderInfo{{Name: "Empty 00 00"}, {Name: "Full 01 00", HasCard: true, Label: "only-card"}}
	r := startWith(t, sample, false, func(o *Options) { o.CardRun = c.Run })
	r.waitFor("Overview")
	r.screen.SetSize(170, 40)
	r.key(tcell.KeyRune, '3')
	r.key(tcell.KeyTab, 0)
	r.key(tcell.KeyRune, 'r')
	scr := r.waitFor("only-card (DECC1800263)", "the card (reader 1)")
	if strings.Contains(scr, "Choose the reader") {
		t.Errorf("the menu came up for one card:\n%s", scr)
	}
}

// A key domain with an XKEK and a DKEK that is still being set up are worded as the card manager words them.
func TestCardShowsXKEKDomain(t *testing.T) {
	c := cardtest.New(t)
	c.Domains[2] = []byte{0, 0, 0xCC, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8}
	r := startWith(t, sample, false, func(o *Options) { o.CardRun = c.Run })
	r.waitFor("Overview")
	r.screen.SetSize(170, 40)
	r.key(tcell.KeyRune, '3')
	r.key(tcell.KeyTab, 0)
	r.key(tcell.KeyRune, 'r')
	r.waitFor("XKEK with KCV CC02030405060708 in key domain 0102030405060708", "DKEK set-up in progress with 1 of 2 shares missing (second)", "DKEK with KCV AA02030405060708 (first)")
	for i := 0; i < 7; i++ { // the card, 2 PINs, domain 0 and its key, domain 1 and its key: the next line is the XKEK domain
		r.key(tcell.KeyDown, 0)
	}
	r.waitFor("exchange key encryption key", "0102030405060708")
}
