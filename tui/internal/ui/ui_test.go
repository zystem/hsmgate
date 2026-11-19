package ui

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/zystem/hsmgate/tui/internal/card"
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
	r.key(tcell.KeyTab, 0) // Actions
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

// ---- the actions of the Card page ----------------------------------------------------------------------------------------------------------------------

// cardRig is a page that has read a card and can change a simulated one.
func cardRig(t *testing.T) (*rig, *cardtest.Sim) {
	t.Helper()
	c, sim := cardtest.New(t), cardtest.NewSim()
	r := startWith(t, sample, false, func(o *Options) {
		o.CardRun = c.Run
		o.CardOpen = func(context.Context, card.Reader) (card.Conn, error) { return sim, nil }
	})
	r.waitFor("Overview")
	r.screen.SetSize(170, 40)
	r.key(tcell.KeyRune, '3')
	r.key(tcell.KeyTab, 0)
	r.key(tcell.KeyRune, 'r')
	r.waitFor("signer (1, EC-256)")
	return r, sim
}

// fill types into the fields of the form that is shown, and press presses one of its buttons (0 is the first): what a person does with the keys, without the keys.
func (r *rig) fill(vals map[string]string) {
	r.t.Helper()
	r.do(func() {
		for l, v := range vals {
			it, ok := r.app.cardFormCur.GetFormItemByLabel(l).(*tview.InputField)
			if !ok {
				r.t.Fatalf("no field %q", l)
			}
			it.SetText(v)
		}
	})
}

func (r *rig) press(i int) {
	r.t.Helper()
	r.do(func() {
		b := r.app.cardFormCur.GetButton(i)
		b.InputHandler()(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(tview.Primitive) {})
	})
}

func (r *rig) down(n int) {
	for i := 0; i < n; i++ {
		r.key(tcell.KeyDown, 0)
	}
}

// Enter on a line lists what can be done with that line, and only that.
func TestCardActionMenusFollowTheLine(t *testing.T) {
	r, _ := cardRig(t)
	for _, tc := range []struct {
		downs int
		want  []string
		not   []string
	}{
		{0, []string{"Make a DKEK share file", "Import a key from a file"}, []string{"Change the User PIN"}},
		{1, []string{"Change the User PIN", "Unblock the User PIN with the SO PIN"}, []string{"Change the SO PIN"}},
		{2, []string{"Change the SO PIN"}, []string{"Unblock"}},
		{3, []string{"Import a key from a file", "Delete the key encryption key", "Delete the key domain"}, []string{"Import a DKEK share"}},
		{4, []string{"Export the key to a file (wrap)", "Delete the key…"}, nil}, // the signer: ECDH and wrap
		{5, []string{"Import a DKEK share from a file", "Delete the key domain"}, []string{"Delete the key…", "Import a key from a file"}},
		{6, []string{"Delete the key…"}, []string{"Export the key"}}, // the RSA key: no wrap
		{7, []string{"Create a DKEK key domain"}, []string{"Delete"}},
	} {
		for i := 0; i < tc.downs; i++ {
			r.key(tcell.KeyDown, 0)
		}
		r.key(tcell.KeyEnter, 0)
		scr := r.waitFor(append([]string{"Actions (Enter"}, tc.want...)...)
		for _, n := range tc.not {
			if strings.Contains(scr, n) {
				t.Errorf("after %d downs the menu has %q:\n%s", tc.downs, n, scr)
			}
		}
		r.key(tcell.KeyEsc, 0)
		for i := 0; i < tc.downs; i++ { // back to the card line
			r.key(tcell.KeyUp, 0)
		}
	}
}

// A form refuses what is wrong before it goes to the card.
func TestCardFormsRefuseBadInput(t *testing.T) {
	r, sim := cardRig(t)
	r.down(1)
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Change the User PIN")
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Current PIN", "New PIN again")
	r.fill(map[string]string{"Current PIN": "123456", "New PIN": "111111", "New PIN again": "222222"})
	r.press(0)
	r.waitFor("the two new PINs", "nothing was done")
	r.key(tcell.KeyEnter, 0)
	r.fill(map[string]string{"New PIN": "123", "New PIN again": "123"})
	r.press(0)
	r.waitFor("6 to 16 characters")
	if len(sim.Sent) != 0 {
		t.Errorf("the card was asked: %d commands", len(sim.Sent))
	}
}

// The work on the card: the PIN is given only when the card has tries to spare, a wrong PIN stops everything, and what was done is told.
func TestCardWorkGivesThePINCarefully(t *testing.T) {
	r, sim := cardRig(t)
	create := func(pin string) {
		r.do(func() {
			r.app.cardWork("Create the key domain", []byte(pin), func(s *card.Session) (string, error) {
				_, err := s.CreateDKEKDomain(3, 1, "made")
				return "The key domain 3 is made.", err
			})
		})
	}
	create("000000") // wrong
	r.waitFor("did not take the User PIN", "2 tries remaining")
	if sim.Domains[3] != nil || sim.Tries != 2 {
		t.Errorf("after a wrong PIN: %v tries %d", sim.Domains[3], sim.Tries)
	}
	r.key(tcell.KeyEnter, 0)
	sim.Tries = 1
	create("123456") // one try left: not sent at all
	r.waitFor("only 1 try of the User PIN is left")
	if sim.Tries != 1 || sim.Logged {
		t.Errorf("a PIN was sent with one try left: tries %d logged %v", sim.Tries, sim.Logged)
	}
	r.key(tcell.KeyEnter, 0)
	sim.Tries = 3
	create("123456")
	r.waitFor("The key domain 3 is made.")
	if sim.Domains[3] == nil || !strings.HasSuffix(string(sim.Files[0xC703]), "made") {
		t.Errorf("the domain: %+v %q", sim.Domains[3], sim.Files[0xC703])
	}
}

// A destructive action asks for a word first.
func TestCardDeleteAsksForTheWord(t *testing.T) {
	r, sim := cardRig(t)
	sim.Keys[1] = &cardtest.SimKey{Wrap: true}
	r.down(4) // the key of the first domain
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Delete the key…")
	r.key(tcell.KeyDown, 0) // after Export
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Delete the key 1", "Type delete:")
	r.fill(map[string]string{"Type delete:": "yes", "User PIN": "123456"})
	r.press(0)
	r.waitFor("you did not type", "nothing was done")
	if len(sim.Sent) != 0 || sim.Keys[1] == nil {
		t.Error("the card was touched without the word")
	}
}

func TestCardShareFileIsMadeAndRefusesToOverwrite(t *testing.T) {
	defer card.SetKDFCount(20)()
	r, _ := cardRig(t)
	dir := t.TempDir()
	taken := filepath.Join(dir, "taken.pbe")
	os.WriteFile(taken, []byte("x"), 0o600)
	r.do(func() { r.app.makeShare(taken, "a long password", "a long password", card.Strong) })
	r.waitFor("is there already", "nothing is overwritten")
	r.key(tcell.KeyEnter, 0)
	r.do(func() { r.app.makeShare(filepath.Join(dir, "x.pbe"), "short", "short", card.Strong) })
	r.waitFor("must be the same twice")
	r.key(tcell.KeyEnter, 0)
	for _, format := range []card.ShareFormat{card.Strong, card.Compatible} {
		path := filepath.Join(dir, format.String()+".pbe")
		r.do(func() { r.app.makeShare(path, "a long password", "a long password", format) })
		scr := r.waitFor("The share is written to", "key check value of this share", "format")
		st, err := os.Stat(path)
		wantSize := int64(88)
		if format == card.Compatible {
			wantSize = 64
		}
		if err != nil || st.Mode().Perm() != 0o600 || st.Size() != wantSize {
			t.Fatalf("the %s file: %v %v", format, err, st)
		}
		raw, _ := os.ReadFile(path)
		if got, ok := card.FormatOf(raw); !ok || got != format {
			t.Errorf("the format of the file: %v %v", got, ok)
		}
		share, err := card.DecryptShare(raw, []byte("a long password"))
		if err != nil {
			t.Fatal(err)
		}
		if want := fmt.Sprintf("%X", card.KCV(share)); !strings.Contains(scr, want) {
			t.Errorf("the key check value %s is not on the screen:\n%s", want, scr)
		}
		if (format == card.Compatible) != strings.Contains(scr, "compatible format") {
			t.Errorf("the note about the compatible format:\n%s", scr)
		}
		r.key(tcell.KeyEnter, 0)
	}
}

// Whole actions through their forms, on the simulated card: the PIN, the domain, the share, the backup file and the way back.
func TestCardActionsThroughTheForms(t *testing.T) {
	defer card.SetKDFCount(20)()
	r, sim := cardRig(t)
	dir := t.TempDir()
	sim.Domains[0] = &cardtest.SimDomain{Shares: 1, DKEK: bytes.Repeat([]byte{9}, 32)}
	sim.Keys[1] = &cardtest.SimKey{Domain: 0, Wrap: true, Data: bytes.Repeat([]byte{7}, 300)}
	sim.Files[0xC401] = []byte{0xA0, 0x0E, 0x30, 0x09, 0x0C, 0x07, 'b', 'a', 'c', 'k', 'u', 'p', '!', 0x30, 0x01, 0x04}

	// change the User PIN
	r.down(1)
	r.key(tcell.KeyEnter, 0) // the menu
	r.key(tcell.KeyEnter, 0) // Change the User PIN
	r.waitFor("Current PIN")
	r.fill(map[string]string{"Current PIN": "123456", "New PIN": "654321", "New PIN again": "654321"})
	r.press(0)
	r.waitFor("The User PIN is changed.")
	if sim.PIN != "654321" {
		t.Errorf("the PIN is %q", sim.PIN)
	}
	r.key(tcell.KeyEnter, 0)
	r.waitFor("signer (1, EC-256)") // the card is read again; the page stands on the same line

	// export the key of the first domain (the page's tree shows the key 1, which the fake of the page and the simulated card share)
	r.down(3) // the signer
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Export the key to a file (wrap)")
	r.key(tcell.KeyEnter, 0)
	r.waitFor("User PIN", "File")
	wky := filepath.Join(dir, "signer.wky")
	r.fill(map[string]string{"File": wky, "User PIN": "654321"})
	r.press(0)
	r.waitFor("is written to", "308 bytes")
	st, err := os.Stat(wky)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the file: %v %v", err, st)
	}
	r.key(tcell.KeyEnter, 0)

	// the same file again is refused, and so is the key that is on the card already under that label
	r.key(tcell.KeyEnter, 0)
	r.key(tcell.KeyEnter, 0)
	r.waitFor("File")
	r.fill(map[string]string{"File": wky, "User PIN": "654321"})
	r.press(0)
	r.waitFor("is there already", "nothing is overwritten")
	r.key(tcell.KeyEnter, 0)
	r.press(1) // Cancel
	sim.Tries = 3

	// import it back: it comes as the key 2 (the label "backup!" is not on the page's tree, so no refusal)
	r.key(tcell.KeyUp, 0)
	r.key(tcell.KeyUp, 0)
	r.key(tcell.KeyUp, 0)
	r.key(tcell.KeyUp, 0)
	r.key(tcell.KeyEnter, 0) // the card line
	r.waitFor("Import a key from a file")
	r.down(1)
	r.key(tcell.KeyEnter, 0)
	r.waitFor("File", "User PIN")
	r.fill(map[string]string{"File": wky, "User PIN": "654321"})
	r.press(0)
	r.waitFor("The key is on the card as the key 2")
	if k := sim.Keys[2]; k == nil || len(k.Data) != 300 {
		t.Errorf("the key that came back: %+v", k)
	}
}

// Key domains through the forms: make one, give it a share from a file, delete its key encryption key and the domain; and the PINs with the SO PIN.
func TestCardDomainFlowsThroughTheForms(t *testing.T) {
	defer card.SetKDFCount(20)()
	r, sim := cardRig(t)
	dir := t.TempDir()

	// a domain that is not created (the tree of the page is the fake's: line 7)
	r.down(7)
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Create a DKEK key domain")
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Number of shares")
	r.fill(map[string]string{"Number of shares": "300", "Label": "t", "User PIN": "123456"})
	r.press(0)
	r.waitFor("1 to 255")
	r.key(tcell.KeyEnter, 0)
	r.fill(map[string]string{"Number of shares": "1", "Label": "t", "User PIN": "123456"})
	r.press(0)
	r.waitFor("The key domain 2 is made")
	if d := sim.Domains[2]; d == nil || d.Outstanding != 1 {
		t.Fatalf("%+v", sim.Domains[2])
	}
	r.key(tcell.KeyEnter, 0)
	r.waitFor("signer (1, EC-256)")

	// a share from a file into the domain that the page shows as being set up (line 5); the simulated card has it as domain 1
	sim.Domains[1] = &cardtest.SimDomain{Shares: 1, Outstanding: 1, DKEK: make([]byte, 32)}
	share, _ := card.NewShare(nil)
	file, _ := card.EncryptShare(card.Strong, share, []byte("share password"), nil)
	path := filepath.Join(dir, "s.pbe")
	os.WriteFile(path, file, 0o600)
	r.key(tcell.KeyUp, 0)
	r.key(tcell.KeyUp, 0)
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Import a DKEK share from a file")
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Password of the file")
	r.fill(map[string]string{"File": path, "Password of the file": "wrong one", "User PIN": "123456"})
	r.press(0)
	r.waitFor("does not open this DKEK share")
	r.key(tcell.KeyEnter, 0)
	if sim.Domains[1].Outstanding != 1 {
		t.Error("a share was imported with a wrong password")
	}
	r.fill(map[string]string{"Password of the file": "share password"})
	r.press(0)
	r.waitFor("last share is in", "complete")
	if sim.Domains[1].Outstanding != 0 {
		t.Errorf("%+v", sim.Domains[1])
	}
	r.key(tcell.KeyEnter, 0)
	r.waitFor("signer (1, EC-256)")

	// delete the key encryption key and then the domain
	for i, want := range []string{"is deleted", "is deleted"} {
		r.key(tcell.KeyEnter, 0)
		r.waitFor("Delete the key domain")
		r.down(1 + i) // the key encryption key, then the domain
		r.key(tcell.KeyEnter, 0)
		r.waitFor("Type delete:")
		r.fill(map[string]string{"Type delete:": "delete", "User PIN": "123456"})
		r.press(0)
		r.waitFor(want)
		r.key(tcell.KeyEnter, 0)
		r.waitFor("signer (1, EC-256)")
		if i == 0 && sim.Domains[1].Outstanding != 1 {
			t.Error("the key encryption key was not deleted")
		}
	}
	if sim.Domains[1] != nil {
		t.Error("the domain is still there")
	}

	// the PINs: the SO PIN unblocks the User PIN; the SO PIN is changed only with 8 characters
	for i := 0; i < 6; i++ { // up to the card line, then down to the User PIN
		r.key(tcell.KeyUp, 0)
	}
	r.down(1)
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Unblock the User PIN with the SO PIN")
	r.down(1)
	r.key(tcell.KeyEnter, 0)
	r.waitFor("New User PIN again")
	r.fill(map[string]string{"SO PIN": "57621880", "New User PIN": "999999", "New User PIN again": "999999"})
	r.press(0)
	r.waitFor("The User PIN is set to the new one")
	if sim.PIN != "999999" {
		t.Errorf("%q", sim.PIN)
	}
	r.key(tcell.KeyEnter, 0)
	r.waitFor("signer (1, EC-256)")
	r.key(tcell.KeyDown, 0)
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Change the SO PIN")
	r.key(tcell.KeyEnter, 0)
	r.waitFor("New SO PIN again")
	r.fill(map[string]string{"Current SO PIN": "57621880", "New SO PIN": "123", "New SO PIN again": "123"})
	r.press(0)
	r.waitFor("8 characters")
}

// The form of a share file offers the strong format first and the compatible one second, and makes what was chosen.
func TestCardShareFormOffersBothFormats(t *testing.T) {
	defer card.SetKDFCount(20)()
	r, _ := cardRig(t)
	dir := t.TempDir()
	for i, size := range []int64{88, 64} {
		r.key(tcell.KeyEnter, 0) // the card line
		r.waitFor("Make a DKEK share file")
		r.key(tcell.KeyEnter, 0)
		r.waitFor("Password again", "strong")
		path := filepath.Join(dir, fmt.Sprintf("f%d.pbe", i))
		r.fill(map[string]string{"File": path, "Password": "a long password", "Password again": "a long password"})
		r.do(func() {
			dd := r.app.cardFormCur.GetFormItemByLabel("Format").(*tview.DropDown)
			if cur, _ := dd.GetCurrentOption(); cur != 0 {
				t.Errorf("the default format is the option %d", cur)
			}
			dd.SetCurrentOption(i)
		})
		r.press(0)
		r.waitFor("The share is written to")
		if st, err := os.Stat(path); err != nil || st.Size() != size {
			t.Fatalf("option %d: %v %v", i, err, st)
		}
		r.key(tcell.KeyEnter, 0)
		r.waitFor("signer (1, EC-256)")
	}
}

// A key is generated and an XKEK key domain is made through the files, all through the forms on the simulated card.
func TestCardKeyAndXKEKActionsThroughTheForms(t *testing.T) {
	c, sim := cardtest.New(t), cardtest.NewSim()
	c.FCPs["CC01"] = cardtest.KeyFCP(0, []byte{0xFF, 0xFF, 0xFF, 0xFF}, 0x73, 0x80, 0x92) // the first key may sign
	r := startWith(t, sample, false, func(o *Options) {
		o.CardRun = c.Run
		o.CardOpen = func(context.Context, card.Reader) (card.Conn, error) { return sim, nil }
	})
	r.waitFor("Overview")
	r.screen.SetSize(170, 40)
	r.key(tcell.KeyRune, '3')
	r.key(tcell.KeyTab, 0)
	r.key(tcell.KeyRune, 'r')
	r.waitFor("signer (1, EC-256)")
	dir := t.TempDir()
	idFile, kdm := filepath.Join(dir, "dev.id"), filepath.Join(dir, "m.kdm")

	// the device ID of the card
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Export the device ID of this card")
	r.down(2)
	r.key(tcell.KeyEnter, 0)
	r.waitFor("File", "device ID")
	r.fill(map[string]string{"File": idFile})
	r.press(0)
	r.waitFor("The device ID is written to")
	raw, err := os.ReadFile(idFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := card.ParseDeviceID(raw); err != nil {
		t.Errorf("the device ID file: %v", err)
	}
	r.key(tcell.KeyEnter, 0)
	r.waitFor("signer (1, EC-256)")

	// a signing key in the first key domain (line 3): the card makes it and the page writes its description
	r.down(3)
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Generate a key (EC, RSA or AES)")
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Label", "Type", "Use")
	r.fill(map[string]string{"Label": "signer", "User PIN": "123456"})
	r.press(0)
	r.waitFor("a key with the label", "already")
	r.key(tcell.KeyEnter, 0)
	r.fill(map[string]string{"Label": "group-signer"})
	r.do(func() {
		r.app.cardFormCur.GetFormItemByLabel("Use").(*tview.DropDown).SetCurrentOption(4) // an RSA use for an EC type
	})
	r.press(0)
	r.waitFor("is for RSA keys")
	r.key(tcell.KeyEnter, 0)
	r.do(func() {
		r.app.cardFormCur.GetFormItemByLabel("Use").(*tview.DropDown).SetCurrentOption(0) // sign (ECDSA)
	})
	r.press(0)
	r.waitFor("The key 1 (group-signer, EC-256) is made", "CKA_ID")
	if k := sim.Keys[1]; k == nil || k.Domain != 0 || !bytes.Equal(k.Algs, card.AlgorithmByName("EC", "sign")) {
		t.Fatalf("the key: %+v", sim.Keys[1])
	}
	r.key(tcell.KeyEnter, 0)
	r.waitFor("signer (1, EC-256)")

	// the group signer signs the membership of the device (line 4 is the key 1 of the page)
	r.down(1)
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Sign a key domain membership (group signer)")
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Device ID file", "Membership file")
	r.fill(map[string]string{"Device ID file": filepath.Join(dir, "nothing.id"), "Membership file": kdm, "User PIN": "123456"})
	r.press(0)
	r.waitFor("nothing.id")
	r.key(tcell.KeyEnter, 0)
	r.fill(map[string]string{"Device ID file": idFile})
	r.press(0)
	r.waitFor("The membership is written to", "key domain it is for")
	raw, err = os.ReadFile(kdm)
	if err != nil {
		t.Fatal(err)
	}
	mf, err := card.ParseMembershipFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	r.key(tcell.KeyEnter, 0)
	r.waitFor("signer (1, EC-256)")

	// the XKEK key domain from the file (the page's tree has the domain 2 as not created, line 7)
	r.down(3)
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Create an XKEK key domain from a membership file")
	r.down(1)
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Membership file", "Label")
	r.fill(map[string]string{"Membership file": idFile, "User PIN": "123456"})
	r.press(0)
	r.waitFor("not a key domain membership")
	r.key(tcell.KeyEnter, 0)
	r.fill(map[string]string{"Membership file": kdm, "Label": "group"})
	r.press(0)
	r.waitFor("The XKEK key domain 2 is made")
	d := sim.Domains[2]
	if d == nil || d.XKEK == nil || !bytes.Equal(d.XKEK, mf.DomainUID()[:8]) {
		t.Errorf("the domain: %+v, the id of the file %X", d, mf.DomainUID())
	}
}

// An AES key is generated through the form: the type and the use are chosen from the lists, and a use of another kind is refused.
func TestCardGeneratesAnAESKeyThroughTheForm(t *testing.T) {
	c, sim := cardtest.New(t), cardtest.NewSim()
	c.FCPs["CC01"] = cardtest.KeyFCP(0, []byte{0xFF, 0xFF, 0xFF, 0xFF}, 0x73, 0x80, 0x92)
	r := startWith(t, sample, false, func(o *Options) {
		o.CardRun = c.Run
		o.CardOpen = func(context.Context, card.Reader) (card.Conn, error) { return sim, nil }
	})
	r.waitFor("Overview")
	r.screen.SetSize(170, 40)
	r.key(tcell.KeyRune, '3')
	r.key(tcell.KeyTab, 0)
	r.key(tcell.KeyRune, 'r')
	r.waitFor("signer (1, EC-256)")
	r.down(3)
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Generate a key (EC, RSA or AES)")
	r.key(tcell.KeyEnter, 0)
	r.waitFor("Label", "Type", "Use")
	r.fill(map[string]string{"Label": "aes-two", "User PIN": "123456"})
	r.do(func() {
		f := r.app.cardFormCur
		f.GetFormItemByLabel("Type").(*tview.DropDown).SetCurrentOption(4) // AES 256
	})
	r.press(0)
	r.waitFor("is for EC keys")
	r.key(tcell.KeyEnter, 0)
	r.do(func() {
		r.app.cardFormCur.GetFormItemByLabel("Use").(*tview.DropDown).SetCurrentOption(8) // encrypt, decrypt and wrap
	})
	r.press(0)
	r.waitFor("(aes-two, AES-256) is made")
	var k *cardtest.SimKey
	for _, v := range sim.Keys {
		if v.AES == 256 {
			k = v
		}
	}
	if k == nil || !bytes.Equal(k.Algs, card.AlgorithmByName("AES", "encrypt", "wrap")) {
		t.Fatalf("the AES key: %+v", k)
	}
}
