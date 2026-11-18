// Package ui is the terminal interface of hsmgate-setup: a menu on the left, the page of the chosen section on the right, dialogs in the middle, in the manner of the installers of
// Debian and YaST. Everything is reachable with the keyboard (Tab, the arrows, Enter, Esc) and with the mouse, and it works over SSH and on a serial console.
package ui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/tui/internal/card"
	"github.com/zystem/hsmgate/tui/internal/store"
	"github.com/zystem/hsmgate/tui/internal/sys"
)

// Options says what the tool works on.
type Options struct {
	ConfigPath string
	Socket     string // the admin socket of the running service ("" : the one in the configuration)
	Unit       string // the systemd unit (default hsmgate)
	Version    string
	FirstRun   bool                                                  // start with the quick setup when there is no configuration
	Screen     tcell.Screen                                          // for tests: a simulation screen
	Bin        string                                                // the hsmgate program (found when empty)
	CardRun    card.Run                                              // runs opensc-tool for the Card page (sys.Run when nil; tests give a card made of bytes)
	CardOpen   func(context.Context, card.Reader) (card.Conn, error) // opens the connection for the commands that change the card (opensc-explorer when nil)
	Now        func() time.Time
}

// App is the program.
type App struct {
	opt         Options
	app         *tview.Application
	pages       *tview.Pages
	nav         *tview.List
	body        *tview.Flex     // the right side: the page of a section
	content     tview.Primitive // what the body holds now: Tab moves the focus into it
	sw, sh      int             // the size of the screen, seen at the last draw
	bar         *tview.TextView
	head        *tview.TextView
	doc         *store.Doc
	card        cardState   // the Card page
	cardFormCur *tview.Form // the form of the action that is shown (for tests to fill and press)

	section  string
	sections []section
}

type section struct {
	key   string
	title string
	build func(a *App) tview.Primitive
}

// New opens the configuration (an absent file is an empty document) and builds the screens.
func New(opt Options) (*App, error) {
	if opt.Unit == "" {
		opt.Unit = "hsmgate"
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	doc, err := store.Open(opt.ConfigPath)
	if err != nil {
		return nil, err
	}
	a := &App{opt: opt, app: tview.NewApplication(), pages: tview.NewPages(), doc: doc, card: cardState{reader: -1}}
	if opt.Screen != nil {
		a.app.SetScreen(opt.Screen)
	}
	a.app.EnableMouse(true)
	theme()
	a.sections = []section{
		{"dashboard", "Overview", (*App).dashboard},
		{"tokens", "Tokens", (*App).tokens},
		{"card", "Card", (*App).cardView},
		{"keys", "Keys", (*App).keys},
		{"clients", "Clients", (*App).clients},
		{"settings", "Settings and faces", (*App).settings},
		{"audit", "Audit log", (*App).auditView},
		{"apply", "Review and save", (*App).apply},
	}
	a.layout()
	return a, nil
}

// theme: a blue desktop, grey dialogs with black text, as the installers have.
func theme() {
	tview.Styles.PrimitiveBackgroundColor = tcell.ColorSilver
	tview.Styles.ContrastBackgroundColor = tcell.ColorNavy
	tview.Styles.MoreContrastBackgroundColor = tcell.ColorTeal
	tview.Styles.BorderColor = tcell.ColorBlack
	tview.Styles.TitleColor = tcell.ColorBlack
	tview.Styles.GraphicsColor = tcell.ColorBlack
	tview.Styles.PrimaryTextColor = tcell.ColorBlack
	tview.Styles.SecondaryTextColor = tcell.ColorDarkBlue
	tview.Styles.TertiaryTextColor = tcell.ColorDarkGreen
	tview.Styles.InverseTextColor = tcell.ColorWhite
	tview.Styles.ContrastSecondaryTextColor = tcell.ColorDarkRed
}

func (a *App) layout() {
	a.head = tview.NewTextView().SetDynamicColors(true).SetTextAlign(tview.AlignCenter)
	a.head.SetBackgroundColor(tcell.ColorNavy)
	a.head.SetTextColor(tcell.ColorWhite)
	a.bar = tview.NewTextView().SetDynamicColors(true)
	a.bar.SetBackgroundColor(tcell.ColorTeal)
	a.bar.SetTextColor(tcell.ColorWhite)

	a.nav = tview.NewList().ShowSecondaryText(false)
	a.nav.SetBorder(true).SetTitle(" hsmgate ")
	a.nav.SetSelectedBackgroundColor(tcell.ColorNavy).SetSelectedTextColor(tcell.ColorWhite)
	for i, s := range a.sections {
		key := s.key
		a.nav.AddItem(s.title, "", rune('1'+i), func() { a.show(key) })
	}
	a.nav.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if (ev.Key() == tcell.KeyTab || ev.Key() == tcell.KeyRight) && a.content != nil {
			a.app.SetFocus(a.content)
			return nil
		}
		return ev
	})
	a.nav.SetChangedFunc(func(i int, _ string, _ string, _ rune) { a.show(a.sections[i].key) })

	a.body = tview.NewFlex()
	main := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(a.head, 1, 0, false).
		AddItem(tview.NewFlex().AddItem(a.nav, 26, 0, true).AddItem(a.body, 0, 1, false), 0, 1, true).
		AddItem(a.bar, 1, 0, false)
	a.pages.AddPage("main", main, true, true)

	a.app.SetBeforeDrawFunc(func(s tcell.Screen) bool {
		a.sw, a.sh = s.Size()
		s.Fill(' ', tcell.StyleDefault.Background(tcell.ColorNavy))
		return false
	})
	a.app.SetRoot(a.pages, true)
	a.app.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyCtrlC:
			a.quit()
			return nil
		case tcell.KeyF10:
			a.quit()
			return nil
		}
		return ev
	})
	a.show("dashboard")
}

func (a *App) setBar(text string) { a.bar.SetText(" " + text) }

// refresh rewrites the header (the file, an asterisk for unsaved changes).
func (a *App) refresh() {
	mark := ""
	if a.doc.Changed() {
		mark = "[yellow](unsaved)[white] " // first, so that a long path cannot push it off the screen
	}
	a.head.SetText(fmt.Sprintf("%shsmgate %s  —  %s", mark, a.opt.Version, a.opt.ConfigPath))
}

// show builds the page of a section on the right. A section is built again each time it is shown, so that it always reflects the file.
func (a *App) show(key string) {
	a.section = key
	for _, s := range a.sections {
		if s.key == key {
			a.body.Clear()
			a.content = s.build(a)
			a.body.AddItem(a.content, 0, 1, false)
		}
	}
	a.setBar(fmt.Sprintf("Tab: next field   Enter: choose   Esc: back   F10 or Ctrl-C: quit   1-%d: sections", len(a.sections)))
	a.refresh()
}

// Run starts the screen and returns when the person quits.
func (a *App) Run() error {
	if a.opt.FirstRun && !a.configExists() {
		a.wizard()
	}
	return a.app.Run()
}

func (a *App) configExists() bool { _, err := os.Stat(a.opt.ConfigPath); return err == nil }

// Stop ends the program (used by tests).
func (a *App) Stop() { a.app.Stop() }

func (a *App) quit() {
	if a.doc.Changed() {
		a.ask("Unsaved changes", "There are changes that are not saved. Quit and lose them?", []string{"Keep editing", "Quit without saving"}, func(i int) {
			if i == 1 {
				a.app.Stop()
			}
		})
		return
	}
	a.app.Stop()
}

// ---- dialogs -----------------------------------------------------------------------------------------------------------------------------------------

// modalPage puts a centered primitive over the screen.
func (a *App) modalPage(name string, p tview.Primitive, w, h int) {
	// never bigger than the screen: an installer console is 80x24
	if a.sw > 0 && a.sh > 0 {
		if w > a.sw-2 {
			w = a.sw - 2
		}
		if h > a.sh-2 {
			h = a.sh - 2
		}
	}
	g := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).AddItem(nil, 0, 1, false).AddItem(p, h, 0, true).AddItem(nil, 0, 1, false), w, 0, true).
		AddItem(nil, 0, 1, false)
	a.pages.AddPage(name, g, true, true)
	a.app.SetFocus(p)
}

// ask shows a question with buttons; then is told which one was chosen (the index), after the dialog is closed.
func (a *App) ask(title, text string, buttons []string, then func(int)) {
	prev := a.app.GetFocus() // the focus goes back to where it was: to a form that is still open, to the page
	m := tview.NewModal().SetText(text).AddButtons(buttons)
	m.SetBackgroundColor(tcell.ColorSilver).SetTextColor(tcell.ColorBlack)
	m.SetButtonBackgroundColor(tcell.ColorNavy).SetButtonTextColor(tcell.ColorWhite)
	m.SetDoneFunc(func(i int, _ string) {
		a.pages.RemovePage("modal")
		if prev != nil && a.pages.HasPage("form") || prev != nil && prev != m && a.section == "card" {
			a.app.SetFocus(prev)
		} else {
			a.app.SetFocus(a.nav)
		}
		if i >= 0 && then != nil {
			then(i)
		}
	})
	a.pages.AddPage("modal", m, true, true)
	a.app.SetFocus(m)
}

// notice shows a message with one button.
func (a *App) notice(title, text string) { a.ask(title, text, []string{"OK"}, nil) }

// fail shows an error in words.
func (a *App) fail(err error) {
	a.ask("Error", "[red]Not done:[black]\n\n"+err.Error(), []string{"OK"}, nil)
}

// form shows a form in a bordered dialog.
func (a *App) form(title string, f *tview.Form, w, h int) {
	f.SetBorder(true).SetTitle(" " + title + " ")
	f.SetItemPadding(0) // one row a field: ten fields must fit in 24 rows
	f.SetButtonBackgroundColor(tcell.ColorNavy).SetButtonTextColor(tcell.ColorWhite)
	f.SetFieldBackgroundColor(tcell.ColorNavy).SetFieldTextColor(tcell.ColorWhite)
	f.SetCancelFunc(func() { a.pages.RemovePage("form"); a.app.SetFocus(a.nav) })
	a.modalPage("form", f, w, h)
}

func (a *App) closeForm() { a.pages.RemovePage("form"); a.app.SetFocus(a.nav) }

// typed asks the person to type a word to go on: the way to confirm what cannot be undone.
func (a *App) typed(title, text, word string, then func()) {
	f := tview.NewForm()
	f.AddTextView("", text, 0, 6, true, false)
	f.AddInputField("Type "+word+":", "", 30, nil, nil)
	f.AddButton("Do it", func() {
		if f.GetFormItemByLabel("Type "+word+":").(*tview.InputField).GetText() != word {
			a.fail(fmt.Errorf("you did not type %q: nothing was done", word))
			return
		}
		a.closeForm()
		then()
	})
	f.AddButton("Cancel", a.closeForm)
	a.form(title, f, 70, 16)
}

// ---- small helpers -----------------------------------------------------------------------------------------------------------------------------------

func table(headers ...string) *tview.Table {
	t := tview.NewTable().SetSelectable(true, false).SetFixed(1, 0).SetSeparator(tview.Borders.Vertical)
	t.SetBorder(true)
	t.SetSelectedStyle(tcell.StyleDefault.Background(tcell.ColorNavy).Foreground(tcell.ColorWhite))
	for i, h := range headers {
		t.SetCell(0, i, tview.NewTableCell(h).SetSelectable(false).SetTextColor(tcell.ColorDarkBlue).SetAttributes(tcell.AttrBold).SetExpansion(1))
	}
	return t
}

func cell(t *tview.Table, row, col int, text string) {
	t.SetCell(row, col, tview.NewTableCell(text).SetExpansion(1))
}

// page puts a content and a row of buttons in a bordered box. Tab and Shift-Tab go round the content and the buttons; Esc goes back to the menu.
func (a *App) page(title string, content tview.Primitive, buttons ...*tview.Button) tview.Primitive {
	row := tview.NewFlex()
	ring := []tview.Primitive{content}
	for _, b := range buttons {
		b.SetBackgroundColor(tcell.ColorNavy)
		b.SetLabelColor(tcell.ColorWhite)
		row.AddItem(b, len(b.GetLabel())+4, 0, true).AddItem(nil, 1, 0, false)
		ring = append(ring, b)
	}
	f := tview.NewFlex().SetDirection(tview.FlexRow).AddItem(content, 0, 1, true)
	if len(buttons) > 0 {
		f.AddItem(row, 1, 0, false)
	}
	f.SetBorder(true).SetTitle(" " + title + " ")
	f.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyTab, tcell.KeyBacktab:
			cur := 0
			for i, p := range ring {
				if p.HasFocus() {
					cur = i
				}
			}
			step := 1
			if ev.Key() == tcell.KeyBacktab {
				step = len(ring) - 1
			}
			a.app.SetFocus(ring[(cur+step)%len(ring)])
			return nil
		case tcell.KeyEsc:
			a.app.SetFocus(a.nav)
			return nil
		}
		return ev
	})
	return f
}

func btn(label string, f func()) *tview.Button { return tview.NewButton(label).SetSelectedFunc(f) }

func (a *App) cfg() (*config.Config, error) { return a.doc.Config() }

func (a *App) socket() string {
	if a.opt.Socket != "" {
		return a.opt.Socket
	}
	if v := a.doc.Value("admin_socket"); v != "" {
		return v
	}
	return ""
}

func (a *App) dir() string { return filepath.Dir(a.opt.ConfigPath) }

func (a *App) bin() (string, error) {
	if a.opt.Bin != "" {
		return a.opt.Bin, nil
	}
	return sys.Binary()
}

func (a *App) runCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 2*time.Minute)
}

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func joinOr(s []string, empty string) string {
	if len(s) == 0 {
		return empty
	}
	return strings.Join(s, ", ")
}
