package ui

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/zystem/hsmgate/tui/internal/setup"
	"github.com/zystem/hsmgate/tui/internal/store"
)

// wizard is the quick setup: a few pages of questions, a review, the doing, and the commands that work now. It uses the same setup.Apply as `hsmgate-setup -auto`.
func (a *App) wizard() {
	ans := setup.Defaults()
	ans.Bin = a.opt.Bin
	if d := a.dir(); d != "." && d != "" {
		ans.Dir = d
	}
	const name = "wizard"

	var page int
	pages := []func() tview.Primitive{}
	var goTo func(i int)

	form := func(title string, f *tview.Form, text string) tview.Primitive {
		f.SetButtonBackgroundColor(tcell.ColorNavy).SetButtonTextColor(tcell.ColorWhite)
		f.SetFieldBackgroundColor(tcell.ColorNavy).SetFieldTextColor(tcell.ColorWhite)
		f.SetBorder(true).SetTitle(" Quick setup: " + title + " ")
		f.SetItemPadding(0)
		f.SetCancelFunc(func() { a.pages.RemovePage(name); a.app.SetFocus(a.nav) })
		if text != "" {
			tv := tview.NewTextView().SetDynamicColors(true).SetText(text).SetWrap(true)
			fl := tview.NewFlex().SetDirection(tview.FlexRow).AddItem(tv, 4, 0, false).AddItem(f, 0, 1, true)
			return fl
		}
		return f
	}
	next := func(f *tview.Form, check func() error) {
		f.AddButton("Back", func() {
			if page > 0 {
				goTo(prev(page, ans))
			}
		})
		f.AddButton("Next", func() {
			if check != nil {
				if err := check(); err != nil {
					a.fail(err)
					return
				}
			}
			goTo(following(page, ans))
		})
		f.AddButton("Cancel", func() { a.pages.RemovePage(name); a.app.SetFocus(a.nav) })
	}
	in := func(f *tview.Form, l string) string {
		return strings.TrimSpace(f.GetFormItemByLabel(l).(*tview.InputField).GetText())
	}

	// 0: where the keys live
	pages = append(pages, func() tview.Primitive {
		f := tview.NewForm()
		idx := 0
		if ans.Mode == setup.ModeCard {
			idx = 1
		}
		f.AddDropDown("Where are the private keys?", []string{"In files (tests, development, a pilot)", "On a smart card or HSM (PKCS#11)"}, idx, func(_ string, i int) {
			ans.Mode = []string{setup.ModeSoft, setup.ModeCard}[i]
		})
		next(f, nil)
		return form("1 of 6, the keys", f, "A key in a file is as safe as the file: for tests and a pilot.\nOn a card the key never leaves the card: for real use. This tool does not make keys on a card; it uses one that is there.")
	})
	// 1: network and place
	pages = append(pages, func() tview.Primitive {
		f := tview.NewForm()
		f.AddInputField("Directory of the configuration", ans.Dir, 0, nil, nil)
		f.AddInputField("Listen on (address:port)", ans.Listen, 30, nil, nil)
		f.AddInputField("More names or addresses of this machine (comma, optional)", ans.ExtraNames, 0, nil, nil)
		f.AddInputField("Service runs as (empty: nobody to give files to)", ans.User, 20, nil, nil)
		f.AddCheckbox("Enable and start the service when done (systemd)", ans.Enable, func(c bool) { ans.Enable = c })
		next(f, func() error {
			ans.Dir, ans.Listen, ans.ExtraNames, ans.User = in(f, "Directory of the configuration"), in(f, "Listen on (address:port)"), in(f, "More names or addresses of this machine (comma, optional)"), in(f, "Service runs as (empty: nobody to give files to)")
			return nil
		})
		return form("2 of 6, the place", f, "The certificate of the service gets the names of this machine by itself; add the ones clients will use (a DNS name, a floating address).")
	})
	// 2: the card
	pages = append(pages, func() tview.Primitive {
		f := tview.NewForm()
		f.AddInputField("PKCS#11 module", ans.Module, 0, nil, nil)
		f.AddInputField("Token label", ans.TokenLabel, 24, nil, nil)
		f.AddInputField("Token serial (optional)", ans.TokenSerial, 24, nil, nil)
		f.AddInputField("CKA_ID of the key pair (hex)", ans.CardKeyID, 44, nil, nil)
		f.AddInputField("PIN file (empty: unlock by hand after each start)", ans.PinFile, 0, nil, nil)
		next(f, func() error {
			ans.Module, ans.TokenLabel, ans.TokenSerial, ans.CardKeyID, ans.PinFile = in(f, "PKCS#11 module"), in(f, "Token label"), in(f, "Token serial (optional)"), in(f, "CKA_ID of the key pair (hex)"), in(f, "PIN file (empty: unlock by hand after each start)")
			if ans.Module == "" || ans.CardKeyID == "" || (ans.TokenLabel == "" && ans.TokenSerial == "") {
				return fmt.Errorf("the module, the label or serial of the token, and the CKA_ID of the key pair are needed.\n`pkcs11-tool --module MODULE -L` shows the token, `-O --type pubkey` the key pairs")
			}
			return nil
		})
		return form("the card", f, "A PIN file is read once at start and is as secret as the PIN: mode 0400. Without it the card starts locked until you unlock it (Tokens, Unlock).")
	})
	// 3: key and client
	pages = append(pages, func() tview.Primitive {
		f := tview.NewForm()
		f.AddInputField("Name of the first key", ans.KeyName, 24, nil, nil)
		idx := 0
		if ans.ContextMode {
			idx = 1
		}
		f.AddDropDown("Context", []string{"none: a fixed key (what OpenBao's seal needs)", "required: each request names what the data belongs to"}, idx, func(_ string, i int) { ans.ContextMode = i == 1 })
		f.AddInputField("Allowed context prefixes (comma; context only)", strings.Join(ans.Allow, ","), 30, nil, nil)
		f.AddInputField("Name of the first client", ans.ClientName, 24, nil, nil)
		next(f, func() error {
			ans.KeyName, ans.ClientName = in(f, "Name of the first key"), in(f, "Name of the first client")
			ans.Allow = nil
			for _, p := range strings.Split(in(f, "Allowed context prefixes (comma; context only)"), ",") {
				if p = strings.TrimSpace(p); p != "" {
					ans.Allow = append(ans.Allow, p)
				}
			}
			if !store.ValidName(ans.KeyName) || !store.ValidName(ans.ClientName) {
				return fmt.Errorf("use letters, digits, dot, dash and underscore for the names")
			}
			if ans.ContextMode && len(ans.Allow) == 0 {
				return fmt.Errorf("a key with a context needs at least one allowed prefix, for example app/")
			}
			return nil
		})
		return form("3 of 6, the first key and client", f, "The client is the program that will use the key. Its certificate is made for you; it gets the right to encrypt, decrypt and rewrap with this key, 600 times a minute.")
	})
	// 4: audit
	pages = append(pages, func() tview.Primitive {
		f := tview.NewForm()
		f.AddInputField("Audit file (empty: the output of the service)", ans.AuditFile, 0, nil, nil)
		f.AddCheckbox("Also to the output of the service (containers, journald)", ans.AuditStdout, func(c bool) { ans.AuditStdout = c })
		f.AddInputField("Rotate at MB (0: never)", strconv.Itoa(ans.AuditMaxMB), 8, nil, nil)
		f.AddInputField("Old files kept", strconv.Itoa(ans.AuditFiles), 8, nil, nil)
		next(f, func() error {
			ans.AuditFile = in(f, "Audit file (empty: the output of the service)")
			var err1, err2 error
			ans.AuditMaxMB, err1 = strconv.Atoi(in(f, "Rotate at MB (0: never)"))
			ans.AuditFiles, err2 = strconv.Atoi(in(f, "Old files kept"))
			if err1 != nil || err2 != nil {
				return fmt.Errorf("the sizes are numbers")
			}
			return nil
		})
		return form("4 of 6, the audit", f, "Every decision is written down, refusals too, before the answer goes out. With a file the service rotates it itself, so it cannot fill the disk.")
	})
	// 5: review
	pages = append(pages, func() tview.Primitive {
		tv := tview.NewTextView().SetDynamicColors(true).SetWrap(true)
		var b strings.Builder
		if err := ans.Validate(); err != nil {
			b.WriteString("[red]Not ready:[black] " + err.Error() + "\n")
		} else if ans.Exists() {
			b.WriteString("[red]" + ans.ConfigPath() + " exists.[black] The quick setup makes the first configuration only; change an existing one in the other sections.\n")
		} else {
			b.WriteString("This will be done:\n\n")
			for _, s := range ans.Plan() {
				b.WriteString("  • " + tview.Escape(string(s)) + "\n")
			}
		}
		tv.SetText(b.String())
		row := tview.NewForm()
		row.SetButtonBackgroundColor(tcell.ColorNavy).SetButtonTextColor(tcell.ColorWhite)
		row.AddButton("Back", func() { goTo(prev(page, ans)) })
		if ans.Validate() == nil && !ans.Exists() {
			row.AddButton("Install", func() { goTo(len(pages)) })
		}
		row.AddButton("Cancel", func() { a.pages.RemovePage(name); a.app.SetFocus(a.nav) })
		fl := tview.NewFlex().SetDirection(tview.FlexRow).AddItem(tv, 0, 1, false).AddItem(row, 3, 0, true)
		fl.SetBorder(true).SetTitle(" Quick setup: 5 of 6, review ")
		return fl
	})

	goTo = func(i int) {
		page = i
		var p tview.Primitive
		if i >= len(pages) {
			p = a.wizardRun(name, ans)
		} else {
			p = pages[i]()
		}
		a.pages.RemovePage(name)
		blank := func() *tview.Box { return tview.NewBox().SetBackgroundColor(tcell.ColorNavy) } // the wizard hides the page under it
		a.pages.AddPage(name, tview.NewFlex().AddItem(blank(), 2, 0, false).AddItem(tview.NewFlex().SetDirection(tview.FlexRow).AddItem(blank(), 1, 0, false).AddItem(p, 0, 1, true).AddItem(blank(), 1, 0, false), 0, 1, true).AddItem(blank(), 2, 0, false), true, true)
		a.app.SetFocus(p)
	}
	goTo(0)
}

// the pages a mode uses: the card page only for a card
func following(i int, ans setup.Answers) int {
	if i == 1 && ans.Mode != setup.ModeCard {
		return 3
	}
	return i + 1
}

func prev(i int, ans setup.Answers) int {
	if i == 3 && ans.Mode != setup.ModeCard {
		return 1
	}
	return i - 1
}

// wizardRun does the setup while the person watches the log, then shows the commands that work now.
func (a *App) wizardRun(name string, ans setup.Answers) tview.Primitive {
	tv := tview.NewTextView().SetDynamicColors(true).SetScrollable(true).SetWrap(true)
	tv.SetBorder(true).SetTitle(" Quick setup: 6 of 6, doing it ")
	tv.SetText("Working…\n")
	log := func(s string) {
		a.app.QueueUpdateDraw(func() { tv.SetText(tv.GetText(false) + "  ✓ " + tview.Escape(s) + "\n") })
	}
	go func() {
		ctx, cancel := a.runCtx()
		defer cancel()
		res, err := setup.Apply(ctx, ans, log)
		a.app.QueueUpdateDraw(func() {
			text := tv.GetText(false)
			if err != nil {
				tv.SetText(text + "\n[red]Stopped:[black] " + tview.Escape(err.Error()) + "\n\nPress Esc to close.")
				tv.SetDoneFunc(func(tcell.Key) { a.pages.RemovePage(name); a.app.SetFocus(a.nav) })
				return
			}
			var b strings.Builder
			b.WriteString(text + "\n[green]Done.[black]\n\nTry it now:\n\n")
			for _, c := range res.TryIt {
				b.WriteString("  " + tview.Escape(c) + "\n")
			}
			b.WriteString("\nThe client's files, to give to the program that uses the key:\n")
			for _, f := range res.ClientFiles {
				b.WriteString("  " + f + "\n")
			}
			for _, n := range res.Notes {
				b.WriteString("\n[::b]Note:[::-] " + tview.Escape(n) + "\n")
			}
			b.WriteString("\nBack up " + filepath.Join(ans.Dir, "ca") + " and the key file: they cannot be made again.\n\nPress Esc to close.")
			tv.SetText(b.String())
			a.opt.ConfigPath = res.ConfigPath
			if d, err := store.Open(res.ConfigPath); err == nil {
				a.doc = d
			}
			tv.SetDoneFunc(func(tcell.Key) { a.pages.RemovePage(name); a.show("dashboard"); a.app.SetFocus(a.nav) })
		})
	}()
	return tv
}
