package ui

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/rivo/tview"

	"github.com/zystem/hsmgate/tui/internal/store"
	"github.com/zystem/hsmgate/tui/internal/sys"
)

func (a *App) tokens() tview.Primitive {
	t := table("Name", "Type", "Labels", "Detail")
	cfg, err := a.cfg()
	if err != nil {
		t.SetTitle(" the configuration is not valid: see Review and save ")
	}
	var names []string
	if cfg != nil {
		for i, tk := range cfg.Tokens {
			labels := make([]string, 0, len(tk.Keys))
			for l := range tk.Keys {
				labels = append(labels, l)
			}
			sort.Strings(labels)
			detail := tk.Module
			if tk.Type == "soft" {
				detail = "private keys in files"
			} else if tk.PinFile != "" {
				detail += " (PIN file)"
			}
			cell(t, i+1, 0, tk.Name)
			cell(t, i+1, 1, tk.Type)
			cell(t, i+1, 2, joinOr(labels, "-"))
			cell(t, i+1, 3, detail)
			names = append(names, tk.Name)
		}
	}
	selected := func() string {
		r, _ := t.GetSelection()
		if r < 1 || r > len(names) {
			return ""
		}
		return names[r-1]
	}
	return a.page("Tokens: where the private keys are", t,
		btn("Add soft token", a.addSoftToken),
		btn("Add card", a.addCardToken),
		btn("Unlock", func() { a.unlock(selected()) }),
		btn("Remove", func() { a.removeToken(selected()) }))
}

func (a *App) addSoftToken() {
	f := tview.NewForm().AddInputField("Name", "soft", 24, nil, nil)
	f.AddButton("Add", func() {
		name := f.GetFormItemByLabel("Name").(*tview.InputField).GetText()
		if err := a.doc.AddSoftToken(name); err != nil {
			a.fail(err)
			return
		}
		a.closeForm()
		a.show("tokens")
	}).AddButton("Cancel", a.closeForm)
	a.form("Add a soft token (keys in files: tests, development)", f, 60, 9)
}

func (a *App) addCardToken() {
	def := moduleDefault()
	f := tview.NewForm().
		AddInputField("Name", "card", 24, nil, nil).
		AddInputField("PKCS#11 module", def, 50, nil, nil).
		AddInputField("Token label", "", 24, nil, nil).
		AddInputField("Token serial (optional)", "", 24, nil, nil).
		AddInputField("PIN file (optional)", "", 50, nil, nil)
	in := func(l string) string { return f.GetFormItemByLabel(l).(*tview.InputField).GetText() }
	f.AddButton("Add", func() {
		err := a.doc.AddPKCS11Token(in("Name"), store.PKCS11{Module: in("PKCS#11 module"), TokenLabel: in("Token label"), TokenSerial: in("Token serial (optional)"), PinFile: in("PIN file (optional)")})
		if err != nil {
			a.fail(err)
			return
		}
		a.closeForm()
		a.show("tokens")
		a.notice("Card added", "Add the key pair of the card to a key with Keys, Create key (give its CKA_ID).\nWithout a PIN file the card starts locked: use Unlock after the service starts.")
	}).AddButton("Cancel", a.closeForm)
	a.form("Add a card or HSM (PKCS#11)", f, 70, 17)
}

func moduleDefault() string {
	for _, p := range []string{"/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so", "/usr/lib64/opensc-pkcs11.so", "/usr/lib/opensc-pkcs11.so"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
}

func (a *App) removeToken(name string) {
	if name == "" {
		a.notice("Remove", "Choose a token in the list first.")
		return
	}
	a.typed("Remove token "+name, "The token is taken out of the configuration. Keys that use it must be removed or moved first: the program refuses otherwise. The private keys on a card are not touched.", name, func() {
		if err := a.doc.RemoveToken(name); err != nil {
			a.fail(err)
			return
		}
		a.show("tokens")
	})
}

// unlock gives a card its PIN through the admin socket of the running service. The PIN is typed masked and kept nowhere.
func (a *App) unlock(name string) {
	if name == "" {
		a.notice("Unlock", "Choose a token in the list first.")
		return
	}
	sock := a.socket()
	if sock == "" {
		a.fail(fmt.Errorf("the configuration has no admin_socket: set it under Settings, save and restart the service"))
		return
	}
	f := tview.NewForm().AddPasswordField("PIN of "+name, "", 24, '*', nil)
	f.AddButton("Unlock", func() {
		pin := []byte(f.GetFormItemByLabel("PIN of " + name).(*tview.InputField).GetText())
		f.GetFormItemByLabel("PIN of " + name).(*tview.InputField).SetText("")
		err := sys.Unlock(sock, name, pin)
		for i := range pin {
			pin[i] = 0
		}
		a.closeForm()
		if err != nil {
			a.fail(fmt.Errorf("%s\n\nA card blocks after a few wrong tries: do not try again before you know the PIN", strings.TrimSpace(err.Error())))
			return
		}
		a.show("dashboard")
		a.notice("Unlocked", "The token "+name+" has its PIN.")
	}).AddButton("Cancel", a.closeForm)
	a.form("Unlock "+name, f, 56, 9)
}
