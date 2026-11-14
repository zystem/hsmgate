package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rivo/tview"

	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/tui/internal/actions"
	"github.com/zystem/hsmgate/tui/internal/store"
)

func (a *App) keys() tview.Primitive {
	t := table("Key", "Versions", "Context", "Usage", "Faces", "Clients")
	var names []string
	if cfg, err := a.cfg(); err == nil {
		for n := range cfg.Keys {
			names = append(names, n)
		}
		sort.Strings(names)
		for i, n := range names {
			k := cfg.Keys[n]
			mode := "none (fixed)"
			if k.AAD.Mode == "context" {
				mode = strings.Join(k.AAD.Allow, " ")
			}
			var faces []string
			if k.KMSJSON {
				faces = append(faces, "json")
			}
			if k.KMSGRPC {
				faces = append(faces, "grpc")
			}
			if k.KMSRest {
				faces = append(faces, "rest")
			}
			var who []string
			for _, c := range cfg.Clients {
				if _, ok := c.Keys[n]; ok {
					who = append(who, c.Name)
				}
			}
			usage := k.KMSJSONUsage
			if usage == "" {
				usage = "transit"
			}
			cell(t, i+1, 0, n)
			cell(t, i+1, 1, fmt.Sprint(len(k.Versions)))
			cell(t, i+1, 2, mode)
			cell(t, i+1, 3, usage)
			cell(t, i+1, 4, joinOr(faces, "-"))
			cell(t, i+1, 5, joinOr(who, "-"))
		}
	} else {
		t.SetTitle(" the configuration is not valid: see Review and save ")
	}
	sel := func() string {
		r, _ := t.GetSelection()
		if r < 1 || r > len(names) {
			return ""
		}
		return names[r-1]
	}
	return a.page("Keys", t,
		btn("Create key", a.createKey),
		btn("Rotate", func() { a.rotateKey(sel()) }),
		btn("Delete", func() { a.deleteKey(sel()) }))
}

// tokenChoices lists the tokens and says which are soft.
func (a *App) tokenChoices() (names []string, soft map[string]bool) {
	soft = map[string]bool{}
	if cfg, err := a.cfg(); err == nil {
		for _, t := range cfg.Tokens {
			names = append(names, t.Name)
			soft[t.Name] = t.Type == "soft"
		}
	}
	return
}

func (a *App) createKey() {
	toks, soft := a.tokenChoices()
	if len(toks) == 0 {
		a.notice("Create key", "There is no token yet. Add one first (Tokens: a soft token for tests, a card for real keys).")
		return
	}
	f := tview.NewForm()
	f.AddInputField("Key name", "", 28, nil, nil)
	f.AddDropDown("Token", toks, 0, nil)
	f.AddCheckbox("Make a new key file (soft token)", true, nil)
	f.AddInputField("Card: CKA_ID of the key pair (hex)", "", 44, nil, nil)
	f.AddDropDown("Context", []string{"none: a fixed key (OpenBao seal and similar)", "required: the request's context is bound to the key"}, 0, nil)
	f.AddInputField("Allowed context prefixes (context only, comma)", "app/", 30, nil, nil)
	f.AddDropDown("Usage", []string{"transit (encrypt, decrypt, rewrap)", "key_agreement (KMS-JSON derive)", "encrypt_decrypt (KMS faces)", "sign_verify", "generate_verify_mac"}, 0, nil)
	f.AddCheckbox("Offer on the KMS-JSON face", false, nil)
	f.AddCheckbox("Offer on the KMS-gRPC face", false, nil)
	f.AddCheckbox("Offer on the KMS-REST face", false, nil)
	in := func(l string) *tview.InputField { return f.GetFormItemByLabel(l).(*tview.InputField) }
	chk := func(l string) bool { return f.GetFormItemByLabel(l).(*tview.Checkbox).IsChecked() }
	f.AddButton("Create", func() {
		name := in("Key name").GetText()
		_, tok := f.GetFormItemByLabel("Token").(*tview.DropDown).GetCurrentOption()
		tokName := strings.TrimSpace(tok)
		ci, _ := f.GetFormItemByLabel("Context").(*tview.DropDown).GetCurrentOption()
		ui, _ := f.GetFormItemByLabel("Usage").(*tview.DropDown).GetCurrentOption()
		usage := []string{"", "key_agreement", config.UsageEncryptDecrypt, config.UsageSignVerify, config.UsageMAC}[ui]
		spec := store.KeySpec{Token: tokName, AADMode: "fixed", Usage: usage,
			KMSJSON: chk("Offer on the KMS-JSON face"), KMSGRPC: chk("Offer on the KMS-gRPC face"), KMSRest: chk("Offer on the KMS-REST face")}
		if ci == 1 {
			spec.AADMode = "context"
			for _, p := range strings.Split(in("Allowed context prefixes (context only, comma)").GetText(), ",") {
				if p = strings.TrimSpace(p); p != "" {
					spec.Allow = append(spec.Allow, p)
				}
			}
		}
		if soft[tokName] && !chk("Make a new key file (soft token)") {
			a.fail(fmt.Errorf("a soft key needs a key file: leave \"Make a new key file\" on, or set the label by hand in the configuration"))
			return
		}
		res, err := actions.CreateKey(a.doc, actions.NewKey{Name: name, Spec: spec, Dir: a.dir(), Soft: soft[tokName], Owner: a.serviceUser(),
			CKA: strings.TrimSpace(in("Card: CKA_ID of the key pair (hex)").GetText())})
		if err != nil {
			a.fail(err)
			return
		}
		a.closeForm()
		a.show("keys")
		if res.File != "" {
			a.notice("Key created", "The key "+name+" is in the document; its key file is "+res.File+" (mode 0400, public point "+res.Point+"…).\n\nBack the file up: what is sealed under the key cannot be opened without it.\nSave the configuration on Review and save.")
		}
	}).AddButton("Cancel", a.closeForm)
	a.form("Create a key", f, 84, 32)
}

// rotateKey adds a version: new texts are sealed under it, the old ones still open.
func (a *App) rotateKey(name string) {
	if name == "" {
		a.notice("Rotate", "Choose a key in the list first.")
		return
	}
	cfg, err := a.cfg()
	if err != nil {
		a.fail(err)
		return
	}
	k := cfg.Keys[name]
	last := k.Versions[len(k.Versions)-1]
	tok := ""
	isSoft := false
	for _, t := range cfg.Tokens {
		if t.Name == last.Token {
			tok, isSoft = t.Name, t.Type == "soft"
		}
	}
	f := tview.NewForm()
	f.AddTextView("", fmt.Sprintf("Version %d of %q is made on the token %s. New texts are sealed under it; texts sealed under the older versions still open.", len(k.Versions)+1, name, tok), 0, 4, true, false)
	if !isSoft {
		f.AddInputField("CKA_ID of the new key pair (hex)", "", 44, nil, nil)
	}
	f.AddButton("Rotate", func() {
		cka := ""
		if !isSoft {
			cka = strings.TrimSpace(f.GetFormItemByLabel("CKA_ID of the new key pair (hex)").(*tview.InputField).GetText())
		}
		if _, err := actions.Rotate(a.doc, name, a.dir(), a.serviceUser(), cka); err != nil {
			a.fail(err)
			return
		}
		a.closeForm()
		a.show("keys")
		a.notice("Rotated", fmt.Sprintf("%q has %d versions now. Save the configuration, then reload.", name, len(k.Versions)+1))
	}).AddButton("Cancel", a.closeForm)
	a.form("Rotate "+name, f, 72, 14)
}

// deleteKey removes a key from the configuration, with its grants, after the person types its name. Key files that nothing else uses are offered for removal in a second, separate question.
func (a *App) deleteKey(name string) {
	if name == "" {
		a.notice("Delete", "Choose a key in the list first.")
		return
	}
	cfg, err := a.cfg()
	if err != nil {
		a.fail(err)
		return
	}
	k := cfg.Keys[name]
	var users []string
	for _, c := range cfg.Clients {
		if _, ok := c.Keys[name]; ok {
			users = append(users, c.Name)
		}
	}
	warn := fmt.Sprintf("Deleting the key %q.\n\n[red]Everything sealed under it cannot be opened[black] unless the key is put back. Its %d version(s) and the grants of: %s will go from the configuration.", name, len(k.Versions), joinOr(users, "no client"))
	a.typed("Delete key "+name, warn, name, func() {
		del, err := actions.DeleteKey(a.doc, name)
		if err != nil {
			a.fail(err)
			return
		}
		a.show("keys")
		msg := fmt.Sprintf("The key %q is out of the document (grants removed: %s). Save to make it final.", name, joinOr(del.Grants, "none"))
		if len(del.Orphans) == 0 {
			a.notice("Deleted", msg)
			return
		}
		a.ask("Key files", msg+"\n\nThe key material is still on disk:\n  "+strings.Join(del.Orphans, "\n  ")+"\n\nKeep the files (a backup of the key), or overwrite and delete them (cannot be undone)?", []string{"Keep the files", "Delete the files"}, func(i int) {
			if i != 1 {
				return
			}
			if errs := actions.Shred(del.Orphans); len(errs) > 0 {
				var m []string
				for _, e := range errs {
					m = append(m, e.Error())
				}
				a.fail(fmt.Errorf("%s", strings.Join(m, "\n")))
			} else {
				a.notice("Deleted", "The key files were overwritten and removed. On a flash or journalling file system an overwrite is not a guarantee.")
			}
		})
	})
}
