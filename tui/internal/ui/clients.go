package ui

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/rivo/tview"

	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/tui/internal/sys"
)

func (a *App) clients() tview.Primitive {
	t := table("Client", "Recognised by", "Rights")
	var names []string
	if cfg, err := a.cfg(); err == nil {
		for i, c := range cfg.Clients {
			id := c.Identity
			var by string
			switch {
			case id.SHA256 != "":
				by = "certificate " + short(id.SHA256, 16)
			case id.URI != "":
				by = "URI " + id.URI
			default:
				by = "CN " + id.CN
			}
			var rights []string
			keys := make([]string, 0, len(c.Keys))
			for k := range c.Keys {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				rights = append(rights, k+": "+strings.Join(c.Keys[k].Ops, "/"))
			}
			cell(t, i+1, 0, c.Name)
			cell(t, i+1, 1, by)
			cell(t, i+1, 2, joinOr(rights, "none"))
			names = append(names, c.Name)
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
	return a.page("Clients: who may use which key", t,
		btn("Add client", a.addClient),
		btn("Give right", func() { a.giveRight(sel()) }),
		btn("Take right away", func() { a.takeRight(sel()) }),
		btn("Remove", func() { a.removeClient(sel()) }))
}

func (a *App) addClient() {
	f := tview.NewForm()
	f.AddInputField("Client name", "", 28, nil, nil)
	f.AddCheckbox("Make its certificate now", true, nil)
	in := func(l string) string { return f.GetFormItemByLabel(l).(*tview.InputField).GetText() }
	f.AddButton("Add", func() {
		name := in("Client name")
		if err := a.doc.AddClient(name, config.Identity{CN: name}); err != nil {
			a.fail(err)
			return
		}
		mk := f.GetFormItemByLabel("Make its certificate now").(*tview.Checkbox).IsChecked()
		a.closeForm()
		a.show("clients")
		if !mk {
			a.notice("Client added", "The client is recognised by the CN of its certificate: "+name+". Make its certificate with `hsmgate ca client`.")
			return
		}
		a.issueCert(name)
	}).AddButton("Cancel", a.closeForm)
	a.form("Add a client", f, 60, 11)
}

// issueCert makes a client certificate with `hsmgate ca client`, which needs the configuration on disk (it reads where the files go).
func (a *App) issueCert(name string) {
	if !a.configExists() {
		a.notice("Certificate", "Save the configuration first (Review and save): the certificate commands read it from the disk.\nThen make the certificate: hsmgate ca client -config "+a.opt.ConfigPath+" -cn "+name)
		return
	}
	bin, err := a.bin()
	if err != nil {
		a.fail(err)
		return
	}
	ctx, cancel := a.runCtx()
	defer cancel()
	out, err := sys.Run(ctx, bin, "ca", "client", "-config", a.opt.ConfigPath, "-cn", name)
	if err != nil {
		a.fail(fmt.Errorf("%v\n\n(a card-sealed authority asks for the PIN on a terminal: run the command by hand)", err))
		return
	}
	a.notice("Certificate made", strings.TrimSpace(out)+"\n\nGive the files "+filepath.Join(a.dir(), "clients", name+".pem")+", .key and ca.pem to the client.")
}

func (a *App) giveRight(client string) {
	if client == "" {
		a.notice("Give right", "Choose a client in the list first.")
		return
	}
	cfg, err := a.cfg()
	if err != nil {
		a.fail(err)
		return
	}
	var keys []string
	for k := range cfg.Keys {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		a.notice("Give right", "There is no key yet: create one first.")
		return
	}
	f := tview.NewForm()
	f.AddDropDown("Key", keys, 0, nil)
	for _, op := range []string{"encrypt", "decrypt", "rewrap"} {
		f.AddCheckbox(op, true, nil)
	}
	for _, op := range []string{"derive", "sign", "verify", "generate_mac", "verify_mac"} {
		f.AddCheckbox(op+" (KMS faces)", false, nil)
	}
	f.AddInputField("Requests per minute (0: no limit)", "600", 10, nil, nil)
	f.AddInputField("Contexts it may use (context keys; comma)", "", 30, nil, nil)
	f.AddButton("Give", func() {
		_, key := f.GetFormItemByLabel("Key").(*tview.DropDown).GetCurrentOption()
		var ops []string
		for _, op := range []string{"encrypt", "decrypt", "rewrap", "derive", "sign", "verify", "generate_mac", "verify_mac"} {
			label := op
			if op != "encrypt" && op != "decrypt" && op != "rewrap" {
				label += " (KMS faces)"
			}
			if f.GetFormItemByLabel(label).(*tview.Checkbox).IsChecked() {
				ops = append(ops, op)
			}
		}
		pm, _ := strconv.Atoi(strings.TrimSpace(f.GetFormItemByLabel("Requests per minute (0: no limit)").(*tview.InputField).GetText()))
		var ctxs []string
		for _, c := range strings.Split(f.GetFormItemByLabel("Contexts it may use (context keys; comma)").(*tview.InputField).GetText(), ",") {
			if c = strings.TrimSpace(c); c != "" {
				ctxs = append(ctxs, c)
			}
		}
		if err := a.doc.SetGrant(client, key, config.Grant{Ops: ops, PerMinute: pm, Contexts: ctxs}); err != nil {
			a.fail(err)
			return
		}
		a.closeForm()
		a.show("clients")
	}).AddButton("Cancel", a.closeForm)
	a.form("Rights of "+client, f, 70, 26)
}

func (a *App) takeRight(client string) {
	if client == "" {
		a.notice("Take right away", "Choose a client in the list first.")
		return
	}
	cfg, err := a.cfg()
	if err != nil {
		a.fail(err)
		return
	}
	var keys []string
	for _, c := range cfg.Clients {
		if c.Name == client {
			for k := range c.Keys {
				keys = append(keys, k)
			}
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		a.notice("Take right away", client+" has no rights.")
		return
	}
	f := tview.NewForm().AddDropDown("Key", keys, 0, nil)
	f.AddButton("Take away", func() {
		_, key := f.GetFormItemByLabel("Key").(*tview.DropDown).GetCurrentOption()
		if err := a.doc.RemoveGrant(client, key); err != nil {
			a.fail(err)
			return
		}
		a.closeForm()
		a.show("clients")
	}).AddButton("Cancel", a.closeForm)
	a.form("Take a right away from "+client, f, 56, 9)
}

func (a *App) removeClient(name string) {
	if name == "" {
		a.notice("Remove", "Choose a client in the list first.")
		return
	}
	a.typed("Remove client "+name, "The client is no longer known. Its certificate is not revoked (there is no revocation list); it simply stops being accepted. Keys and what was sealed are not touched.", name, func() {
		if err := a.doc.RemoveClient(name); err != nil {
			a.fail(err)
			return
		}
		a.show("clients")
	})
}
