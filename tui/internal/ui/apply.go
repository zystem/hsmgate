package ui

import (
	"strings"

	"github.com/rivo/tview"

	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/tui/internal/store"
	"github.com/zystem/hsmgate/tui/internal/sys"
)

// restartNeeded says which of the changes a reload (SIGHUP) does not take: the service must be restarted for them.
func restartNeeded(old, cur *config.Config) []string {
	if old == nil || cur == nil {
		return nil
	}
	var r []string
	add := func(cond bool, what string) {
		if cond {
			r = append(r, what)
		}
	}
	add(old.Listen != cur.Listen, "listen")
	add(old.AdminSocket != cur.AdminSocket, "admin_socket")
	add(old.Audit != cur.Audit, "audit.*")
	add(old.Limits != cur.Limits, "limits")
	add(old.Transit.Mount != cur.Transit.Mount, "transit.mount")
	add(old.KMSJSON.Enabled != cur.KMSJSON.Enabled, "kmsjson.enabled")
	add(old.KMSGRPC.Enabled != cur.KMSGRPC.Enabled || old.KMSGRPC.TokenPath != cur.KMSGRPC.TokenPath, "kmsgrpc.enabled/token_path")
	add(old.KMSRest.Enabled != cur.KMSRest.Enabled || old.KMSRest.Tenant != cur.KMSRest.Tenant, "kmsrest.enabled/tenant")
	return r
}

// apply: what would be written, whether the service would accept it, and the buttons that write it.
func (a *App) apply() tview.Primitive {
	tv := tview.NewTextView().SetDynamicColors(true).SetScrollable(true)
	diff, err := a.doc.DiffToOriginal()
	var b strings.Builder
	if _, cerr := a.cfg(); cerr != nil {
		b.WriteString("[red]The service would refuse this file:[black]\n  " + cerr.Error() + "\n\n")
	} else {
		b.WriteString("[green]The service accepts this file.[black]\n\n")
	}
	switch {
	case err != nil:
		b.WriteString("[red]" + err.Error() + "[black]\n")
	case diff == "":
		b.WriteString("No changes: the file on disk is what you see in the other sections.\n")
	default:
		for _, l := range strings.Split(strings.TrimRight(diff, "\n"), "\n") {
			switch {
			case strings.HasPrefix(l, "+++"), strings.HasPrefix(l, "---"), l == "@@":
				b.WriteString("[blue]" + tview.Escape(l) + "[black]\n")
			case strings.HasPrefix(l, "+ "):
				b.WriteString("[green]" + tview.Escape(l) + "[black]\n")
			case strings.HasPrefix(l, "- "):
				b.WriteString("[red]" + tview.Escape(l) + "[black]\n")
			default:
				b.WriteString(tview.Escape(l) + "\n")
			}
		}
	}
	tv.SetText(b.String())
	return a.page("Review and save", tv,
		btn("Save", func() { a.save(false) }),
		btn("Save and reload", func() { a.save(true) }),
		btn("Discard changes", a.discard))
}

func (a *App) discard() {
	if !a.doc.Changed() {
		a.notice("Discard", "There is nothing to discard.")
		return
	}
	a.ask("Discard", "Throw away every change since the file was read?", []string{"Keep them", "Discard"}, func(i int) {
		if i != 1 {
			return
		}
		d, err := store.Open(a.opt.ConfigPath)
		if err != nil {
			a.fail(err)
			return
		}
		a.doc = d
		a.show("apply")
	})
}

func (a *App) save(reload bool) {
	var old *config.Config
	if o, err := store.Open(a.opt.ConfigPath); err == nil {
		old, _ = o.Config()
	}
	backup, err := a.doc.Save()
	if err != nil {
		a.fail(err)
		return
	}
	msg := "Saved " + a.opt.ConfigPath + "."
	if backup != "" {
		msg += "\nThe old file is kept as " + backup + "."
	}
	cur, _ := a.cfg()
	if need := restartNeeded(old, cur); len(need) > 0 {
		msg += "\n\n[red]A restart is needed[black] for: " + strings.Join(need, ", ") + ". A reload does not take these."
		reload = false
	}
	if reload {
		if err := sys.ReloadService(contextBackground(), a.opt.Unit); err != nil {
			msg += "\n\nThe file is saved, but the reload did not work:\n" + err.Error()
		} else {
			msg += "\n\nThe service was told to read it again (SIGHUP): keys, clients and certificates are new now."
		}
	} else {
		msg += "\n\nThe running service has not read it yet: use Reload on the Overview page (or restart it)."
	}
	a.show("apply")
	a.notice("Saved", msg)
}
