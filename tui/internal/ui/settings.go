package ui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// settings: the listen address, the audit, the limits and the other faces, in one form. A value left empty (or off, or 0) is removed from the file, so that the default applies and the
// file stays short.
func (a *App) settings() tview.Primitive {
	cfg, err := a.cfg()
	if err != nil {
		tv := tview.NewTextView().SetDynamicColors(true).SetText("[red]The configuration is not valid, so the settings cannot be shown:[black]\n\n" + err.Error() + "\n\nFix it in the other sections or discard the changes (Review and save).")
		return a.page("Settings and faces", tv)
	}
	f := tview.NewForm()
	f.SetButtonBackgroundColor(tcell.ColorNavy).SetFieldBackgroundColor(tcell.ColorNavy).SetFieldTextColor(tcell.ColorWhite)
	f.AddInputField("Listen (restart)", cfg.Listen, 32, nil, nil)
	f.AddInputField("Admin socket (restart)", cfg.AdminSocket, 40, nil, nil)
	f.AddInputField("Audit file (empty: the output of the service) (restart)", cfg.Audit.File, 40, nil, nil)
	f.AddCheckbox("Audit also to the output of the service (restart)", cfg.Audit.Stdout, nil)
	f.AddInputField("Rotate the audit file at MB (0: never) (restart)", strconv.Itoa(cfg.Audit.MaxSizeMB), 8, nil, nil)
	f.AddInputField("Old audit files kept (restart)", strconv.Itoa(cfg.Audit.MaxFiles), 8, nil, nil)
	f.AddInputField("Operations at once on the tokens (0: 8) (restart)", strconv.Itoa(cfg.Limits.MaxConcurrent), 8, nil, nil)
	f.AddInputField("Seconds a request may wait (0: 2) (restart)", strconv.Itoa(cfg.Limits.QueueSeconds), 8, nil, nil)
	f.AddCheckbox("Metrics on the admin socket", cfg.Metrics.Enabled, nil)
	f.AddCheckbox("KMS-JSON face (restart)", cfg.KMSJSON.Enabled, nil)
	f.AddInputField("  KMS-JSON region", cfg.KMSJSON.Region, 16, nil, nil)
	f.AddCheckbox("KMS-gRPC face (restart)", cfg.KMSGRPC.Enabled, nil)
	f.AddInputField("  KMS-gRPC project", cfg.KMSGRPC.Project, 20, nil, nil)
	f.AddInputField("  KMS-gRPC location", cfg.KMSGRPC.Location, 20, nil, nil)
	f.AddInputField("  KMS-gRPC key ring", cfg.KMSGRPC.KeyRing, 20, nil, nil)
	f.AddCheckbox("KMS-REST face (restart)", cfg.KMSRest.Enabled, nil)
	f.AddInputField("  KMS-REST tenant", cfg.KMSRest.Tenant, 20, nil, nil)
	f.AddButton("Apply to the document", func() { a.applySettings(f) })
	f.SetBorder(true).SetTitle(" Settings and faces ")
	f.SetItemPadding(0)
	f.SetCancelFunc(func() { a.app.SetFocus(a.nav) })
	return f
}

func (a *App) applySettings(f *tview.Form) {
	in := func(l string) string { return strings.TrimSpace(f.GetFormItemByLabel(l).(*tview.InputField).GetText()) }
	chk := func(l string) bool { return f.GetFormItemByLabel(l).(*tview.Checkbox).IsChecked() }
	num := func(l string) (int, error) {
		v := in(l)
		if v == "" {
			return 0, nil
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("%q must be a number that is not negative", l)
		}
		return n, nil
	}
	put := func(v any, path ...string) {
		empty := false
		switch x := v.(type) {
		case string:
			empty = x == ""
		case bool:
			empty = !x
		case int:
			empty = x == 0
		}
		if empty {
			a.doc.Unset(path...)
			return
		}
		a.doc.Set(v, path...)
	}
	for l, p := range map[string][]string{
		"Operations at once on the tokens (0: 8) (restart)": {"limits", "max_concurrent"},
		"Seconds a request may wait (0: 2) (restart)":       {"limits", "queue_seconds"},
		"Rotate the audit file at MB (0: never) (restart)":  {"audit", "max_size_mb"},
		"Old audit files kept (restart)":                    {"audit", "max_files"},
	} {
		n, err := num(l)
		if err != nil {
			a.fail(err)
			return
		}
		put(n, p...)
	}
	put(in("Listen (restart)"), "listen")
	put(in("Admin socket (restart)"), "admin_socket")
	put(in("Audit file (empty: the output of the service) (restart)"), "audit", "file")
	put(chk("Audit also to the output of the service (restart)"), "audit", "stdout")
	put(chk("Metrics on the admin socket"), "metrics", "enabled")
	put(chk("KMS-JSON face (restart)"), "kmsjson", "enabled")
	put(in("  KMS-JSON region"), "kmsjson", "region")
	put(chk("KMS-gRPC face (restart)"), "kmsgrpc", "enabled")
	put(in("  KMS-gRPC project"), "kmsgrpc", "project")
	put(in("  KMS-gRPC location"), "kmsgrpc", "location")
	put(in("  KMS-gRPC key ring"), "kmsgrpc", "key_ring")
	put(chk("KMS-REST face (restart)"), "kmsrest", "enabled")
	put(in("  KMS-REST tenant"), "kmsrest", "tenant")
	a.refresh()
	if _, err := a.cfg(); err != nil {
		a.notice("Settings", "[red]Applied to the document, but the service would refuse it:[black]\n"+err.Error()+"\n\nFix the values, or discard on Review and save.")
		return
	}
	a.notice("Settings", "Applied to the document. Review and save writes the file; settings marked (restart) need a restart of the service, the others a reload.")
}
