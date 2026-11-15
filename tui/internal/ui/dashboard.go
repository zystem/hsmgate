package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rivo/tview"

	"github.com/zystem/hsmgate/tui/internal/sys"
)

// dashboard: is the service up, what do its tokens say, is the file good.
func (a *App) dashboard() tview.Primitive {
	tv := tview.NewTextView().SetDynamicColors(true).SetWrap(true)
	var b strings.Builder

	if !a.configExists() && !a.doc.Changed() {
		b.WriteString("[red]There is no configuration yet[black] (" + a.opt.ConfigPath + ").\n\nStart the [::b]quick setup[::-]: a few questions, and you get a running service, a key, a client and its certificate.\n")
	} else {
		cfg, err := a.cfg()
		if err != nil {
			b.WriteString("[red]The configuration is not good:[black]\n  " + err.Error() + "\n\n")
		} else {
			fmt.Fprintf(&b, "[green]The configuration is good.[black]\n  listens on [::b]%s[::-]; %d token(s), %d key(s), %d client(s)\n", cfg.Listen, len(cfg.Tokens), len(cfg.Keys), len(cfg.Clients))
			var faces []string
			if cfg.KMSJSON.Enabled {
				faces = append(faces, "KMS-JSON")
			}
			if cfg.KMSGRPC.Enabled {
				faces = append(faces, "KMS-gRPC")
			}
			if cfg.KMSRest.Enabled {
				faces = append(faces, "KMS-REST")
			}
			fmt.Fprintf(&b, "  faces: Transit%s\n  audit: %s\n\n", func() string {
				if len(faces) == 0 {
					return ""
				}
				return ", " + strings.Join(faces, ", ")
			}(), func() string {
				if cfg.Audit.File == "" {
					return "to the output of the service"
				}
				return cfg.Audit.File
			}())
		}
		b.WriteString(a.serviceLines())
	}
	tv.SetText(b.String())

	row := []*tview.Button{btn("Refresh", func() { a.show("dashboard") })}
	if !a.configExists() && !a.doc.Changed() {
		row = append([]*tview.Button{btn("Quick setup", a.wizard)}, row...)
	} else if sys.HasSystemd() && sys.IsRoot() {
		for _, act := range []string{"start", "stop", "restart", "reload"} {
			act := act
			row = append(row, btn(strings.ToUpper(act[:1])+act[1:], func() { a.service(act) }))
		}
	}
	return a.page("Overview", tv, row...)
}

// serviceLines says what the running service reports.
func (a *App) serviceLines() string {
	var b strings.Builder
	if sys.HasSystemd() {
		ctx, cancel := a.runCtx()
		defer cancel()
		out, _ := sys.Systemctl(ctx, "is-active", a.opt.Unit)
		state := strings.TrimSpace(out)
		colour := "red"
		if state == "active" {
			colour = "green"
		}
		fmt.Fprintf(&b, "service %s: [%s]%s[black]\n", a.opt.Unit, colour, state)
	}
	sock := a.socket()
	if sock == "" {
		b.WriteString("no admin_socket in the configuration: the state of the tokens cannot be asked.\n")
		return b.String()
	}
	st, err := sys.Status(sock)
	switch {
	case err == nil:
		names := make([]string, 0, len(st))
		for n := range st {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			c := "green"
			if st[n] != "ready" {
				c = "red"
			}
			fmt.Fprintf(&b, "token %s: [%s]%s[black]\n", n, c, st[n])
		}
	case sys.ErrNotRunning(err):
		b.WriteString("the service is not running (no answer on " + sock + ")\n")
	default:
		fmt.Fprintf(&b, "the admin socket %s: %v\n", sock, err)
	}
	return b.String()
}

func (a *App) service(act string) {
	ctx, cancel := a.runCtx()
	defer cancel()
	out, err := sys.Systemctl(ctx, act, a.opt.Unit)
	if err != nil {
		a.fail(fmt.Errorf("systemctl %s %s: %v", act, a.opt.Unit, strings.TrimSpace(out+" "+err.Error())))
		return
	}
	a.show("dashboard")
}
