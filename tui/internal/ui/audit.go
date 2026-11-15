package ui

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/rivo/tview"
)

type auditLine struct {
	Time, Client, Face, Key, Op, Context, Result string
}

// readTail reads up to n of the last lines of a file without reading all of a big one.
func readTail(path string, n int) ([]string, error) {
	f, err := os.Open(path) // #nosec G304 -- the audit file named in the configuration
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	const window = 512 << 10
	if st.Size() > window {
		if _, err := f.Seek(st.Size()-window, 0); err != nil {
			return nil, err
		}
	}
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if st.Size() > window && len(lines) > 0 {
		lines = lines[1:] // the first may be cut in the middle
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, sc.Err()
}

func (a *App) auditView() tview.Primitive {
	tv := tview.NewTextView().SetDynamicColors(true).SetScrollable(true)
	cfg, err := a.cfg()
	if err != nil {
		tv.SetText("[red]The configuration is not valid.[black]")
		return a.page("Audit log", tv)
	}
	if cfg.Audit.File == "" {
		tv.SetText("The audit goes to the output of the service, not to a file.\n\nUnder systemd:  journalctl -u hsmgate -o cat\nIn a container: docker logs / kubectl logs\n\nSet an audit file under Settings to read it here.")
		return a.page("Audit log", tv)
	}
	filter := "all"
	render := func() {
		lines, err := readTail(cfg.Audit.File, 400)
		if err != nil {
			tv.SetText("[red]" + tview.Escape(err.Error()) + "[black]")
			return
		}
		var b strings.Builder
		shown := 0
		for _, raw := range lines {
			var l auditLine
			if json.Unmarshal([]byte(raw), &l) != nil {
				continue
			}
			ok := l.Result == "ok" || l.Result == "attempt"
			if (filter == "problems" && ok) || (filter == "ok" && !ok) {
				continue
			}
			c := "green"
			if !ok {
				c = "red"
			}
			t := l.Time
			if len(t) >= 19 {
				t = t[11:19]
			}
			fmt.Fprintf(&b, "%s [%s]%-18s[black] %-10s %-14s %s %s\n", t, c, tview.Escape(l.Result), tview.Escape(l.Client), tview.Escape(l.Op), tview.Escape(l.Key), tview.Escape(l.Context))
			shown++
		}
		if shown == 0 {
			b.WriteString("(no lines" + map[bool]string{true: "", false: " with this filter"}[filter == "all"] + ")")
		}
		tv.SetText(b.String())
		tv.ScrollToEnd()
	}
	render()
	set := func(v string) func() { return func() { filter = v; render() } }
	return a.page("Audit log: the last decisions of "+cfg.Audit.File, tv,
		btn("All", set("all")), btn("Problems", set("problems")), btn("Ok", set("ok")), btn("Refresh", render))
}
