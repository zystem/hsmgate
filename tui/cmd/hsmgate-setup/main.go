// hsmgate-setup is the terminal tool of hsmgate: a menu-driven interface for the configuration (keys, clients, tokens, faces, audit), and a quick setup that goes from nothing to a
// running service. It edits hsmgate.yaml, the one source of truth, and never keeps a copy of its own.
//
//	hsmgate-setup                       the menus
//	hsmgate-setup -first-run            the quick setup when there is no configuration, the menus otherwise (what a package runs after the installation)
//	hsmgate-setup -auto                 the quick setup with the defaults and the flags, with no screen (unattended installations, tests)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/zystem/hsmgate/tui/internal/setup"
	"github.com/zystem/hsmgate/tui/internal/ui"
)

var version = "dev"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr *os.File) int {
	def := setup.Defaults() // as root: the system layout; as a user: the home directory (the flags say "default" and the values are filled in after the parse)
	fs := flag.NewFlagSet("hsmgate-setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "the configuration file (default: /etc/hsmgate/hsmgate.yaml as root, ~/.config/hsmgate/hsmgate.yaml otherwise)")
	sock := fs.String("socket", "", "the admin socket of the running service (default: the one in the configuration)")
	unit := fs.String("unit", "hsmgate", "the systemd unit of the service")
	first := fs.Bool("first-run", false, "start with the quick setup when there is no configuration")
	auto := fs.Bool("auto", false, "the quick setup with no screen: the defaults and these flags (also HSMGATE_SETUP_AUTO=1)")
	ver := fs.Bool("version", false, "print the version")
	// the answers of -auto
	mode := fs.String("mode", "soft", "-auto: soft (keys in files) or card")
	listen := fs.String("listen", "", "-auto: address:port (default: 0.0.0.0:8443 as root, 127.0.0.1:8443 otherwise)")
	names := fs.String("names", "", "-auto: more names or addresses for the certificate of the service, comma separated")
	user := fs.String("user", "", "-auto: the account the service runs as (default: hsmgate, when it exists and this is root)")
	keyName := fs.String("key", "app", "-auto: name of the first key")
	clientName := fs.String("client", "app", "-auto: name of the first client")
	allow := fs.String("context-prefixes", "", "-auto: make the key a context key with these prefixes (comma separated); empty: a fixed key")
	auditFile := fs.String("audit-file", "", "-auto: the audit file (default: /var/log/hsmgate/audit.log as root, in ~/.local/state/hsmgate otherwise; \"none\": the output of the service)")
	auditMB := fs.Int("audit-max-mb", 25, "-auto: rotate the audit file at this size in MB (0: never)")
	enable := fs.Bool("enable", false, "-auto: enable and start the systemd unit (default: yes when this is root and there is systemd; -enable=false: no)")
	module := fs.String("module", "", "-auto, card: the PKCS#11 module (default: the OpenSC one, when it is found)")
	tokenLabel := fs.String("token-label", "", "-auto, card: the label of the token")
	keyID := fs.String("card-key-id", "", "-auto, card: the CKA_ID of the key pair (hex)")
	pinFile := fs.String("pin-file", "", "-auto, card: the file with the PIN, mode 0400 (default: pin in the directory of the configuration)")
	bin := fs.String("bin", "", "the hsmgate program (default: next to this tool, or on the PATH)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if *cfgPath == "" {
		*cfgPath = def.ConfigPath()
	}
	if *ver {
		fmt.Fprintln(stdout, "hsmgate-setup", version)
		return 0
	}
	if os.Getenv("HSMGATE_SETUP_AUTO") == "1" {
		*auto = true
	}

	if *auto {
		a := def
		a.Mode, a.ExtraNames, a.KeyName, a.ClientName, a.AuditMaxMB, a.Bin = *mode, *names, *keyName, *clientName, *auditMB, *bin
		if set["listen"] {
			a.Listen = *listen
		}
		if set["user"] {
			a.User = *user
		}
		if set["audit-file"] {
			a.AuditFile = *auditFile
			if a.AuditFile == "none" {
				a.AuditFile = ""
			}
		}
		if set["enable"] {
			a.Enable = *enable
		}
		if set["module"] {
			a.Module = *module
		}
		if set["pin-file"] {
			a.PinFile = *pinFile
		}
		a.TokenLabel, a.CardKeyID = *tokenLabel, *keyID
		if set["config"] {
			a.Dir = dirOf(*cfgPath)
			if !set["pin-file"] {
				a.PinFile = a.Dir + "/pin"
			}
		}
		if *allow != "" {
			a.ContextMode = true
			for _, p := range strings.Split(*allow, ",") {
				if p = strings.TrimSpace(p); p != "" {
					a.Allow = append(a.Allow, p)
				}
			}
		}
		if a.Exists() {
			fmt.Fprintf(stdout, "%s exists: nothing to do.\n", a.ConfigPath())
			return 0
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		res, err := setup.Apply(ctx, a, func(s string) { fmt.Fprintln(stdout, "  ok:", s) })
		if err != nil {
			fmt.Fprintln(stderr, "hsmgate-setup:", err)
			return 1
		}
		fmt.Fprintln(stdout, "\ndone. Try it:")
		for _, c := range res.TryIt {
			fmt.Fprintln(stdout, "  "+c)
		}
		for _, n := range res.Notes {
			fmt.Fprintln(stdout, "note:", n)
		}
		return 0
	}

	if !isTerminal(os.Stdin) || !isTerminal(os.Stdout) {
		if *first {
			// a package installed on a machine with nobody at the keyboard: say how, and leave quietly
			fmt.Fprintln(stdout, "hsmgate: not configured yet. Run `sudo hsmgate-setup` at a terminal, or `sudo hsmgate-setup -auto` for the defaults.")
			return 0
		}
		fmt.Fprintln(stderr, "hsmgate-setup needs a terminal; for an unattended setup use -auto")
		return 1
	}
	a, err := ui.New(ui.Options{ConfigPath: *cfgPath, Socket: *sock, Unit: *unit, Version: version, FirstRun: *first, Bin: *bin})
	if err != nil {
		fmt.Fprintln(stderr, "hsmgate-setup:", err)
		return 1
	}
	if err := a.Run(); err != nil {
		fmt.Fprintln(stderr, "hsmgate-setup:", err)
		return 1
	}
	return 0
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func dirOf(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "."
	}
	return p[:i]
}
