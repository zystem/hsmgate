// Package setup is the quick setup: from a few answers to a running hsmgate with a first key, a first client and a certificate for it. It has no screen of its own: the wizard of the
// terminal tool and the headless run (`hsmgate-setup -auto`, used by packages and tests) both call it, so that what a person sees is what an installation does.
package setup

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/tui/internal/store"
	"github.com/zystem/hsmgate/tui/internal/sys"
)

// Mode says where the private keys live.
const (
	ModeSoft = "soft" // files: tests, development, a pilot
	ModeCard = "card" // a smart card or an HSM through a PKCS#11 module
)

// Answers is everything the quick setup asks.
type Answers struct {
	Mode string

	Dir         string // the directory of the configuration, the certificates and the key files
	Listen      string // address:port the service listens on
	ExtraNames  string // more names or addresses for the server certificate, comma separated (the machine's own are guessed)
	User        string // the account the service runs as; it owns the secrets (empty: none is changed)
	AdminSocket string

	// card only
	Module, TokenLabel, TokenSerial, PinFile, CardKeyID string

	KeyName     string   // the first key
	ContextMode bool     // false: "fixed" (no context: what OpenBao's seal and similar clients need); true: the context of a request is the additional data
	Allow       []string // context mode: the prefixes
	ClientName  string   // the first client; its certificate is made

	AuditFile   string // "" : the audit goes to the output of the service
	AuditStdout bool   // with a file: also to the output
	AuditMaxMB  int    // rotate the file at this size (0: never)
	AuditFiles  int

	Enable bool // enable and start the systemd unit (when there is systemd and this is root)

	Bin string // the hsmgate program; found when empty
}

// Defaults are the answers for a machine where a person is at the keyboard: the system layout when this is root, the home of the user otherwise.
func Defaults() Answers {
	a := Answers{
		Mode: ModeSoft, Listen: "0.0.0.0:8443", KeyName: "app", ClientName: "app",
		AuditStdout: false, AuditMaxMB: 25, AuditFiles: 5,
	}
	if sys.IsRoot() {
		a.Dir = "/etc/hsmgate"
		a.AuditFile = "/var/log/hsmgate/audit.log"
		a.AdminSocket = "/run/hsmgate/admin.sock"
		if sys.UserExists("hsmgate") {
			a.User = "hsmgate"
		}
		a.Enable = sys.HasSystemd()
		a.Module = firstExisting(
			"/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so", "/usr/lib64/opensc-pkcs11.so", "/usr/lib/opensc-pkcs11.so", "/usr/lib/pkcs11/opensc-pkcs11.so")
		a.PinFile = "/etc/hsmgate/pin"
		return a
	}
	// a person without root: everything in the home, on the loopback, no unit
	home, _ := os.UserHomeDir()
	cfg := os.Getenv("XDG_CONFIG_HOME")
	if cfg == "" {
		cfg = filepath.Join(home, ".config")
	}
	state := os.Getenv("XDG_STATE_HOME")
	if state == "" {
		state = filepath.Join(home, ".local", "state")
	}
	a.Dir = filepath.Join(cfg, "hsmgate")
	a.Listen = "127.0.0.1:8443"
	a.AuditFile = filepath.Join(state, "hsmgate", "audit.log")
	a.AdminSocket = filepath.Join(a.Dir, "admin.sock")
	a.PinFile = filepath.Join(a.Dir, "pin")
	return a
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// ConfigPath is where the configuration is written.
func (a Answers) ConfigPath() string { return filepath.Join(a.Dir, "hsmgate.yaml") }

// Validate says what is wrong with the answers, in words for a person; the first problem only.
func (a Answers) Validate() error {
	if a.Mode != ModeSoft && a.Mode != ModeCard {
		return fmt.Errorf("the keys are in files (%s) or on a card (%s)", ModeSoft, ModeCard)
	}
	if a.Dir == "" || !filepath.IsAbs(a.Dir) {
		return fmt.Errorf("the directory must be an absolute path")
	}
	host, port, err := net.SplitHostPort(a.Listen)
	if err != nil || port == "" {
		return fmt.Errorf("listen: write it as address:port, for example 0.0.0.0:8443 (%v)", err)
	}
	_ = host
	for what, n := range map[string]string{"key": a.KeyName, "client": a.ClientName} {
		if !store.ValidName(n) {
			return fmt.Errorf("the %s name %q: use letters, digits, dot, dash and underscore, starting with a letter or a digit", what, n)
		}
	}
	if a.ContextMode && len(a.Allow) == 0 {
		return fmt.Errorf("with a context the key needs at least one allowed prefix, for example app/")
	}
	if a.Mode == ModeCard {
		if a.Module == "" || (a.TokenLabel == "" && a.TokenSerial == "") || a.CardKeyID == "" {
			return fmt.Errorf("a card needs the PKCS#11 module, the label (or serial) of the token and the CKA_ID of the key pair (hex)")
		}
	}
	if a.AuditMaxMB < 0 || a.AuditFiles < 0 || ((a.AuditMaxMB > 0) && a.AuditFile == "") {
		return fmt.Errorf("rotation needs an audit file and sizes that are not negative")
	}
	if a.AuditFile != "" && !filepath.IsAbs(a.AuditFile) {
		return fmt.Errorf("the audit file must be an absolute path")
	}
	return nil
}

// Step is one thing the setup does, in words, for the screen that asks "go on?" and for the log.
type Step string

// Plan lists what Apply will do, so that a person can read it first.
func (a Answers) Plan() []Step {
	var s []Step
	s = append(s, Step("write "+a.ConfigPath()+" (a backup of an old one is kept)"))
	if a.Mode == ModeSoft {
		s = append(s, Step("make the key file "+filepath.Join(a.Dir, "soft-"+a.KeyName+"-1.hex")+" (mode 0400: whoever reads it has the key)"))
	} else {
		s = append(s, Step(fmt.Sprintf("use the key pair %s of the token %s on %s (no key is made on the card)", a.CardKeyID, firstNonEmpty(a.TokenLabel, a.TokenSerial), a.Module)))
	}
	s = append(s, Step("make the authority of the certificates in "+filepath.Join(a.Dir, "ca")+", the certificate of the service and the certificate of the client "+a.ClientName))
	if a.AuditFile != "" {
		s = append(s, Step("write the audit to "+a.AuditFile+rotation(a)))
	} else {
		s = append(s, Step("send the audit to the output of the service"))
	}
	if a.Enable {
		s = append(s, Step("enable and start the service (systemctl enable --now hsmgate)"))
	}
	return s
}

func rotation(a Answers) string {
	if a.AuditMaxMB > 0 {
		return fmt.Sprintf(", rotated at %d MB, %d old files kept", a.AuditMaxMB, a.AuditFiles)
	}
	return ", never rotated"
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

// Result is what a finished setup tells the person.
type Result struct {
	ConfigPath  string
	ClientFiles []string
	Started     bool
	TryIt       []string // commands that work now
	Notes       []string
}

// Exists says whether a configuration is already there: the quick setup is for the first one, and never writes over it.
func (a Answers) Exists() bool {
	_, err := os.Stat(a.ConfigPath())
	return err == nil
}

// Apply does the setup. log gets one line per step. It stops at the first failure and says which files exist by then, because a half made setup is worse than none: it refuses to run again over
// an existing configuration, so the person removes what the message names and starts again.
func Apply(ctx context.Context, a Answers, log func(string)) (*Result, error) {
	if log == nil {
		log = func(string) {}
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	if a.Exists() {
		return nil, fmt.Errorf("%s exists: the quick setup makes the first configuration and does not write over one; use the menus to change it", a.ConfigPath())
	}
	bin := a.Bin
	if bin == "" {
		b, err := sys.Binary()
		if err != nil {
			return nil, err
		}
		bin = b
	}
	if err := os.MkdirAll(a.Dir, 0o750); err != nil {
		return nil, err
	}
	sys.Chown(a.Dir, a.User)
	d := store.New(a.ConfigPath())
	steps := []error{
		d.Set(a.Listen, "listen"),
		d.Set(filepath.Join(a.Dir, "server.pem"), "tls", "cert"),
		d.Set(filepath.Join(a.Dir, "server.key"), "tls", "key"),
		d.Set(filepath.Join(a.Dir, "ca.pem"), "tls", "client_ca"),
	}
	if a.AdminSocket != "" {
		steps = append(steps, d.Set(a.AdminSocket, "admin_socket"))
	}
	if a.AuditFile != "" {
		steps = append(steps, d.Set(a.AuditFile, "audit", "file"))
		if a.AuditStdout {
			steps = append(steps, d.Set(true, "audit", "stdout"))
		}
		if a.AuditMaxMB > 0 {
			steps = append(steps, d.Set(a.AuditMaxMB, "audit", "max_size_mb"))
			if a.AuditFiles > 0 {
				steps = append(steps, d.Set(a.AuditFiles, "audit", "max_files"))
			}
		}
	}
	for _, err := range steps {
		if err != nil {
			return nil, err
		}
	}

	tokenName, label := "soft", a.KeyName+"-1"
	var keyFile string
	if a.Mode == ModeSoft {
		if err := d.AddSoftToken(tokenName); err != nil {
			return nil, err
		}
		keyFile = filepath.Join(a.Dir, "soft-"+label+".hex")
		if err := d.SetTokenKey(tokenName, label, keyFile); err != nil {
			return nil, err
		}
	} else {
		tokenName = "card"
		label = a.KeyName + "-1"
		if err := d.AddPKCS11Token(tokenName, store.PKCS11{Module: a.Module, TokenLabel: a.TokenLabel, TokenSerial: a.TokenSerial, PinFile: a.PinFile}); err != nil {
			return nil, err
		}
		if err := d.SetTokenKey(tokenName, label, a.CardKeyID); err != nil {
			return nil, err
		}
	}
	spec := store.KeySpec{Token: tokenName, Label: label, AADMode: "fixed"}
	if a.ContextMode {
		spec.AADMode, spec.Allow = "context", a.Allow
	}
	if err := d.AddKey(a.KeyName, spec); err != nil {
		return nil, err
	}
	if err := d.AddClient(a.ClientName, config.Identity{CN: a.ClientName}); err != nil {
		return nil, err
	}
	if err := d.SetGrant(a.ClientName, a.KeyName, config.Grant{Ops: []string{"encrypt", "decrypt", "rewrap"}, PerMinute: 600}); err != nil {
		return nil, err
	}
	// the audit directory and the unit's runtime directory are made by the package and the unit; with no unit the directory of the audit file is made here
	if a.AuditFile != "" {
		if err := os.MkdirAll(filepath.Dir(a.AuditFile), 0o750); err != nil {
			return nil, err
		}
		sys.Chown(filepath.Dir(a.AuditFile), a.User)
	}
	if a.AdminSocket != "" {
		if err := os.MkdirAll(filepath.Dir(a.AdminSocket), 0o750); err != nil {
			return nil, err
		}
		sys.Chown(filepath.Dir(a.AdminSocket), a.User)
	}

	if a.Mode == ModeSoft {
		fp, err := sys.NewSoftKey(keyFile, a.User)
		if err != nil {
			return nil, err
		}
		log("made the key file " + keyFile + " (public point " + fp + "…)")
	}
	if _, err := d.Save(); err != nil {
		return nil, err
	}
	sys.ChownGroup(a.ConfigPath(), a.User) // root's file, read by the service through its group (mode 0640)
	log("wrote " + a.ConfigPath())

	args := []string{"ca", "setup", "-config", a.ConfigPath(), "-client", a.ClientName}
	if a.ExtraNames != "" {
		for _, n := range strings.Split(a.ExtraNames, ",") {
			n = strings.TrimSpace(n)
			if n == "" {
				continue
			}
			if net.ParseIP(n) != nil {
				args = append(args, "-ip", n)
			} else {
				args = append(args, "-dns", n)
			}
		}
	}
	if a.User != "" {
		args = append(args, "-owner", a.User)
	}
	if _, err := sys.Run(ctx, bin, args...); err != nil {
		return nil, fmt.Errorf("the certificates were not made (the configuration and the key file are written: remove %s and %s to start again): %w", a.ConfigPath(), keyFile, err)
	}
	log("made the authority, the certificate of the service and the certificate of " + a.ClientName)

	if a.Mode == ModeSoft {
		if _, err := sys.RunAs(ctx, a.User, bin, "check", "-config", a.ConfigPath()); err != nil {
			return nil, fmt.Errorf("hsmgate check does not accept what was written: %w", err)
		}
		log("hsmgate check: the configuration is good")
	}

	res := &Result{ConfigPath: a.ConfigPath()}
	cl := filepath.Join(a.Dir, "clients")
	res.ClientFiles = []string{filepath.Join(cl, a.ClientName+".pem"), filepath.Join(cl, a.ClientName+".key"), filepath.Join(cl, "ca.pem")}
	if a.Enable && sys.IsRoot() && sys.HasSystemd() {
		if out, err := sys.Systemctl(ctx, "enable", "--now", "hsmgate"); err != nil {
			res.Notes = append(res.Notes, "the service did not start: "+strings.TrimSpace(out)+" (see: journalctl -u hsmgate)")
		} else {
			res.Started = true
			log("enabled and started the service")
		}
	}
	if a.Mode == ModeCard && !res.Started {
		if a.PinFile == "" {
			res.Notes = append(res.Notes, "the card is locked until it gets its PIN: hsmgate unlock -config "+a.ConfigPath()+" -token card (or give pin_file and start the service)")
		} else {
			res.Notes = append(res.Notes, "the service reads the PIN from "+a.PinFile+" when it starts (the file must be owned by the account the service runs as, mode 0400)")
		}
	}
	if !res.Started {
		res.Notes = append(res.Notes, "start it: hsmgate serve -config "+a.ConfigPath())
	}
	host := hostOf(a.Listen)
	ctxFlag := ""
	if a.ContextMode {
		ctxFlag = " -context " + strings.TrimSuffix(a.Allow[0], "|") + "x"
	}
	res.TryIt = []string{
		fmt.Sprintf("export HSMGATE_ADDR=https://%s HSMGATE_CA=%s HSMGATE_CERT=%s HSMGATE_KEYFILE=%s HSMGATE_TRANSIT_KEY=%s", host, res.ClientFiles[2], res.ClientFiles[0], res.ClientFiles[1], a.KeyName),
		"echo 'my secret' | hsmgate encrypt" + ctxFlag + " > sealed.txt",
		"hsmgate decrypt" + ctxFlag + " < sealed.txt",
	}
	return res, nil
}

func hostOf(listen string) string {
	h, p, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	if h == "" || h == "0.0.0.0" || h == "::" || h == "[::]" {
		h = "localhost"
		if n, err := os.Hostname(); err == nil && n != "" {
			h = n
		}
	}
	return net.JoinHostPort(h, p)
}
