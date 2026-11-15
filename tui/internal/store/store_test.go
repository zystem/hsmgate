package store

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/zystem/hsmgate/internal/config"
)

// build makes a small valid configuration with the operations a person uses.
func build(t *testing.T) *Doc {
	t.Helper()
	d := New(filepath.Join(t.TempDir(), "hsmgate.yaml"))
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(d.Set("0.0.0.0:8443", "listen"))
	must(d.Set("/etc/hsmgate/server.pem", "tls", "cert"))
	must(d.Set("/etc/hsmgate/server.key", "tls", "key"))
	must(d.Set("/etc/hsmgate/ca.pem", "tls", "client_ca"))
	must(d.AddSoftToken("soft"))
	must(d.SetTokenKey("soft", "m1", "/etc/hsmgate/soft-m1.hex"))
	must(d.AddKey("app", KeySpec{Token: "soft", Label: "m1", AADMode: "context", Allow: []string{"app/"}}))
	must(d.AddClient("web", config.Identity{CN: "web"}))
	must(d.SetGrant("web", "app", config.Grant{Ops: []string{"encrypt", "decrypt"}, PerMinute: 120}))
	return d
}

func TestBuildsAConfigTheServiceAccepts(t *testing.T) {
	d := build(t)
	c, err := d.Config()
	if err != nil {
		raw, _ := d.Bytes()
		t.Fatalf("%v\n%s", err, raw)
	}
	if len(c.Tokens) != 1 || c.Tokens[0].Keys["m1"] == "" || len(c.Keys["app"].Versions) != 1 || c.Keys["app"].AAD.Mode != "context" || c.Clients[0].Keys["app"].PerMinute != 120 {
		t.Errorf("parsed: %+v", c)
	}
}

// The reason for editing the text and not a database: what the person wrote stays, the comments and the order.
func TestKeepsCommentsAndOrder(t *testing.T) {
	src := `# the door of the dev host
listen: 0.0.0.0:8443   # not on the internet

tls:
  cert: /etc/hsmgate/server.pem
  key: /etc/hsmgate/server.key
  client_ca: /etc/hsmgate/ca.pem

tokens:
  # the software token: files
  - name: soft
    type: soft
    keys: {m1: /etc/hsmgate/soft-m1.hex}
keys:
  app:   # the application's key
    versions: [{token: soft, label: m1}]
    aad: {mode: fixed}
clients:
  - name: web
    identity: {cn: web}
    keys:
      app: {ops: [encrypt]}
`
	p := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(p, []byte(src), 0o600)
	d, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Set(25, "audit", "max_size_mb"); err != nil {
		t.Fatal(err)
	}
	if err := d.Set("/var/log/hsmgate/audit.log", "audit", "file"); err != nil {
		t.Fatal(err)
	}
	out, _ := d.Bytes()
	for _, want := range []string{"# the door of the dev host", "# not on the internet", "# the software token: files", "# the application's key", "max_size_mb: 25"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("lost %q in:\n%s", want, out)
		}
	}
	if strings.Index(string(out), "listen:") > strings.Index(string(out), "tokens:") || strings.Index(string(out), "tokens:") > strings.Index(string(out), "keys:") {
		t.Error("the order of the sections changed")
	}
	if _, err := d.Config(); err != nil {
		t.Errorf("%v\n%s", err, out)
	}
}

func TestRefusesDuplicatesAndBadNames(t *testing.T) {
	d := build(t)
	for what, err := range map[string]error{
		"token twice":       d.AddSoftToken("soft"),
		"key twice":         d.AddKey("app", KeySpec{Token: "soft", Label: "m1"}),
		"client twice":      d.AddClient("web", config.Identity{CN: "web"}),
		"bad key name":      d.AddKey("a b", KeySpec{Token: "soft", Label: "m1"}),
		"slash":             d.AddClient("../x", config.Identity{CN: "x"}),
		"no such token":     d.AddKey("k2", KeySpec{Token: "nope", Label: "m1"}),
		"no identity":       d.AddClient("anon", config.Identity{}),
		"context w/o allow": d.AddKey("k3", KeySpec{Token: "soft", Label: "m1", AADMode: "context"}),
		"grant no ops":      d.SetGrant("web", "app", config.Grant{}),
		"grant no key":      d.SetGrant("web", "nope", config.Grant{Ops: []string{"encrypt"}}),
	} {
		if err == nil {
			t.Errorf("%s was accepted", what)
		}
	}
}

func TestRotationAddsAVersion(t *testing.T) {
	d := build(t)
	if err := d.SetTokenKey("soft", "m2", "/etc/hsmgate/soft-m2.hex"); err != nil {
		t.Fatal(err)
	}
	if err := d.AddVersion("app", "soft", "m2"); err != nil {
		t.Fatal(err)
	}
	c, err := d.Config()
	if err != nil {
		t.Fatal(err)
	}
	if v := c.Keys["app"].Versions; len(v) != 2 || v[1].Label != "m2" {
		t.Errorf("versions: %+v", v)
	}
}

// Taking a key away takes its grants with it, and says which; a token or a label that a key still uses cannot be removed.
func TestRemovalIsCareful(t *testing.T) {
	d := build(t)
	if err := d.RemoveToken("soft"); err == nil || !strings.Contains(err.Error(), "key app v1") {
		t.Errorf("a token in use was removed: %v", err)
	}
	if err := d.RemoveTokenKey("soft", "m1"); err == nil {
		t.Error("a label in use was removed")
	}
	gone, err := d.RemoveKey("app")
	if err != nil || len(gone) != 1 || gone[0] != "web/app" {
		t.Fatalf("gone %v, %v", gone, err)
	}
	if _, err := d.Config(); err != nil {
		t.Errorf("the config after removing a key: %v", err)
	}
	if err := d.RemoveTokenKey("soft", "m1"); err != nil {
		t.Errorf("a label that no key uses was refused: %v", err)
	}
	if err := d.RemoveToken("soft"); err != nil {
		t.Errorf("a token that nothing uses was refused: %v", err)
	}
	if err := d.RemoveClient("web"); err != nil {
		t.Error(err)
	}
	if d.Has("tokens") || d.Has("keys") || d.Has("clients") {
		raw, _ := d.Bytes()
		t.Errorf("emptied sections are left:\n%s", raw)
	}
}

func TestUnsetRemovesAnEmptiedMapping(t *testing.T) {
	d := build(t)
	d.Set(true, "audit", "stdout")
	if !d.Unset("audit", "stdout") || d.Has("audit") {
		t.Error("audit: {} was left")
	}
	if d.Unset("nope", "x") {
		t.Error("removed what is not there")
	}
}

func TestSaveWritesOnlyWhatTheServiceAccepts(t *testing.T) {
	d := build(t)
	d.Set("not-an-address-or-anything", "limits", "max_concurrent") // a string where a number belongs
	if _, err := d.Save(); err == nil {
		t.Fatal("an invalid document was saved")
	}
	if _, err := os.Stat(d.Path); err == nil {
		t.Error("a file was written for an invalid document")
	}
}

func TestSaveIsAtomicBacksUpAndKeepsTheMode(t *testing.T) {
	d := build(t)
	if _, err := d.Save(); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(d.Path)
	if st.Mode().Perm() != 0o640 {
		t.Errorf("a new file is %v, want 0640", st.Mode().Perm())
	}
	os.Chmod(d.Path, 0o600) // the person's choice
	d2, err := Open(d.Path)
	if err != nil {
		t.Fatal(err)
	}
	d2.Set(7, "limits", "queue_seconds")
	diff, _ := d2.DiffToOriginal()
	if !strings.Contains(diff, "\n+   queue_seconds: 7\n") || regexp.MustCompile(`(?m)^- `).MatchString(diff) {
		t.Errorf("diff:\n%s", diff)
	}
	backup, err := d2.Save()
	if err != nil || backup == "" {
		t.Fatalf("backup %q, %v", backup, err)
	}
	if st, _ := os.Stat(d2.Path); st.Mode().Perm() != 0o600 {
		t.Errorf("the mode of the old file was not kept: %v", st.Mode().Perm())
	}
	if old, _ := os.ReadFile(backup); strings.Contains(string(old), "queue_seconds") {
		t.Error("the backup has the new text")
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(d.Path), ".hsmgate.yaml-*"))
	if len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
	if d2.Changed() {
		t.Error("Changed after a Save")
	}
}

func TestOldBackupsArePruned(t *testing.T) {
	d := build(t)
	d.Save()
	for i := 0; i < KeepBackups+4; i++ {
		os.WriteFile(d.Path+".bak-2020010"+string(rune('a'+i%26))+"-000000", []byte("x"), 0o600)
	}
	d.Set(1, "limits", "queue_seconds")
	d.Save()
	all, _ := filepath.Glob(d.Path + ".bak-*")
	if len(all) > KeepBackups {
		t.Errorf("%d backups kept, want at most %d", len(all), KeepBackups)
	}
}

func TestDiffShowsOnlyTheChange(t *testing.T) {
	a := []byte("a: 1\nb: 2\nc: 3\nd: 4\ne: 5\nf: 6\ng: 7\nh: 8\n")
	b := []byte("a: 1\nb: 2\nc: 3\nd: 40\ne: 5\nf: 6\ng: 7\nh: 8\n")
	got := Diff(a, b, "old", "new")
	if !strings.Contains(got, "\n- d: 4\n") || !strings.Contains(got, "\n+ d: 40\n") {
		t.Errorf("diff:\n%s", got)
	}
	if Diff(a, a, "o", "n") != "" {
		t.Error("a difference where there is none")
	}
}

// An example file of the repository opens, is kept as it is, and is a valid configuration.
func TestOpensTheExampleOfTheRepository(t *testing.T) {
	d, err := Open("../../../deploy/hsmgate.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	out, err := d.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	orig, _ := os.ReadFile("../../../deploy/hsmgate.example.yaml")
	for _, line := range strings.Split(string(orig), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") && !strings.Contains(string(out), strings.TrimSpace(line)) {
			t.Errorf("a comment was lost: %q", line)
		}
	}
}

func TestCardTokenAndGrantRemoval(t *testing.T) {
	d := build(t)
	if err := d.AddPKCS11Token("card", PKCS11{Module: "/usr/lib/opensc-pkcs11.so", TokenLabel: "cinim", PinFile: "/etc/hsmgate/pin"}); err != nil {
		t.Fatal(err)
	}
	for what, err := range map[string]error{
		"no module":  d.AddPKCS11Token("c2", PKCS11{TokenLabel: "x"}),
		"no label":   d.AddPKCS11Token("c3", PKCS11{Module: "/m.so"}),
		"card twice": d.AddPKCS11Token("card", PKCS11{Module: "/m.so", TokenLabel: "x"}),
	} {
		if err == nil {
			t.Errorf("%s was accepted", what)
		}
	}
	if err := d.SetTokenKey("card", "k1", "5ded83a1"); err != nil {
		t.Fatal(err)
	}
	c, err := d.Config()
	if err != nil || c.Tokens[1].Module == "" || c.Tokens[1].PinFile != "/etc/hsmgate/pin" || c.Tokens[1].Keys["k1"] != "5ded83a1" {
		t.Fatalf("%v %+v", err, c)
	}
	if err := d.RemoveGrant("web", "app"); err != nil {
		t.Fatal(err)
	}
	if err := d.RemoveGrant("web", "app"); err == nil {
		t.Error("a grant was removed twice")
	}
	if v := d.Value("listen"); v != "0.0.0.0:8443" {
		t.Errorf("Value: %q", v)
	}
	if d.Value("nope", "x") != "" || len(d.Original()) != 0 {
		t.Error("Value or Original for what is not there")
	}
}
