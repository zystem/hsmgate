package actions

import (
	"crypto/ecdh"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/tui/internal/store"
)

func base(t *testing.T) (*store.Doc, string) {
	t.Helper()
	dir := t.TempDir()
	d := store.New(filepath.Join(dir, "hsmgate.yaml"))
	d.Set("0.0.0.0:8443", "listen")
	d.Set(dir+"/server.pem", "tls", "cert")
	d.Set(dir+"/server.key", "tls", "key")
	d.Set(dir+"/ca.pem", "tls", "client_ca")
	if err := d.AddSoftToken("soft"); err != nil {
		t.Fatal(err)
	}
	return d, dir
}

func TestCreateKeyMakesAWorkingKeyFile(t *testing.T) {
	d, dir := base(t)
	r, err := CreateKey(d, NewKey{Name: "orders", Soft: true, Dir: dir, Spec: store.KeySpec{Token: "soft", AADMode: "fixed"}})
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(r.File)
	if err != nil || st.Mode().Perm() != 0o400 {
		t.Fatalf("key file: %v %v", err, st)
	}
	// the file is what the service reads for a soft token (backend.NewSoft: 64 hex digits that are a P-256 scalar), and its public point is what was reported
	raw, _ := os.ReadFile(r.File)
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(b) != 32 {
		t.Fatalf("the key file is not 64 hex digits: %v %q", err, raw)
	}
	k, err := ecdh.P256().NewPrivateKey(b)
	if err != nil {
		t.Fatalf("not a P-256 scalar: %v", err)
	}
	if hex.EncodeToString(k.PublicKey().Bytes())[:16] != r.Point {
		t.Errorf("the reported point %q is not the key's", r.Point)
	}
	if _, err := d.Config(); err != nil {
		t.Errorf("config: %v", err)
	}
	if !strings.HasPrefix(r.Point, "04") {
		t.Errorf("point %q", r.Point)
	}
}

func TestCreateKeyUndoesItselfOnFailure(t *testing.T) {
	d, dir := base(t)
	if _, err := CreateKey(d, NewKey{Name: "dup", Soft: true, Dir: dir, Spec: store.KeySpec{Token: "soft", AADMode: "fixed"}}); err != nil {
		t.Fatal(err)
	}
	before, _ := d.Bytes()
	// the same name again: the key exists, nothing may change, and no second file may be made
	if _, err := CreateKey(d, NewKey{Name: "dup", Soft: true, Dir: dir, Spec: store.KeySpec{Token: "soft", AADMode: "fixed"}}); err == nil {
		t.Fatal("a key was made twice")
	}
	after, _ := d.Bytes()
	if string(before) != string(after) {
		t.Errorf("the document changed after a failure:\n%s\n---\n%s", before, after)
	}
	// a bad context mode (no allowed prefix) fails after the label was set: it must be taken off again
	if _, err := CreateKey(d, NewKey{Name: "ctx", Soft: true, Dir: dir, Spec: store.KeySpec{Token: "soft", AADMode: "context"}}); err == nil {
		t.Fatal("a context key without prefixes was made")
	}
	if _, err := os.Stat(filepath.Join(dir, "soft-ctx-1.hex")); err == nil {
		t.Error("a key file was left for a key that was not made")
	}
	if cfg, _ := d.Config(); cfg != nil {
		if _, ok := cfg.Tokens[0].Keys["ctx-1"]; ok {
			t.Error("the label of a key that was not made is left")
		}
	}
}

func TestCardKeyNeedsItsID(t *testing.T) {
	d, dir := base(t)
	d.AddPKCS11Token("card", store.PKCS11{Module: "/usr/lib/opensc-pkcs11.so", TokenLabel: "cinim"})
	if _, err := CreateKey(d, NewKey{Name: "k", Dir: dir, Spec: store.KeySpec{Token: "card", AADMode: "fixed"}}); err == nil || !strings.Contains(err.Error(), "CKA_ID") {
		t.Errorf("err = %v", err)
	}
	if _, err := CreateKey(d, NewKey{Name: "k", Dir: dir, CKA: "5ded83a1", Spec: store.KeySpec{Token: "card", AADMode: "fixed"}}); err != nil {
		t.Fatal(err)
	}
	if cfg, err := d.Config(); err != nil || cfg.Keys["k"].Versions[0].Token != "card" {
		t.Errorf("%v %+v", err, cfg)
	}
}

func TestRotateAddsAVersionAndAFile(t *testing.T) {
	d, dir := base(t)
	CreateKey(d, NewKey{Name: "orders", Soft: true, Dir: dir, Spec: store.KeySpec{Token: "soft", AADMode: "fixed"}})
	r, err := Rotate(d, "orders", dir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Label != "orders-2" {
		t.Errorf("label %q", r.Label)
	}
	cfg, err := d.Config()
	if err != nil || len(cfg.Keys["orders"].Versions) != 2 {
		t.Fatalf("%v %+v", err, cfg)
	}
	if _, err := os.Stat(r.File); err != nil {
		t.Error("no key file for the new version")
	}
	if _, err := Rotate(d, "nope", dir, "", ""); err == nil {
		t.Error("rotated a key that is not there")
	}
}

func TestDeleteKeyKeepsFilesStillInUse(t *testing.T) {
	d, dir := base(t)
	CreateKey(d, NewKey{Name: "a", Soft: true, Dir: dir, Spec: store.KeySpec{Token: "soft", AADMode: "fixed"}})
	CreateKey(d, NewKey{Name: "b", Soft: true, Dir: dir, Spec: store.KeySpec{Token: "soft", AADMode: "fixed"}})
	// a second key that uses the label of the first
	d.AddKey("a2", store.KeySpec{Token: "soft", Label: "a-1", AADMode: "fixed"})
	d.AddClient("c", config.Identity{CN: "c"})
	d.SetGrant("c", "a", config.Grant{Ops: []string{"encrypt"}})
	del, err := DeleteKey(d, "a")
	if err != nil {
		t.Fatal(err)
	}
	if len(del.Grants) != 1 || del.Grants[0] != "c/a" {
		t.Errorf("grants %v", del.Grants)
	}
	if len(del.Orphans) != 0 {
		t.Errorf("the file of a key still in use is offered for removal: %v", del.Orphans)
	}
	del, err = DeleteKey(d, "b")
	if err != nil || len(del.Orphans) != 1 || !strings.HasSuffix(del.Orphans[0], "soft-b-1.hex") {
		t.Fatalf("%v %+v", err, del)
	}
	if errs := Shred(del.Orphans); len(errs) != 0 {
		t.Fatal(errs)
	}
	if _, err := os.Stat(del.Orphans[0]); err == nil {
		t.Error("the file is still there")
	}
}
