// Package actions holds what the screens do to the configuration and to the key files, without any screen: creating, rotating and deleting a key. The forms call these functions, so that
// what the tests check is what a person gets, and so that a failure half way is undone here, in one place.
package actions

import (
	"fmt"
	"path/filepath"

	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/tui/internal/store"
	"github.com/zystem/hsmgate/tui/internal/sys"
)

// NewKey is what is asked when a key is made.
type NewKey struct {
	Name  string
	Spec  store.KeySpec // Token and AAD, usage and faces; the Label is chosen here
	Dir   string        // soft token: where the key file goes
	CKA   string        // card: the CKA_ID of the key pair (hex)
	Soft  bool          // the token is a soft token: a key file is made
	Owner string        // the account that owns a new key file ("" : whoever runs this)
}

// Result says what was made, for the message the person reads.
type Result struct {
	Label string
	File  string // a new key file ("" for a card)
	Point string // the first digits of the public point of a new soft key
}

// CreateKey adds a key to the document. On a soft token it makes the key file too (mode 0400, never over a file that is there). If anything fails the document and the disk are as they
// were.
func CreateKey(d *store.Doc, k NewKey) (*Result, error) {
	label := k.Name + "-1"
	k.Spec.Label = label
	res := &Result{Label: label}
	if k.Soft {
		res.File = filepath.Join(k.Dir, "soft-"+label+".hex")
		if err := d.SetTokenKey(k.Spec.Token, label, res.File); err != nil {
			return nil, err
		}
	} else {
		if k.CKA == "" {
			return nil, fmt.Errorf("a key on a card needs the CKA_ID of its key pair (hex): `pkcs11-tool --module MODULE -O --type pubkey` lists them. This tool does not make keys on a card")
		}
		if err := d.SetTokenKey(k.Spec.Token, label, k.CKA); err != nil {
			return nil, err
		}
	}
	if err := d.AddKey(k.Name, k.Spec); err != nil {
		_ = d.RemoveTokenKey(k.Spec.Token, label)
		return nil, err
	}
	if k.Soft {
		fp, err := sys.NewSoftKey(res.File, k.Owner)
		if err != nil {
			_, _ = d.RemoveKey(k.Name)
			_ = d.RemoveTokenKey(k.Spec.Token, label)
			return nil, err
		}
		res.Point = fp
	}
	return res, nil
}

// Rotate adds a version to a key: a new label on the token of the latest version, and, on a soft token, a new key file.
func Rotate(d *store.Doc, name, dir, owner, cka string) (*Result, error) {
	cfg, err := d.Config()
	if err != nil {
		return nil, err
	}
	k, ok := cfg.Keys[name]
	if !ok {
		return nil, fmt.Errorf("no key %q", name)
	}
	last := k.Versions[len(k.Versions)-1]
	soft := false
	for _, t := range cfg.Tokens {
		if t.Name == last.Token {
			soft = t.Type == "soft"
		}
	}
	label := fmt.Sprintf("%s-%d", name, len(k.Versions)+1)
	res := &Result{Label: label}
	where := cka
	if soft {
		res.File = filepath.Join(dir, "soft-"+label+".hex")
		where = res.File
	} else if cka == "" {
		return nil, fmt.Errorf("the CKA_ID of the new key pair (hex) is needed")
	}
	if err := d.SetTokenKey(last.Token, label, where); err != nil {
		return nil, err
	}
	if err := d.AddVersion(name, last.Token, label); err != nil {
		_ = d.RemoveTokenKey(last.Token, label)
		return nil, err
	}
	if soft {
		fp, err := sys.NewSoftKey(res.File, owner)
		if err != nil {
			// undo: the version is the last of the key, take it off again by rebuilding the list is not possible through the API, so the caller is told to discard
			return nil, fmt.Errorf("%w (the document has the new version without its file: discard the changes)", err)
		}
		res.Point = fp
	}
	return res, nil
}

// Deleted says what removing a key did.
type Deleted struct {
	Grants  []string // "client/key" grants that went with it
	Orphans []string // key files that no key version uses any more (still on disk)
}

// DeleteKey removes a key and its grants from the document. The key files it used are not touched: those that nothing else uses are returned, to be offered for removal.
func DeleteKey(d *store.Doc, name string) (*Deleted, error) {
	before, err := d.Config()
	if err != nil {
		return nil, err
	}
	files := SoftFiles(before, before.Keys[name])
	gone, err := d.RemoveKey(name)
	if err != nil {
		return nil, err
	}
	after, _ := d.Config()
	return &Deleted{Grants: gone, Orphans: orphans(after, files)}, nil
}

// SoftFiles lists the key files of the versions of a key that are on soft tokens.
func SoftFiles(cfg *config.Config, k config.Key) []string {
	soft := map[string]config.Token{}
	for _, t := range cfg.Tokens {
		if t.Type == "soft" {
			soft[t.Name] = t
		}
	}
	var out []string
	for _, v := range k.Versions {
		if t, ok := soft[v.Token]; ok {
			if f := t.Keys[v.Label]; f != "" {
				out = append(out, f)
			}
		}
	}
	return out
}

func orphans(cfg *config.Config, files []string) []string {
	if cfg == nil {
		return files
	}
	used := map[string]bool{}
	for _, k := range cfg.Keys {
		for _, f := range SoftFiles(cfg, k) {
			used[f] = true
		}
	}
	var out []string
	for _, f := range files {
		if !used[f] {
			out = append(out, f)
		}
	}
	return out
}

// Shred overwrites and removes key files; the errors are collected.
func Shred(files []string) []error {
	var errs []error
	for _, f := range files {
		if err := sys.Shred(f); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}
