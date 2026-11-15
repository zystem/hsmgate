package store

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/zystem/hsmgate/internal/config"
)

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ValidName says whether s may be the name of a token, a key or a client (the service takes more, but a name that is safe in a file name, a URL and a shell is what a person
// should be offered).
func ValidName(s string) bool { return nameRE.MatchString(s) }

func checkName(what, s string) error {
	if !ValidName(s) {
		return fmt.Errorf("%s %q: use letters, digits, dot, dash and underscore, at most 128, starting with a letter or a digit", what, s)
	}
	return nil
}

// ---- tokens ------------------------------------------------------------------------------------------------------------------------------------------

func (d *Doc) token(name string) *yaml.Node {
	it, _ := find(get(d.root, "tokens"), name)
	return it
}

// AddSoftToken adds a token that keeps its private keys in files (tests, development, a pilot).
func (d *Doc) AddSoftToken(name string) error {
	if err := checkName("token", name); err != nil {
		return err
	}
	if d.token(name) != nil {
		return fmt.Errorf("a token %q is there already", name)
	}
	t := newMap("name", name, "type", "soft")
	set(t, "keys", flow(&yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}))
	sequence(d.root, "tokens").Content = append(sequence(d.root, "tokens").Content, t)
	return nil
}

// PKCS11 describes a token on a card or an HSM.
type PKCS11 struct {
	Module, TokenLabel, TokenSerial, PinFile string
}

// AddPKCS11Token adds a token that is reached through a PKCS#11 module.
func (d *Doc) AddPKCS11Token(name string, p PKCS11) error {
	if err := checkName("token", name); err != nil {
		return err
	}
	if d.token(name) != nil {
		return fmt.Errorf("a token %q is there already", name)
	}
	if plain(p.Module) == "" {
		return fmt.Errorf("the PKCS#11 module is needed (for example /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so)")
	}
	if plain(p.TokenLabel) == "" && plain(p.TokenSerial) == "" {
		return fmt.Errorf("name the token by its label or its serial number")
	}
	t := newMap("name", name, "type", "pkcs11", "module", p.Module)
	if p.TokenLabel != "" {
		set(t, "token_label", scalar(p.TokenLabel))
	}
	if p.TokenSerial != "" {
		set(t, "token_serial", scalar(p.TokenSerial))
	}
	if p.PinFile != "" {
		set(t, "pin_file", scalar(p.PinFile))
	}
	set(t, "keys", flow(&yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}))
	seq := sequence(d.root, "tokens")
	seq.Content = append(seq.Content, t)
	return nil
}

// SetTokenKey says where the key with this label is: a file with 64 hex digits for a soft token, the CKA_ID (hex) of the key pair for a card.
func (d *Doc) SetTokenKey(token, label, where string) error {
	if err := checkName("label", label); err != nil {
		return err
	}
	t := d.token(token)
	if t == nil {
		return fmt.Errorf("no token %q", token)
	}
	keys := mapping(t, "keys")
	keys.Style &^= yaml.FlowStyle
	set(keys, label, scalar(where))
	return nil
}

// RemoveTokenKey forgets a label of a token. It refuses while a key version uses it.
func (d *Doc) RemoveTokenKey(token, label string) error {
	if users := d.versionsUsing(token, label); len(users) > 0 {
		return fmt.Errorf("the label %s/%s is used by %s", token, label, strings.Join(users, ", "))
	}
	t := d.token(token)
	if t == nil || !del(get(t, "keys"), label) {
		return fmt.Errorf("no label %s/%s", token, label)
	}
	return nil
}

// RemoveToken removes a token. It refuses while a key version or a spare uses it.
func (d *Doc) RemoveToken(name string) error {
	users := d.versionsUsing(name, "")
	if len(users) > 0 {
		return fmt.Errorf("the token %q is used by %s", name, strings.Join(users, ", "))
	}
	seq := get(d.root, "tokens")
	_, i := find(seq, name)
	if i < 0 {
		return fmt.Errorf("no token %q", name)
	}
	seq.Content = append(seq.Content[:i], seq.Content[i+1:]...)
	if len(seq.Content) == 0 {
		del(d.root, "tokens")
	}
	return nil
}

// versionsUsing lists "key vN" for every version that holds a key of the token (a given label, or any when label is empty), as primary or as a spare.
func (d *Doc) versionsUsing(token, label string) []string {
	var out []string
	keys := get(d.root, "keys")
	if keys == nil {
		return nil
	}
	for i := 0; i+1 < len(keys.Content); i += 2 {
		name := keys.Content[i].Value
		for vi, v := range func() []*yaml.Node {
			if s := get(keys.Content[i+1], "versions"); s != nil {
				return s.Content
			}
			return nil
		}() {
			holders := []*yaml.Node{v}
			if r := get(v, "replicas"); r != nil {
				holders = append(holders, r.Content...)
			}
			for _, h := range holders {
				t, l := get(h, "token"), get(h, "label")
				if t != nil && t.Value == token && (label == "" || (l != nil && l.Value == label)) {
					out = append(out, fmt.Sprintf("key %s v%d", name, vi+1))
					break
				}
			}
		}
	}
	return out
}

// ---- keys --------------------------------------------------------------------------------------------------------------------------------------------

// KeySpec is what a person chooses when making a key.
type KeySpec struct {
	Token, Label string   // the first version: a label of a token
	AADMode      string   // "fixed" (no context; what OpenBao's seal needs) or "context"
	Allow        []string // context mode: the prefixes a context may begin with
	Fixed        string   // fixed mode: the constant, empty for the default
	MaxBytes     int      // 0: the default
	Usage        string   // the KMS-JSON usage: "" or key_agreement, encrypt_decrypt, sign_verify, generate_verify_mac
	KMSJSON      bool
	KMSGRPC      bool
	KMSRest      bool
}

// AddKey adds a key with its first version.
func (d *Doc) AddKey(name string, s KeySpec) error {
	if err := checkName("key", name); err != nil {
		return err
	}
	if d.Has("keys", name) {
		return fmt.Errorf("a key %q is there already", name)
	}
	if d.token(s.Token) == nil {
		return fmt.Errorf("no token %q: add the token first", s.Token)
	}
	if s.Label == "" {
		return fmt.Errorf("the first version needs the label of a key of the token")
	}
	k := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	vs := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{flow(newMap("token", s.Token, "label", s.Label))}}
	set(k, "versions", vs)
	switch s.AADMode {
	case "", "fixed":
		a := newMap("mode", "fixed")
		if s.Fixed != "" {
			set(a, "fixed", scalar(s.Fixed))
		}
		set(k, "aad", flow(a))
	case "context":
		if len(s.Allow) == 0 {
			return fmt.Errorf("a key in context mode needs at least one allowed prefix (for example app/)")
		}
		a := newMap("mode", "context")
		set(a, "allow", flow(scalar(s.Allow)))
		set(k, "aad", flow(a))
	default:
		return fmt.Errorf("the mode is fixed or context")
	}
	if s.MaxBytes > 0 {
		set(k, "max_bytes", scalar(s.MaxBytes))
	}
	if s.KMSJSON {
		set(k, "kmsjson", scalar(true))
	}
	if s.KMSGRPC {
		set(k, "kmsgrpc", scalar(true))
	}
	if s.KMSRest {
		set(k, "kmsrest", scalar(true))
	}
	if s.Usage != "" && s.Usage != config.UsageKeyAgreement {
		set(k, "kmsjson_usage", scalar(s.Usage))
	}
	set(mapping(d.root, "keys"), name, k)
	return nil
}

// AddVersion adds a version (a rotation): the new one becomes the latest. Texts sealed under the older ones stay readable.
func (d *Doc) AddVersion(key, token, label string) error {
	k := get(get(d.root, "keys"), key)
	if k == nil {
		return fmt.Errorf("no key %q", key)
	}
	if d.token(token) == nil {
		return fmt.Errorf("no token %q", token)
	}
	vs := sequence(k, "versions")
	vs.Content = append(vs.Content, flow(newMap("token", token, "label", label)))
	return nil
}

// RemoveKey removes a key and the grants that name it. What clients sealed under the key cannot be opened afterwards unless the key is put back: the caller must have asked.
// It returns the grants that were removed as "client/key".
func (d *Doc) RemoveKey(name string) ([]string, error) {
	keys := get(d.root, "keys")
	if !del(keys, name) {
		return nil, fmt.Errorf("no key %q", name)
	}
	if len(keys.Content) == 0 {
		del(d.root, "keys")
	}
	var gone []string
	for _, c := range func() []*yaml.Node {
		if s := get(d.root, "clients"); s != nil {
			return s.Content
		}
		return nil
	}() {
		if g := get(c, "keys"); g != nil && del(g, name) {
			gone = append(gone, get(c, "name").Value+"/"+name)
		}
	}
	sort.Strings(gone)
	return gone, nil
}

// ---- clients -----------------------------------------------------------------------------------------------------------------------------------------

func (d *Doc) client(name string) *yaml.Node {
	it, _ := find(get(d.root, "clients"), name)
	return it
}

// AddClient adds a client known by its certificate: its CN, the SHA-256 of the certificate (stronger) or a URI.
func (d *Doc) AddClient(name string, id config.Identity) error {
	if err := checkName("client", name); err != nil {
		return err
	}
	if d.client(name) != nil {
		return fmt.Errorf("a client %q is there already", name)
	}
	if id.CN == "" && id.SHA256 == "" && id.URI == "" {
		return fmt.Errorf("say how the client is recognised: its CN, the SHA-256 of its certificate or a URI")
	}
	idn := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	if id.URI != "" {
		set(idn, "uri", scalar(id.URI))
	}
	if id.SHA256 != "" {
		set(idn, "sha256", scalar(id.SHA256))
	}
	if id.CN != "" {
		set(idn, "cn", scalar(id.CN))
	}
	c := newMap("name", name)
	set(c, "identity", flow(idn))
	seq := sequence(d.root, "clients")
	seq.Content = append(seq.Content, c)
	return nil
}

// SetGrant gives a client rights on a key (replacing an earlier grant).
func (d *Doc) SetGrant(client, key string, g config.Grant) error {
	c := d.client(client)
	if c == nil {
		return fmt.Errorf("no client %q", client)
	}
	if !d.Has("keys", key) {
		return fmt.Errorf("no key %q", key)
	}
	if len(g.Ops) == 0 {
		return fmt.Errorf("give at least one operation")
	}
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	set(n, "ops", flow(scalar(g.Ops)))
	if g.PerMinute > 0 {
		set(n, "per_minute", scalar(g.PerMinute))
	}
	if g.PerDay > 0 {
		set(n, "per_day", scalar(g.PerDay))
	}
	if len(g.Contexts) > 0 {
		set(n, "contexts", flow(scalar(g.Contexts)))
	}
	set(mapping(c, "keys"), key, flow(n))
	return nil
}

// RemoveGrant takes a client's rights on a key away.
func (d *Doc) RemoveGrant(client, key string) error {
	c := d.client(client)
	if c == nil || !del(get(c, "keys"), key) {
		return fmt.Errorf("client %q has no grant on %q", client, key)
	}
	return nil
}

// RemoveClient removes a client. Its certificate, if one was made, is not revoked (there is no revocation list): it just stops being known.
func (d *Doc) RemoveClient(name string) error {
	seq := get(d.root, "clients")
	_, i := find(seq, name)
	if i < 0 {
		return fmt.Errorf("no client %q", name)
	}
	seq.Content = append(seq.Content[:i], seq.Content[i+1:]...)
	if len(seq.Content) == 0 {
		del(d.root, "clients")
	}
	return nil
}
