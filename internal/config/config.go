// Package config is hsmgate.yaml: tokens, keys, clients, listeners. Everything is checked at load; a bad file never starts a service.
package config

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen string `yaml:"listen"`
	TLS    TLS    `yaml:"tls"`
	// InsecureLoopbackClient, when set, serves plain HTTP on a loopback address as this client: for tests and development only.
	InsecureLoopbackClient string `yaml:"insecure_loopback_client"`
	Transit                struct {
		Mount string `yaml:"mount"`
	} `yaml:"transit"`
	// AdminSocket is a unix socket (mode 0600) for unlock and status; unset: no admin door.
	AdminSocket string `yaml:"admin_socket"`
	// Limits bound the work that reaches the tokens at once (a card serves one operation at a time). Changing them needs a restart.
	Limits Limits `yaml:"limits"`
	Audit  struct {
		File string `yaml:"file"`
	} `yaml:"audit"`
	Tokens  []Token        `yaml:"tokens"`
	Keys    map[string]Key `yaml:"keys"`
	Clients []Client       `yaml:"clients"`
}

type Limits struct {
	MaxConcurrent int `yaml:"max_concurrent"` // operations that may run or wait for a token at once; default 8
	QueueSeconds  int `yaml:"queue_seconds"`  // how long one may wait for its turn before 503; default 2
}

type TLS struct {
	Cert     string `yaml:"cert"`
	Key      string `yaml:"key"`
	ClientCA string `yaml:"client_ca"`
}

// Token is one physical (or software) token. Type "soft" holds private keys in files: tests and development.
type Token struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"` // soft or pkcs11
	// soft: label -> file with 64 hex digits. pkcs11: label -> CKA_ID of the key pair, in hex.
	Keys map[string]string `yaml:"keys"`
	// pkcs11 only
	Module      string `yaml:"module"`
	TokenLabel  string `yaml:"token_label"`
	TokenSerial string `yaml:"token_serial"`
	// PinFile: tried once at start. Without it the token starts locked until `hsmgate unlock`.
	PinFile string `yaml:"pin_file"`
}

// Key is a named key of the Transit face. Versions[i] is version i+1; the last one is the latest.
type Key struct {
	Versions []Version `yaml:"versions"`
	AAD      AAD       `yaml:"aad"`
	MaxBytes int       `yaml:"max_bytes"`
}

// Version is one version of a key. Replicas are other tokens that hold the same key (a spare card made from a DKEK backup): they are tried, in order,
// when the first token cannot answer; their public key must be the same, or the configuration is refused.
type Version struct {
	Token    string    `yaml:"token"`
	Label    string    `yaml:"label"`
	Replicas []Replica `yaml:"replicas"`
	// Fingerprint, when set, pins the public key of this version (hex, as `hsmgate check` prints it): a holder with another key is never used.
	Fingerprint string `yaml:"fingerprint"`
}

type Replica struct {
	Token string `yaml:"token"`
	Label string `yaml:"label"`
}

// Holders lists the primary and then the replicas.
func (v Version) Holders() []Replica {
	return append([]Replica{{v.Token, v.Label}}, v.Replicas...)
}

// AAD says how the additional data of the AEAD is made. Mode "fixed": a constant for the key, no context accepted (OpenBao's seal sends none;
// the default value is the one kekd used, so that existing ciphertexts open). Mode "context": the context of the request, exactly, required,
// and it must begin with one of Allow.
type AAD struct {
	Mode  string   `yaml:"mode"`
	Fixed string   `yaml:"fixed"`
	Allow []string `yaml:"allow"`
}

type Client struct {
	Name     string           `yaml:"name"`
	Identity Identity         `yaml:"identity"`
	Keys     map[string]Grant `yaml:"keys"`
}

// Identity: any one that is set must match. URI is a URI SAN, SHA256 the hex SHA-256 of the certificate, CN the last resort.
type Identity struct {
	URI    string `yaml:"uri"`
	SHA256 string `yaml:"sha256"`
	CN     string `yaml:"cn"`
}

type Grant struct {
	Ops       []string `yaml:"ops"`
	PerMinute int      `yaml:"per_minute"`
	PerDay    int      `yaml:"per_day"`
	// Contexts narrows a key in context mode for this client: the context of a request must begin with one of these (and with one of the key's own aad.allow).
	// Empty: no narrowing beyond the key's. This is how a client certificate of one namespace is kept to the contexts of that namespace.
	Contexts []string `yaml:"contexts"`
}

const DefaultMaxBytes = 8192

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

// Parse reads and checks a configuration; unknown fields are errors (a misspelt policy line must not be silently ignored).
func Parse(raw []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

const (
	MaxBytesLimit = 1 << 20 // the largest max_bytes
	maxRate       = 1_000_000
)

func isHex(s string, n int) bool {
	if n > 0 && len(s) != n {
		return false
	}
	if len(s) == 0 || len(s)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// Validate checks the configuration as a whole. Ambiguity is an error: duplicate names, two clients with one identity, limits that read as "none" by accident.
func (c *Config) Validate() error {
	if c.Transit.Mount == "" {
		c.Transit.Mount = "transit"
	}
	if c.Limits.MaxConcurrent < 0 || c.Limits.QueueSeconds < 0 || c.Limits.MaxConcurrent > 1024 || c.Limits.QueueSeconds > 60 {
		return fmt.Errorf("limits: max_concurrent 0..1024 and queue_seconds 0..60")
	}
	tokens := map[string]Token{}
	for _, t := range c.Tokens {
		if t.Name == "" || (t.Type != "soft" && t.Type != "pkcs11") {
			return fmt.Errorf("token %q: type must be soft or pkcs11", t.Name)
		}
		if _, dup := tokens[t.Name]; dup {
			return fmt.Errorf("token %q is defined twice", t.Name)
		}
		if t.Type == "pkcs11" {
			if t.Module == "" {
				return fmt.Errorf("token %q: module is required", t.Name)
			}
			for label, id := range t.Keys {
				if !isHex(id, 0) {
					return fmt.Errorf("token %s key %s: the CKA_ID must be hex and not empty", t.Name, label)
				}
			}
		}
		tokens[t.Name] = t
	}
	for name, k := range c.Keys {
		if len(k.Versions) == 0 {
			return fmt.Errorf("key %s: no versions", name)
		}
		if k.MaxBytes < 0 || k.MaxBytes > MaxBytesLimit {
			return fmt.Errorf("key %s: max_bytes must be 0..%d", name, MaxBytesLimit)
		}
		for i, v := range k.Versions {
			if v.Fingerprint != "" && !isHex(v.Fingerprint, 64) {
				return fmt.Errorf("key %s version %d: fingerprint must be 64 hex digits", name, i+1)
			}
			for _, h := range v.Holders() {
				t, ok := tokens[h.Token]
				if !ok {
					return fmt.Errorf("key %s version %d: unknown token %q", name, i+1, h.Token)
				}
				if _, ok := t.Keys[h.Label]; !ok {
					return fmt.Errorf("key %s version %d: token %s has no key %q", name, i+1, h.Token, h.Label)
				}
			}
		}
		switch k.AAD.Mode {
		case "fixed":
		case "context":
			if len(k.AAD.Allow) == 0 {
				return fmt.Errorf("key %s: aad mode context needs allow patterns", name)
			}
			for _, a := range k.AAD.Allow {
				if a == "" {
					return fmt.Errorf("key %s: an empty allow pattern would allow every context", name)
				}
			}
		default:
			return fmt.Errorf("key %s: aad mode must be fixed or context", name)
		}
	}
	names := map[string]bool{}
	idents := map[string]string{}
	for _, cl := range c.Clients {
		if cl.Name == "" {
			return fmt.Errorf("a client has no name")
		}
		if names[cl.Name] {
			return fmt.Errorf("client %q is defined twice", cl.Name)
		}
		names[cl.Name] = true
		id := cl.Identity
		set, ident := 0, ""
		if id.URI != "" {
			set++
			ident = "uri:" + id.URI
			if u, err := url.Parse(id.URI); err != nil || u.Scheme == "" {
				return fmt.Errorf("client %s: identity.uri is not a URI", cl.Name)
			}
		}
		if id.SHA256 != "" {
			set++
			ident = "sha256:" + strings.ToLower(id.SHA256)
			if !isHex(id.SHA256, 64) {
				return fmt.Errorf("client %s: identity.sha256 must be 64 hex digits", cl.Name)
			}
		}
		if id.CN != "" {
			set++
			ident = "cn:" + id.CN
		}
		if set != 1 {
			return fmt.Errorf("client %s: exactly one of identity.uri, identity.sha256, identity.cn is required (several would be an OR)", cl.Name)
		}
		if other, dup := idents[ident]; dup {
			return fmt.Errorf("clients %s and %s have the same identity", other, cl.Name)
		}
		idents[ident] = cl.Name
		for key, g := range cl.Keys {
			if _, ok := c.Keys[key]; !ok {
				return fmt.Errorf("client %s: unknown key %q", cl.Name, key)
			}
			if g.PerMinute < 0 || g.PerDay < 0 || g.PerMinute > maxRate || g.PerDay > maxRate {
				return fmt.Errorf("client %s key %s: per_minute and per_day must be 0..%d (0 is no limit)", cl.Name, key, maxRate)
			}
			for _, op := range g.Ops {
				if op != "encrypt" && op != "decrypt" && op != "rewrap" {
					return fmt.Errorf("client %s key %s: unknown op %q", cl.Name, key, op)
				}
			}
			if len(g.Contexts) > 0 && c.Keys[key].AAD.Mode != "context" {
				return fmt.Errorf("client %s key %s: contexts only apply to a key in context mode", cl.Name, key)
			}
			for _, x := range g.Contexts {
				if x == "" {
					return fmt.Errorf("client %s key %s: an empty context prefix would allow every context", cl.Name, key)
				}
			}
		}
	}
	return nil
}

// FixedAAD is the constant additional data of a key in mode fixed.
func (k Key) FixedAAD(name string) string {
	if k.AAD.Fixed != "" {
		return k.AAD.Fixed
	}
	return "openbao/seal/v1|" + name
}
