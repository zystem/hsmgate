// Package config is hsmgate.yaml: tokens, keys, clients, listeners. Everything is checked at load; a bad file never starts a service.
package config

import (
	"fmt"
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
	Audit struct {
		File string `yaml:"file"`
	} `yaml:"audit"`
	Tokens  []Token        `yaml:"tokens"`
	Keys    map[string]Key `yaml:"keys"`
	Clients []Client       `yaml:"clients"`
}

type TLS struct {
	Cert     string `yaml:"cert"`
	Key      string `yaml:"key"`
	ClientCA string `yaml:"client_ca"`
}

// Token is one physical (or software) token. Type "soft" holds private keys in files: tests and development.
type Token struct {
	Name string            `yaml:"name"`
	Type string            `yaml:"type"`
	Keys map[string]string `yaml:"keys"` // soft: label -> file with 64 hex digits
}

// Key is a named key of the Transit face. Versions[i] is version i+1; the last one is the latest.
type Key struct {
	Versions []Version `yaml:"versions"`
	AAD      AAD       `yaml:"aad"`
	MaxBytes int       `yaml:"max_bytes"`
}

type Version struct {
	Token string `yaml:"token"`
	Label string `yaml:"label"`
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
}

const DefaultMaxBytes = 8192

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, err
	}
	return &c, c.Validate()
}

func (c *Config) Validate() error {
	if c.Transit.Mount == "" {
		c.Transit.Mount = "transit"
	}
	tokens := map[string]Token{}
	for _, t := range c.Tokens {
		if t.Name == "" || t.Type != "soft" { // pkcs11 comes in P3
			return fmt.Errorf("token %q: type must be soft", t.Name)
		}
		tokens[t.Name] = t
	}
	for name, k := range c.Keys {
		if len(k.Versions) == 0 {
			return fmt.Errorf("key %s: no versions", name)
		}
		for i, v := range k.Versions {
			t, ok := tokens[v.Token]
			if !ok {
				return fmt.Errorf("key %s version %d: unknown token %q", name, i+1, v.Token)
			}
			if _, ok := t.Keys[v.Label]; !ok {
				return fmt.Errorf("key %s version %d: token %s has no key %q", name, i+1, v.Token, v.Label)
			}
		}
		switch k.AAD.Mode {
		case "fixed":
		case "context":
			if len(k.AAD.Allow) == 0 {
				return fmt.Errorf("key %s: aad mode context needs allow patterns", name)
			}
		default:
			return fmt.Errorf("key %s: aad mode must be fixed or context", name)
		}
	}
	for _, cl := range c.Clients {
		if cl.Name == "" || (cl.Identity == Identity{}) {
			return fmt.Errorf("client %q: name and identity are required", cl.Name)
		}
		for key, g := range cl.Keys {
			if _, ok := c.Keys[key]; !ok {
				return fmt.Errorf("client %s: unknown key %q", cl.Name, key)
			}
			for _, op := range g.Ops {
				if op != "encrypt" && op != "decrypt" && op != "rewrap" {
					return fmt.Errorf("client %s key %s: unknown op %q", cl.Name, key, op)
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
