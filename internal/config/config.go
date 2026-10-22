// Package config is hsmgate.yaml: tokens, keys, clients, listeners. Everything is checked at load; a bad file never starts a service.
package config

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen string `yaml:"listen"`
	TLS    TLS    `yaml:"tls"`
	// SealFormat is the format of what the service seals: "ecies2" (the default: AES-256-GCM, all algorithms approved in a FIPS 140-3 module; an older version of the service
	// cannot open it) or "ecies1" (ChaCha20-Poly1305, what every version before 0.3 wrote). Both are always read, unless RequireFIPS.
	SealFormat string `yaml:"seal_format"`
	// RequireFIPS: refuse to start unless the process runs with the Go cryptographic module in FIPS 140-3 mode (GODEBUG=fips140=on, or a binary built with GOFIPS140), seal in ecies2
	// and refuse to open ecies1 (docs/compliance.md). It says nothing about the token.
	RequireFIPS bool `yaml:"require_fips"`
	// InsecureLoopbackClient, when set, serves plain HTTP on a loopback address as this client: for tests and development only.
	InsecureLoopbackClient string `yaml:"insecure_loopback_client"`
	Transit                struct {
		Mount string `yaml:"mount"`
	} `yaml:"transit"`
	// KMSJSON turns on the second face: a subset of the JSON API of cloud key services of the same name-shape (docs/specs/kms-json.md). It shares the listener with Transit.
	KMSJSON struct {
		Enabled bool   `yaml:"enabled"`
		Region  string `yaml:"region"` // the region string of the credential scope that clients sign with; default "local"
		// MacCacheSeconds: how long the MAC key derived from a key on the token is kept in memory (0: not at all, one ECDH on the token for every MAC). A cache makes MACs fast and puts
		// a key derived from the token's key into the memory of the process for that time.
		MacCacheSeconds int `yaml:"mac_cache_seconds"`
		// AuditMessagePrefix: write the first 6 bytes of the hash of a signed or authenticated message into the audit line (to tie a line to a message). Off by default: the hash of a
		// message with little variety can be guessed from its prefix by whoever reads the log (audit of 2026-10-21).
		AuditMessagePrefix bool `yaml:"audit_message_prefix"`
	} `yaml:"kmsjson"`
	// Metrics: GET /metrics on the admin socket, off unless enabled. Detail "basic" (the default) counts decisions by face and outcome class only; "full" adds the operation and the
	// result words of the audit log. What is counted tells when secrets are used and how much is refused, so it is treated as sensitive (docs/threat-model.md).
	Metrics struct {
		Enabled bool   `yaml:"enabled"`
		Detail  string `yaml:"detail"`
	} `yaml:"metrics"`
	// KMSGRPC turns on the gRPC face: the API of a cloud key service as its client libraries speak it (gRPC over HTTP/2, authenticated by a bearer token that a client gets by
	// proving that it holds the private key of a service account). It shares the listener with the other faces. Project, Location and KeyRing make the resource names
	// ("projects/P/locations/L/keyRings/R/cryptoKeys/KEY"); the defaults are "hsmgate", "global" and "main".
	KMSGRPC struct {
		Enabled   bool   `yaml:"enabled"`
		Project   string `yaml:"project"`
		Location  string `yaml:"location"`
		KeyRing   string `yaml:"key_ring"`
		TokenPath string `yaml:"token_path"` // where clients ask for a token; default /oauth2/token
	} `yaml:"kmsgrpc"`
	// KMSRest turns on the REST face: the API of a cloud key vault as its client libraries speak it (JSON over HTTPS, authenticated by a bearer token that a client gets by
	// proving its client secret or the private key of its credential at the token endpoint). It shares the listener with the other faces. Tenant is the directory identifier that
	// appears in the token path; the default is "hsmgate".
	KMSRest struct {
		Enabled bool   `yaml:"enabled"`
		Tenant  string `yaml:"tenant"`
	} `yaml:"kmsrest"`
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
	// MaxConnections: connections open at once on the listener (the next waits in the backlog); default 128. A client holds one or a few; with HTTP/2 each carries at most 16 requests at a time.
	MaxConnections int `yaml:"max_connections"`
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
	// KMSJSON lets clients with the "derive" right use the key through the KMS-JSON face: ECDH with a key that stays on the token. That face has no context, so whoever may derive
	// can open anything sealed to the key: such a key must be in "fixed" mode (a key in context mode would lose the isolation of its contexts) and is best dedicated to this use.
	KMSJSON bool `yaml:"kmsjson"`
	// KMSGRPC and KMSRest expose the key on the other two key-service faces (the gRPC one and the REST one), with the same usage and the same rules as KMSJSON.
	KMSGRPC bool `yaml:"kmsgrpc"`
	KMSRest bool `yaml:"kmsrest"`
	// KMSJSONUsage: "key_agreement" (the default: DeriveSharedSecret, the client seals and opens) or "encrypt_decrypt" (Encrypt, Decrypt, ReEncrypt, GenerateDataKey: the service seals
	// and opens, as in the Transit face, and the request's EncryptionContext is the additional data) or "sign_verify" (Sign and Verify: ECDSA P-256 with SHA-256, the signature made on the
	// token; the key label must be used by no other key) or "generate_verify_mac" (GenerateMac and VerifyMac: HMAC-SHA-256 with a key derived on the token by ECDH, see
	// internal/keyops/mac.go; the key label must be used by no other key). One key has one usage: the right to derive would open anything sealed to the key.
	KMSJSONUsage string `yaml:"kmsjson_usage"`
}

const (
	UsageKeyAgreement   = "key_agreement"
	UsageEncryptDecrypt = "encrypt_decrypt"
	UsageSignVerify     = "sign_verify"
	UsageMAC            = "generate_verify_mac"
)

// OnAnyFace: the key is exposed on at least one of the key-service faces; the rules about names, usages and separate private keys hold for all of them.
func (k Key) OnAnyFace() bool { return k.KMSJSON || k.KMSGRPC || k.KMSRest }

// OnFace: the key is exposed on the face of this name ("kmsjson", "kmsgrpc", "kmsrest").
func (k Key) OnFace(face string) bool {
	switch face {
	case "kmsjson":
		return k.KMSJSON
	case "kmsgrpc":
		return k.KMSGRPC
	case "kmsrest":
		return k.KMSRest
	}
	return false
}

// Usage of a key on the KMS-JSON face.
func (k Key) Usage() string {
	if k.KMSJSONUsage == "" {
		return UsageKeyAgreement
	}
	return k.KMSJSONUsage
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
	// SigV4 is the credential that this client signs its requests with on the KMS-JSON face (inside the same mutual TLS). The secret is read from a file (mode 0600), never from this file.
	SigV4 *SigV4 `yaml:"sigv4"`
	// JWT is the credential on the gRPC face: the client holds the private key of a service account and proves it with a signed token (RS256); the service holds the public key.
	JWT *JWT `yaml:"jwt"`
	// OAuth is the credential on the REST face: a client id with a secret (read from a file) or with the public key of a certificate whose private key the client holds.
	OAuth *OAuth `yaml:"oauth"`
}

// OAuth is an application credential as the REST face knows it. Exactly one of SecretFile (32 bytes or more) and PublicKeyFile (RSA, 2048 bits or more) is set. AllowFrom and NoCert
// mean what they mean for SigV4.
type OAuth struct {
	ClientID      string   `yaml:"client_id"`
	SecretFile    string   `yaml:"secret_file"`
	PublicKeyFile string   `yaml:"public_key_file"`
	AllowFrom     []string `yaml:"allow_from"`
	NoCert        bool     `yaml:"no_cert"`
}

// JWT is a service account as the gRPC face knows it. Issuer is the "client_email" of the service account file; PublicKeyFile is a PEM public key (RSA, at least 2048 bits) or a
// certificate. AllowFrom and NoCert mean what they mean for SigV4: addresses the credential may be used from (required for NoCert), and no client certificate needed.
type JWT struct {
	Issuer        string   `yaml:"issuer"`
	PublicKeyFile string   `yaml:"public_key_file"`
	AllowFrom     []string `yaml:"allow_from"`
	NoCert        bool     `yaml:"no_cert"`
}

// NoCertCredential: some credential of the client lets it call without a client certificate.
func (c Client) NoCertCredential() bool {
	return (c.SigV4 != nil && c.SigV4.NoCert) || (c.JWT != nil && c.JWT.NoCert) || (c.OAuth != nil && c.OAuth.NoCert)
}

type SigV4 struct {
	AccessKeyID string `yaml:"access_key_id"`
	SecretFile  string `yaml:"secret_file"`
	// AllowFrom limits the addresses this credential may be used from (addresses or CIDR blocks; the address of the TCP peer, never a header). Empty: any, which NoCert does not allow.
	AllowFrom []string `yaml:"allow_from"`
	// NoCert: this client may call with the signature alone, without a client certificate, for programs that cannot present one (the SDKs of cloud key services take only a CA bundle).
	// It is one proof instead of two: the secret is then the only thing that says who calls, and it must be 32 bytes or more. Allowed for keys of the usages encrypt_decrypt, sign_verify
	// and generate_verify_mac (not key_agreement), from listed addresses. A secret that is stolen and used from a listed address signs or makes MACs as the client: give such a client
	// keys of its own and per_minute limits. The client needs no identity (if it has one, a certificate that is shown must still agree).
	NoCert bool `yaml:"no_cert"`
}

// Prefixes reads AllowFrom.
func (s SigV4) Prefixes() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, a := range s.AllowFrom {
		if p, err := netip.ParsePrefix(a); err == nil {
			out = append(out, p.Masked())
			continue
		}
		ip, err := netip.ParseAddr(a)
		if err != nil {
			return nil, fmt.Errorf("allow_from: %q is not an address or a CIDR block", a)
		}
		ip = ip.Unmap()
		out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
	}
	return out, nil
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
	raw, err := os.ReadFile(path) // #nosec G304 -- the path is the operator's own argument
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
	if c.Limits.MaxConcurrent < 0 || c.Limits.QueueSeconds < 0 || c.Limits.MaxConcurrent > 1024 || c.Limits.QueueSeconds > 60 || c.Limits.MaxConnections < 0 || c.Limits.MaxConnections > 65535 {
		return fmt.Errorf("limits: max_concurrent 0..1024, queue_seconds 0..60 and max_connections 0..65535")
	}
	switch c.Metrics.Detail {
	case "":
		c.Metrics.Detail = "basic"
	case "basic", "full":
	default:
		return fmt.Errorf("metrics.detail must be basic or full")
	}
	if c.Metrics.Enabled && c.AdminSocket == "" {
		return fmt.Errorf("metrics.enabled needs admin_socket (the metrics are served on it, not on the network)")
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
		certless := set == 0 && cl.NoCertCredential() // identified by its signature or token alone
		if set != 1 && !certless {
			return fmt.Errorf("client %s: exactly one of identity.uri, identity.sha256, identity.cn is required (several would be an OR)", cl.Name)
		}
		if ident != "" {
			if other, dup := idents[ident]; dup {
				return fmt.Errorf("clients %s and %s have the same identity", other, cl.Name)
			}
			idents[ident] = cl.Name
		}
		for key, g := range cl.Keys {
			if _, ok := c.Keys[key]; !ok {
				return fmt.Errorf("client %s: unknown key %q", cl.Name, key)
			}
			if g.PerMinute < 0 || g.PerDay < 0 || g.PerMinute > maxRate || g.PerDay > maxRate {
				return fmt.Errorf("client %s key %s: per_minute and per_day must be 0..%d (0 is no limit)", cl.Name, key, maxRate)
			}
			for _, op := range g.Ops {
				if op != "encrypt" && op != "decrypt" && op != "rewrap" && op != "derive" && op != "sign" && op != "verify" && op != "generate_mac" && op != "verify_mac" {
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
	if err := c.validateKMSJSON(); err != nil {
		return err
	}
	switch c.SealFormat {
	case "":
		c.SealFormat = "ecies2"
	case "ecies1":
		if c.RequireFIPS {
			return fmt.Errorf("require_fips needs seal_format ecies2")
		}
	case "ecies2":
	default:
		return fmt.Errorf("seal_format must be ecies1 or ecies2")
	}
	if err := c.validateKMSGRPC(); err != nil {
		return err
	}
	return c.validateKMSRest()
}

var idChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"

// validateKMSGRPC: the rules of the gRPC face.
func (c *Config) validateKMSGRPC() error {
	g := &c.KMSGRPC
	if g.Project == "" {
		g.Project = "hsmgate"
	}
	if g.Location == "" {
		g.Location = "global"
	}
	if g.KeyRing == "" {
		g.KeyRing = "main"
	}
	if g.TokenPath == "" {
		g.TokenPath = "/oauth2/token"
	}
	for what, v := range map[string]string{"project": g.Project, "location": g.Location, "key_ring": g.KeyRing} {
		if len(v) > 63 || strings.Trim(v, idChars) != "" {
			return fmt.Errorf("kmsgrpc.%s must be 1 to 63 letters, digits, dashes and underscores", what)
		}
	}
	if !strings.HasPrefix(g.TokenPath, "/") || len(g.TokenPath) < 2 || len(g.TokenPath) > 100 || strings.ContainsAny(g.TokenPath, " ?#") || g.TokenPath == "/v1" || strings.HasPrefix(g.TokenPath, "/v1/") {
		return fmt.Errorf("kmsgrpc.token_path must be a path such as /oauth2/token (not under /v1)")
	}
	any := false
	for name, k := range c.Keys {
		if k.KMSGRPC {
			any = true
			if k.Usage() == UsageKeyAgreement {
				return fmt.Errorf("key %s: kmsgrpc needs kmsjson_usage encrypt_decrypt, sign_verify or generate_verify_mac (that face has no key agreement)", name)
			}
		}
	}
	if g.Enabled && !any {
		return fmt.Errorf("kmsgrpc.enabled but no key has kmsgrpc: true")
	}
	issuers := map[string]string{}
	for _, cl := range c.Clients {
		if cl.JWT == nil {
			continue
		}
		j := cl.JWT
		if !g.Enabled {
			return fmt.Errorf("client %s has a jwt credential but kmsgrpc.enabled is false", cl.Name)
		}
		if len(j.Issuer) < 3 || len(j.Issuer) > 200 || strings.Trim(j.Issuer, idChars+"@.") != "" {
			return fmt.Errorf("client %s: jwt.issuer must be 3 to 200 letters, digits and @ . - _", cl.Name)
		}
		if j.PublicKeyFile == "" {
			return fmt.Errorf("client %s: jwt.public_key_file is required", cl.Name)
		}
		if other, dup := issuers[j.Issuer]; dup {
			return fmt.Errorf("clients %s and %s have the same jwt.issuer", other, cl.Name)
		}
		issuers[j.Issuer] = cl.Name
		if _, err := (SigV4{AllowFrom: j.AllowFrom}).Prefixes(); err != nil {
			return fmt.Errorf("client %s: jwt.%w", cl.Name, err)
		}
		if j.NoCert {
			if len(j.AllowFrom) == 0 {
				return fmt.Errorf("client %s: jwt.no_cert needs jwt.allow_from (a client without a certificate is held to listed addresses)", cl.Name)
			}
			for key, g := range cl.Keys {
				if k := c.Keys[key]; !k.KMSGRPC || k.Usage() == UsageKeyAgreement {
					return fmt.Errorf("client %s key %s: a client without a certificate may use only keys that are on the gRPC face", cl.Name, key)
				}
				for _, op := range g.Ops {
					if op == "derive" || op == "rewrap" {
						return fmt.Errorf("client %s key %s: a client without a certificate may not have the right %s", cl.Name, key, op)
					}
				}
			}
		}
	}
	return nil
}

// validateKMSRest: the rules of the REST face.
func (c *Config) validateKMSRest() error {
	r := &c.KMSRest
	if r.Tenant == "" {
		r.Tenant = "hsmgate"
	}
	if len(r.Tenant) > 63 || strings.Trim(r.Tenant, idChars+".") != "" {
		return fmt.Errorf("kmsrest.tenant must be 1 to 63 letters, digits, dots, dashes and underscores")
	}
	any := false
	for name, k := range c.Keys {
		if k.KMSRest {
			any = true
			if k.Usage() == UsageKeyAgreement {
				return fmt.Errorf("key %s: kmsrest needs kmsjson_usage encrypt_decrypt, sign_verify or generate_verify_mac (that face has no key agreement)", name)
			}
		}
	}
	if r.Enabled && !any {
		return fmt.Errorf("kmsrest.enabled but no key has kmsrest: true")
	}
	ids := map[string]string{}
	for _, cl := range c.Clients {
		o := cl.OAuth
		if o == nil {
			continue
		}
		if !r.Enabled {
			return fmt.Errorf("client %s has an oauth credential but kmsrest.enabled is false", cl.Name)
		}
		if len(o.ClientID) < 3 || len(o.ClientID) > 100 || strings.Trim(o.ClientID, idChars+"@.") != "" {
			return fmt.Errorf("client %s: oauth.client_id must be 3 to 100 letters, digits and @ . - _", cl.Name)
		}
		if (o.SecretFile == "") == (o.PublicKeyFile == "") {
			return fmt.Errorf("client %s: oauth needs exactly one of secret_file and public_key_file", cl.Name)
		}
		if other, dup := ids[o.ClientID]; dup {
			return fmt.Errorf("clients %s and %s have the same oauth.client_id", other, cl.Name)
		}
		ids[o.ClientID] = cl.Name
		if _, err := (SigV4{AllowFrom: o.AllowFrom}).Prefixes(); err != nil {
			return fmt.Errorf("client %s: oauth.%w", cl.Name, err)
		}
		if o.NoCert {
			if len(o.AllowFrom) == 0 {
				return fmt.Errorf("client %s: oauth.no_cert needs oauth.allow_from (a client without a certificate is held to listed addresses)", cl.Name)
			}
			for key, g := range cl.Keys {
				if k := c.Keys[key]; !k.KMSRest || k.Usage() == UsageKeyAgreement {
					return fmt.Errorf("client %s key %s: a client without a certificate may use only keys that are on the REST face", cl.Name, key)
				}
				for _, op := range g.Ops {
					if op == "derive" || op == "rewrap" {
						return fmt.Errorf("client %s key %s: a client without a certificate may not have the right %s", cl.Name, key, op)
					}
				}
			}
		}
	}
	return nil
}

// validateKMSJSON: the second face has rules of its own.
func (c *Config) validateKMSJSON() error {
	if c.KMSJSON.Region == "" {
		c.KMSJSON.Region = "local"
	}
	if c.KMSJSON.MacCacheSeconds < 0 || c.KMSJSON.MacCacheSeconds > 3600 {
		return fmt.Errorf("kmsjson.mac_cache_seconds must be 0 to 3600")
	}
	for _, r := range c.KMSJSON.Region {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return fmt.Errorf("kmsjson.region must be lowercase letters, digits and dashes")
		}
	}
	for name, k := range c.Keys {
		if k.OnAnyFace() {
			// the name is read back from a key id ("name", "alias/name", an identifier ending in ":key/name", "name@N") and written into ciphertext blobs with a length byte
			if len(name) == 0 || len(name) > 128 || strings.Trim(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-") != "" {
				return fmt.Errorf("key %s: a key exposed on a key-service face is named with 1 to 128 letters, digits, dots, dashes and underscores", name)
			}
			if len(k.Versions) > 1000 {
				return fmt.Errorf("key %s: a key exposed on a key-service face has at most 1000 versions", name)
			}
		}
		if k.KMSJSONUsage != "" && !k.OnAnyFace() {
			return fmt.Errorf("key %s: kmsjson_usage needs kmsjson: true (or kmsgrpc, kmsrest)", name)
		}
		switch k.KMSJSONUsage {
		case "", UsageKeyAgreement:
			if k.OnAnyFace() && k.AAD.Mode != "fixed" {
				return fmt.Errorf("key %s: kmsjson key agreement needs aad mode fixed (DeriveSharedSecret has no context, so a key in context mode would lose the isolation of its contexts); use kmsjson_usage: encrypt_decrypt for a key with contexts", name)
			}
		case UsageEncryptDecrypt:
		case UsageSignVerify, UsageMAC:
			// a private key signs, makes MACs or does ECDH, never two of them: see distinctKeys
		default:
			return fmt.Errorf("key %s: kmsjson_usage must be key_agreement, encrypt_decrypt, sign_verify or generate_verify_mac", name)
		}
	}
	if err := c.distinctKeys(); err != nil {
		return err
	}
	akids := map[string]string{}
	for _, cl := range c.Clients {
		derives := false
		for key, g := range cl.Keys {
			for _, op := range g.Ops {
				k := c.Keys[key]
				if (op == "sign" || op == "verify") && !(k.OnAnyFace() && k.Usage() == UsageSignVerify) {
					return fmt.Errorf("client %s key %s: the right %s needs kmsjson: true and the usage sign_verify on the key", cl.Name, key, op)
				}
				if k.OnAnyFace() && k.Usage() == UsageSignVerify && op != "sign" && op != "verify" {
					return fmt.Errorf("client %s key %s: a key with the usage sign_verify has the rights sign and verify only, not %s", cl.Name, key, op)
				}
				if (op == "generate_mac" || op == "verify_mac") && !(k.OnAnyFace() && k.Usage() == UsageMAC) {
					return fmt.Errorf("client %s key %s: the right %s needs kmsjson: true and the usage generate_verify_mac on the key", cl.Name, key, op)
				}
				if k.OnAnyFace() && k.Usage() == UsageMAC && op != "generate_mac" && op != "verify_mac" {
					return fmt.Errorf("client %s key %s: a key with the usage generate_verify_mac has the rights generate_mac and verify_mac only, not %s", cl.Name, key, op)
				}
				if op == "derive" {
					derives = true
					if !c.Keys[key].KMSJSON || c.Keys[key].Usage() != UsageKeyAgreement {
						return fmt.Errorf("client %s key %s: the right derive needs kmsjson: true and the usage key_agreement on the key", cl.Name, key)
					}
				}
			}
		}
		if cl.SigV4 != nil {
			a := cl.SigV4
			if len(a.AccessKeyID) < 16 || len(a.AccessKeyID) > 128 || strings.Trim(a.AccessKeyID, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") != "" {
				return fmt.Errorf("client %s: sigv4.access_key_id must be 16 to 128 letters and digits", cl.Name)
			}
			if a.SecretFile == "" {
				return fmt.Errorf("client %s: sigv4.secret_file is required", cl.Name)
			}
			if other, dup := akids[a.AccessKeyID]; dup {
				return fmt.Errorf("clients %s and %s have the same sigv4.access_key_id", other, cl.Name)
			}
			akids[a.AccessKeyID] = cl.Name
		}
		if derives && cl.SigV4 == nil {
			return fmt.Errorf("client %s: derive needs a sigv4 credential", cl.Name)
		}
		if cl.SigV4 != nil {
			if _, err := cl.SigV4.Prefixes(); err != nil {
				return fmt.Errorf("client %s: sigv4.%w", cl.Name, err)
			}
			if cl.SigV4.NoCert {
				if len(cl.SigV4.AllowFrom) == 0 {
					return fmt.Errorf("client %s: sigv4.no_cert needs sigv4.allow_from (a client without a certificate is held to listed addresses)", cl.Name)
				}
				for key, g := range cl.Keys {
					// the usage key_agreement (DeriveSharedSecret) needs a certificate: it opens whatever is sealed to the key and has no context to check
					if k := c.Keys[key]; !k.KMSJSON || k.Usage() == UsageKeyAgreement {
						return fmt.Errorf("client %s key %s: a client without a certificate may use keys with kmsjson_usage encrypt_decrypt, sign_verify or generate_verify_mac, not key_agreement", cl.Name, key)
					}
					for _, op := range g.Ops {
						if op == "derive" || op == "rewrap" {
							return fmt.Errorf("client %s key %s: a client without a certificate may not have the right %s", cl.Name, key, op)
						}
					}
				}
			}
		}
		if cl.SigV4 != nil && !c.KMSJSON.Enabled {
			return fmt.Errorf("client %s has a sigv4 credential but kmsjson.enabled is false", cl.Name)
		}
	}
	if c.KMSJSON.Enabled {
		any := false
		for _, k := range c.Keys {
			any = any || k.KMSJSON
		}
		if !any {
			return fmt.Errorf("kmsjson.enabled but no key has kmsjson: true")
		}
	}
	return nil
}

// CertOptional: some client may call the KMS-JSON face without a client certificate, so the listener must let a connection without one through (the Transit face refuses it per request).
func (c *Config) CertOptional() bool {
	for _, cl := range c.Clients {
		if cl.NoCertCredential() {
			return true
		}
	}
	return false
}

// physicalKey names the key a holder points at as well as the configuration can tell, without asking the token: the file of a soft key; the module, token and CKA_ID of a PKCS#11 key.
func (c *Config) physicalKey(tokenName, label string) string {
	for _, t := range c.Tokens {
		if t.Name != tokenName {
			continue
		}
		ref := t.Keys[label]
		if t.Type == "soft" {
			return "file:" + filepath.Clean(ref)
		}
		return "p11:" + t.Module + "|" + t.TokenLabel + "|" + t.TokenSerial + "|" + strings.ToLower(ref)
	}
	return "unknown:" + tokenName + "/" + label
}

// distinctKeys: once the KMS-JSON face is in use, no two keys of the configuration may rest on the same private key (audit of 2026-10-21, CR-01). That face gives raw ECDH
// (DeriveSharedSecret), signatures and MACs, and a private key that does any of these under one name and another under a second name loses the separation: a client that may
// derive on one name can compute what is sealed, signed or authenticated under the other (the MAC key of a derived-key MAC is one ECDH away). The check is on what the
// configuration says (the file, the CKA_ID of the module and token, pinned fingerprints); the service also compares the public keys when the tokens answer (server.VerifyDistinct).
// The holders of one key version (a spare card) are one key by definition.
func (c *Config) distinctKeys() error {
	inUse := false
	for _, k := range c.Keys {
		inUse = inUse || k.OnAnyFace()
	}
	if !c.KMSJSON.Enabled && !c.KMSGRPC.Enabled && !c.KMSRest.Enabled && !inUse {
		return nil
	}
	owner := map[string]string{} // physical key or fingerprint -> name of the key
	names := make([]string, 0, len(c.Keys))
	for n := range c.Keys {
		names = append(names, n)
	}
	sort.Strings(names)
	claim := func(id, name string) error {
		if other, taken := owner[id]; taken && other != name {
			return fmt.Errorf("keys %s and %s rest on the same private key (%s): with the KMS-JSON face in use every key needs a private key of its own, or a derive on one name computes what is sealed, signed or authenticated under the other", other, name, strings.TrimPrefix(id, "fp:"))
		}
		owner[id] = name
		return nil
	}
	for _, name := range names {
		for _, v := range c.Keys[name].Versions {
			for _, h := range v.Holders() {
				if err := claim(c.physicalKey(h.Token, h.Label), name); err != nil {
					return err
				}
			}
			if v.Fingerprint != "" {
				if err := claim("fp:"+strings.ToLower(v.Fingerprint), name); err != nil {
					return err
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
