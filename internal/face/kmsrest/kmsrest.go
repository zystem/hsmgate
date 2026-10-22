// Package kmsrest is the face that speaks the REST API of a cloud key vault the way its client libraries do, so that those clients (and the tools built on them) can use keys that
// stay on the token. JSON over HTTPS, authenticated by a bearer token that a client gets at the token endpoint of the face by proving its client secret or the private key of its
// certificate. What an operation does is in internal/kmsops, shared with the other faces; here are the protocol, the names, the authentication of the clients and the audit line of
// each call.
//
// Names here are descriptive. Each operation says in its comment which function of the client library go.step.sm/crypto/kms/azurekms (Apache-2.0) it serves; the wire constants (the
// paths, the field names, the algorithm names) are those the clients require. The face is not affiliated with the makers of any key vault.
package kmsrest

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/zystem/hsmgate/internal/audit"
	"github.com/zystem/hsmgate/internal/backend"
	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/gate"
	"github.com/zystem/hsmgate/internal/generation"
	"github.com/zystem/hsmgate/internal/kmsops"
	"github.com/zystem/hsmgate/internal/oauth"
	"github.com/zystem/hsmgate/internal/peer"
	"github.com/zystem/hsmgate/internal/policy"
)

const (
	face        = "kmsrest"
	maxBody     = 128 << 10
	maxPlain    = 64 << 10
	maxRandom   = 128
	assertionTy = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	tokenSuffix = "/oauth2/v2.0/token" // #nosec G101 -- a path, not a credential
	resource    = "https://vault.azure.net"
)

// Cred is the credential of a client: a secret, or the public key of a certificate whose private key the client holds.
type Cred struct {
	Client string
	ID     string
	Secret []byte
	Pub    *rsa.PublicKey
	NoCert bool
	From   []netip.Prefix
}

type snap struct {
	cfg      *config.Config
	tokens   map[string]backend.Token
	pol      *policy.Policy
	identify func(*http.Request) (string, bool)
	creds    map[string]Cred
}

// Face is the REST face.
type Face struct {
	Audit   *audit.Log
	Gate    *gate.Gate
	Macs    *kmsops.MacCache
	Fails   *peer.Failures
	Created time.Time
	Tenant  string           // fixed for the life of the process
	Now     func() time.Time // for tests
	// NoCertificate says that the connection of a request showed no client certificate; nil: judged from the TLS state. For tests.
	NoCertificate func(*http.Request) bool

	gen    generation.Holder[*snap]
	tokens *oauth.Tokens
}

// New makes a face; Reload gives it its first generation.
func New(a *audit.Log, g *gate.Gate, tenant string) *Face {
	return &Face{Audit: a, Gate: g, Macs: kmsops.NewMacCache(), Fails: peer.NewFailures(), Created: time.Now(), Tenant: tenant, tokens: oauth.NewTokens()}
}

// Reload replaces the generation for the requests that come after; the returned function waits for the requests of the previous one. Access tokens stay valid, but every request is
// judged again against the credentials of the new generation.
func (f *Face) Reload(cfg *config.Config, tokens map[string]backend.Token, pol *policy.Policy, id func(*http.Request) (string, bool), creds map[string]Cred) func() {
	f.Macs.Clear()
	return f.gen.Set(&snap{cfg: cfg, tokens: tokens, pol: pol, identify: id, creds: creds})
}

func (f *Face) tokenPath() string { return "/" + f.Tenant + tokenSuffix }

// Handles: is this request for the face?
func (f *Face) Handles(r *http.Request) bool {
	p := r.URL.Path
	return p == "/keys" || strings.HasPrefix(p, "/keys/") || p == "/rng" || p == f.tokenPath() || p == f.discoveryPath()
}

func (f *Face) discoveryPath() string {
	return "/" + f.Tenant + "/v2.0/.well-known/openid-configuration"
}

// discovery is the metadata of the authority that the credential classes of the client libraries read before they ask for a token: where the token endpoint is. It is public.
func (f *Face) discovery(w http.ResponseWriter, r *http.Request) {
	base := "https://" + r.Host + "/" + f.Tenant
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"issuer": base + "/v2.0", "token_endpoint": base + tokenSuffix, "authorization_endpoint": base + "/oauth2/v2.0/authorize",
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "private_key_jwt"}, "tenant_region_scope": nil})
}

func (f *Face) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *Face) noCertificate(r *http.Request) bool {
	if f.NoCertificate != nil {
		return f.NoCertificate(r)
	}
	return r.TLS != nil && len(r.TLS.PeerCertificates) == 0
}

func requestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b)
}

func (f *Face) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s, release, ok := f.gen.Acquire()
	if !ok || !s.cfg.KMSRest.Enabled {
		http.NotFound(w, r)
		return
	}
	defer release()
	rid := requestID()
	w.Header().Set("X-Request-Id", rid)
	w.Header().Set("x-ms-request-id", rid)
	if r.URL.Path == f.discoveryPath() && r.Method == http.MethodGet {
		f.discovery(w, r)
		return
	}
	if r.URL.Path == f.tokenPath() {
		f.token(w, r, s, rid)
		return
	}
	f.call(w, r, s, rid)
}

// login is what is known of a request before its credential is looked at.
type login struct {
	client   string
	certless bool
	src      netip.Addr
}

func (f *Face) begin(r *http.Request, s *snap) (login, string) {
	l := login{src: peer.Addr(r)}
	client, ok := s.identify(r)
	if ok {
		l.client = client
		return l, ""
	}
	if !f.noCertificate(r) {
		return l, "unauthenticated"
	}
	l.certless = true
	// only a request with no certificate is counted and blocked by address: a client that showed a certificate is already known, and a peer must not be able to lock out the
	// clients behind the same address by sending bad credentials
	if f.Fails.Blocked(l.src, f.now()) {
		return l, "throttled_auth"
	}
	return l, ""
}

func (f *Face) failed(l login) {
	if l.certless {
		f.Fails.Add(l.src, f.now())
	}
}

func (f *Face) bind(l login, s *snap, id string) (Cred, string) {
	c, ok := s.creds[id]
	if !ok {
		return c, "unknown_credential"
	}
	if l.certless && !c.NoCert {
		return c, "unauthenticated"
	}
	if len(c.From) > 0 && !peer.Allowed(c.From, l.src) {
		return c, "address_refused"
	}
	if l.client != "" && l.client != c.Client {
		return c, "credential_mismatch"
	}
	return c, ""
}

// ---- the token endpoint ----

// token trades a client secret, or an assertion signed with the private key of a certificate, for an access token (the grant client_credentials). It is the exchange that the
// credential classes of the client libraries make before their first call, and that the clients of go.step.sm/crypto/kms/azurekms make through them.
func (f *Face) token(w http.ResponseWriter, r *http.Request, s *snap, rid string) {
	ev := audit.Event{RequestID: rid, Face: face, Op: "token"}
	refuse := func(status int, code, desc, result string) {
		ev.Result = result
		f.Audit.Write(ev)
		oauthError(w, status, code, desc)
	}
	if r.Method != http.MethodPost || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		refuse(400, "invalid_request", "the request must be a form", "bad_request")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		refuse(400, "invalid_request", "the request cannot be read", "bad_request")
		return
	}
	form := r.PostForm
	if form.Get("grant_type") != "client_credentials" {
		refuse(400, "unsupported_grant_type", "only client_credentials is supported", "unsupported")
		return
	}
	l, why := f.begin(r, s)
	if why != "" {
		refuse(401, "invalid_client", "the client is not known to the service", why)
		return
	}
	id := form.Get("client_id")
	assertion := form.Get("client_assertion")
	if assertion != "" {
		if form.Get("client_assertion_type") != assertionTy {
			refuse(400, "invalid_request", "unsupported assertion type", "bad_request")
			return
		}
		iss, ok := oauth.PeekIssuer(assertion)
		if !ok || (id != "" && id != iss) {
			f.failed(l)
			refuse(401, "invalid_client", "the credential is not valid", "bad_token")
			return
		}
		id = iss
	}
	c, why := f.bind(l, s, id)
	if why != "" {
		f.failed(l)
		refuse(401, "invalid_client", "the credential is not valid", why)
		return
	}
	switch {
	case assertion != "":
		if c.Pub == nil {
			f.failed(l)
			refuse(401, "invalid_client", "the credential is not valid", "bad_token")
			return
		}
		if _, err := oauth.VerifyJWT(assertion, c.Pub, f.now()); err != nil {
			f.failed(l)
			refuse(401, "invalid_client", "the credential is not valid", "bad_token")
			return
		}
	default:
		sec := form.Get("client_secret")
		if c.Secret == nil || subtle.ConstantTimeCompare([]byte(sec), c.Secret) != 1 {
			f.failed(l)
			refuse(401, "invalid_client", "the credential is not valid", "bad_secret")
			return
		}
	}
	ev.Client = c.Client
	if !f.Audit.Healthy() && f.Audit.Write(audit.Event{RequestID: rid, Face: face, Op: "audit-probe", Result: "probe"}) != nil {
		oauthError(w, 503, "temporarily_unavailable", "audit log unavailable")
		return
	}
	tok, exp := f.tokens.Issue(id, f.now())
	ev.Result = "ok"
	if err := f.Audit.Write(ev); err != nil {
		oauthError(w, 503, "temporarily_unavailable", "audit log unavailable")
		return
	}
	n := int(exp.Sub(f.now()).Seconds())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{"token_type": "Bearer", "expires_in": n, "ext_expires_in": n, "access_token": tok})
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

// ---- the operations ----

// kerr is a failure of a call, in the words of the service.
type kerr struct {
	status int
	code   string
	msg    string
	result string
}

func fromOps(e *kmsops.Error) *kerr {
	switch e.Kind {
	case kmsops.Denied:
		return &kerr{403, "Forbidden", e.Msg, e.Result}
	case kmsops.Usage, kmsops.Invalid, kmsops.BadCiphertext:
		return &kerr{400, "BadParameter", e.Msg, e.Result}
	case kmsops.Throttled, kmsops.Busy:
		return &kerr{429, "Throttled", e.Msg, e.Result}
	case kmsops.Locked, kmsops.Unavailable:
		return &kerr{503, "ServiceUnavailable", e.Msg, e.Result}
	}
	return &kerr{500, "InternalServerError", "internal error", e.Result}
}

func bad(result, msg string) *kerr { return &kerr{400, "BadParameter", msg, result} }

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if status == 429 || status == 503 {
		w.Header().Set("Retry-After", "5")
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func (f *Face) challenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", `Bearer authorization="https://`+r.Host+`/`+f.Tenant+`", resource="`+resource+`"`)
}

type call struct {
	f      *Face
	s      *snap
	r      *http.Request
	client string
	body   []byte
	ev     *audit.Event
	svc    *kmsops.Service
	host   string
}

type route struct {
	op      string // the word of the audit line
	method  string
	handler func(*call, string, int) (any, *kerr)
	vers    bool // the name of a version may follow the name of the key
}

func versionID(n int) string { return strconv.FormatInt(int64(n), 16) }

func parseVersion(v string) (int, bool) {
	if v == "" {
		return 0, true
	}
	n, err := strconv.ParseInt(v, 16, 32)
	if err != nil || n < 1 || versionID(int(n)) != strings.TrimLeft(v, "0") {
		return 0, false
	}
	return int(n), true
}

// versionName is the identifier of a version as the service writes it: 32 hexadecimal digits.
func versionName(n int) string {
	s := versionID(n)
	return strings.Repeat("0", 32-len(s)) + s
}

// routeOf reads the path: /keys, /keys/NAME, /keys/NAME/versions, /keys/NAME/VERSION, /keys/NAME/VERSION/OPERATION (or /keys/NAME/OPERATION, or with an empty version), /rng.
func routeOf(r *http.Request) (name, ver string, rt *route) {
	if r.URL.Path == "/rng" {
		return "", "", routes["rng"]
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/keys"), "/") // "" , name, ...
	switch len(parts) {
	case 1: // /keys
		if parts[0] == "" {
			return "", "", routes["list"]
		}
	case 2: // /keys/NAME
		return parts[1], "", routes["get"]
	case 3: // /keys/NAME/versions, /keys/NAME/VERSION
		if parts[2] == "versions" {
			return parts[1], "", routes["versions"]
		}
		if rt, ok := routes[parts[2]]; ok && rt.vers { // the version left out: the latest
			return parts[1], "", rt
		}
		return parts[1], parts[2], routes["get"]
	case 4: // /keys/NAME/VERSION/OPERATION
		if rt, ok := routes[parts[3]]; ok && rt.vers {
			return parts[1], parts[2], rt
		}
	}
	return "", "", nil
}

var routes map[string]*route

func init() {
	routes = map[string]*route{
		"list":      {op: "list_keys", method: "GET", handler: (*call).listKeys},
		"versions":  {op: "list_versions", method: "GET", handler: (*call).listVersions},
		"get":       {op: "get_key", method: "GET", handler: (*call).getKey, vers: false},
		"sign":      {op: "sign", method: "POST", handler: (*call).sign, vers: true},
		"verify":    {op: "verify", method: "POST", handler: (*call).verify, vers: true},
		"encrypt":   {op: "encrypt", method: "POST", handler: (*call).encrypt, vers: true},
		"decrypt":   {op: "decrypt", method: "POST", handler: (*call).decrypt, vers: true},
		"wrapkey":   {op: "wrapkey", method: "POST", handler: (*call).encrypt, vers: true},
		"unwrapkey": {op: "unwrapkey", method: "POST", handler: (*call).decrypt, vers: true},
		"rng":       {op: "rng", method: "POST", handler: (*call).random},
	}
}

func (f *Face) call(w http.ResponseWriter, r *http.Request, s *snap, rid string) {
	name, verStr, rt := routeOf(r)
	ev := audit.Event{RequestID: rid, Face: face, Op: "unknown"}
	if rt != nil {
		ev.Op = rt.op
	}
	refuse := func(status int, code, msg, result string) {
		ev.Result = result
		f.Audit.Write(ev)
		writeError(w, status, code, msg)
	}
	l, why := f.begin(r, s)
	switch why {
	case "throttled_auth":
		refuse(429, "Throttled", "too many refused tokens from this address", why)
		return
	case "":
	default:
		f.challenge(w, r)
		refuse(401, "Unauthorized", "the client is not known to the service", why)
		return
	}
	h := r.Header.Get("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "Bearer ") {
		f.failed(l)
		f.challenge(w, r)
		refuse(401, "Unauthorized", "Request is missing a Bearer token.", "unauthenticated")
		return
	}
	id, ok := f.tokens.Lookup(strings.TrimSpace(h[7:]), f.now())
	if !ok {
		f.failed(l)
		f.challenge(w, r)
		refuse(401, "Unauthorized", "The access token is not valid.", "bad_token")
		return
	}
	cred, why := f.bind(l, s, id)
	if why != "" {
		f.failed(l)
		f.challenge(w, r)
		refuse(401, "Unauthorized", "The access token is not valid.", why)
		return
	}
	ev.Client = cred.Client
	if rt == nil || r.Method != rt.method {
		refuse(404, "NotFound", "the operation is not supported by this service", "unsupported")
		return
	}
	if r.URL.Query().Get("api-version") == "" {
		refuse(400, "BadParameter", "api-version is required", "bad_request")
		return
	}
	var body []byte
	if r.Method == http.MethodPost {
		var err error
		body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			refuse(400, "BadParameter", "the request body is too large or cannot be read", "bad_request")
			return
		}
	}
	ver, ok := parseVersion(verStr)
	if !ok {
		refuse(404, "NotFound", "no such version", "bad_version")
		return
	}
	if !f.Audit.Healthy() && f.Audit.Write(audit.Event{RequestID: rid, Face: face, Op: "audit-probe", Result: "probe"}) != nil {
		writeError(w, 503, "ServiceUnavailable", "audit log unavailable")
		return
	}
	c := &call{f: f, s: s, r: r, client: cred.Client, body: body, ev: &ev, host: r.Host,
		svc: &kmsops.Service{Face: face, Cfg: s.cfg, Tokens: s.tokens, Policy: s.pol, Gate: f.Gate, Macs: f.Macs, Now: f.Now}}
	out, ke := rt.handler(c, name, ver)
	if ke != nil {
		refuse(ke.status, ke.code, ke.msg, ke.result)
		return
	}
	ev.Result = "ok"
	if err := f.Audit.Write(ev); err != nil {
		writeError(w, 503, "ServiceUnavailable", "audit log unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(out)
}

// ---- helpers ----

func (c *call) kid(name string, ver int) string {
	k := "https://" + c.host + "/keys/" + name
	if ver > 0 {
		k += "/" + versionName(ver)
	}
	return k
}

func (c *call) attrs() map[string]any {
	t := c.f.Created.Unix()
	return map[string]any{"enabled": true, "created": t, "updated": t, "recoveryLevel": "Purgeable"}
}

// key finds the key for the client; a key that is not there, not on the face or not granted is one answer.
func (c *call) key(name string) (config.Key, *kerr) {
	k, e := c.svc.Key(c.client, name)
	if e != nil {
		return k, fromOps(e)
	}
	c.ev.Key = name
	return k, nil
}

var b64 = base64.RawURLEncoding

func dec(s string) ([]byte, bool) {
	b, err := b64.DecodeString(strings.TrimRight(s, "="))
	return b, err == nil
}

type req struct {
	Alg    string `json:"alg"`
	Value  string `json:"value"`
	Digest string `json:"digest"`
	AAD    string `json:"aad"`
	Count  int    `json:"count"`
}

func (c *call) req() (req, *kerr) {
	var q req
	if err := json.Unmarshal(c.body, &q); err != nil {
		return q, bad("bad_request", "the request is not valid JSON")
	}
	return q, nil
}

// ---- keys: azurekms GetPublicKey and the signer's preload; the rest are for tools ----

func (c *call) bundle(name string, ver int, k config.Key) (any, *kerr) {
	key := map[string]any{"kid": c.kid(name, ver)}
	switch k.Usage() {
	case config.UsageSignVerify:
		der, ver2, e := c.svc.Public(c.r.Context(), c.client, name, ver)
		if e != nil {
			return nil, fromOps(e)
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, &kerr{500, "InternalServerError", "internal error", "internal_error"}
		}
		ec, err := pub.(*ecdsa.PublicKey).ECDH()
		if err != nil {
			return nil, &kerr{500, "InternalServerError", "internal error", "internal_error"}
		}
		pt := ec.Bytes() // 04 || X || Y
		key = map[string]any{"kid": c.kid(name, ver2), "kty": "EC-HSM", "crv": "P-256", "key_ops": []string{"sign", "verify"}, "x": b64.EncodeToString(pt[1:33]), "y": b64.EncodeToString(pt[33:65])}
	case config.UsageMAC:
		key["kty"], key["key_ops"] = "oct-HSM", []string{"sign", "verify"}
	default:
		key["kty"], key["key_ops"] = "oct-HSM", []string{"encrypt", "decrypt", "wrapKey", "unwrapKey"}
	}
	return map[string]any{"key": key, "attributes": c.attrs()}, nil
}

// getKey serves azurekms GetPublicKey and the preload of CreateSigner: the public key of a signing key, as a JWK.
func (c *call) getKey(name string, ver int) (any, *kerr) {
	k, e := c.key(name)
	if e != nil {
		return nil, e
	}
	if _, oe := c.svc.Describe(c.client, name); oe != nil {
		return nil, fromOps(oe)
	}
	if ver > len(k.Versions) {
		return nil, &kerr{404, "KeyNotFound", "no such version", "bad_version"}
	}
	if ver == 0 && k.Usage() != config.UsageSignVerify {
		ver = len(k.Versions)
	}
	return c.bundle(name, ver, k)
}

func (c *call) listKeys(string, int) (any, *kerr) {
	list, oe := c.svc.List(c.client)
	if oe != nil {
		return nil, fromOps(oe)
	}
	items := []any{}
	for _, n := range list {
		items = append(items, map[string]any{"kid": c.kid(n, 0), "attributes": c.attrs()})
	}
	return map[string]any{"value": items, "nextLink": nil}, nil
}

func (c *call) listVersions(name string, _ int) (any, *kerr) {
	k, e := c.key(name)
	if e != nil {
		return nil, e
	}
	if _, oe := c.svc.Describe(c.client, name); oe != nil {
		return nil, fromOps(oe)
	}
	items := []any{}
	for v := 1; v <= len(k.Versions); v++ {
		items = append(items, map[string]any{"kid": c.kid(name, v), "attributes": c.attrs()})
	}
	return map[string]any{"value": items, "nextLink": nil}, nil
}

// ---- sign and verify: azurekms Signer.Sign (ES256 over a SHA-256 digest; the signature is r||s, 64 bytes); HS256 is the MAC of a symmetric key ----

type ecSig struct{ R, S *big.Int }

func rawSig(der []byte) ([]byte, bool) {
	var s ecSig
	if rest, err := asn1.Unmarshal(der, &s); err != nil || len(rest) != 0 || s.R.BitLen() > 256 || s.S.BitLen() > 256 {
		return nil, false
	}
	out := make([]byte, 64)
	s.R.FillBytes(out[:32])
	s.S.FillBytes(out[32:])
	return out, true
}

func derSig(raw []byte) ([]byte, bool) {
	if len(raw) != 64 {
		return nil, false
	}
	der, err := asn1.Marshal(ecSig{new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])})
	return der, err == nil
}

func (c *call) sign(name string, ver int) (any, *kerr) {
	q, e := c.req()
	if e != nil {
		return nil, e
	}
	if _, e := c.key(name); e != nil {
		return nil, e
	}
	val, ok := dec(q.Value)
	if !ok || len(val) == 0 {
		return nil, bad("bad_request", "value must be base64url")
	}
	switch q.Alg {
	case "ES256":
		sig, ver, oe := c.svc.Sign(c.r.Context(), c.client, name, ver, val)
		if oe != nil {
			return nil, fromOps(oe)
		}
		raw, ok := rawSig(sig)
		if !ok {
			return nil, &kerr{500, "InternalServerError", "internal error", "internal_error"}
		}
		return map[string]any{"kid": c.kid(name, ver), "value": b64.EncodeToString(raw)}, nil
	case "HS256":
		mac, ver, oe := c.svc.MacGenerate(c.r.Context(), c.client, name, ver, val)
		if oe != nil {
			return nil, fromOps(oe)
		}
		return map[string]any{"kid": c.kid(name, ver), "value": b64.EncodeToString(mac)}, nil
	}
	return nil, bad("bad_algorithm", "the algorithm is not supported by this key")
}

func (c *call) verify(name string, ver int) (any, *kerr) {
	q, e := c.req()
	if e != nil {
		return nil, e
	}
	if _, e := c.key(name); e != nil {
		return nil, e
	}
	digest, ok1 := dec(q.Digest)
	val, ok2 := dec(q.Value)
	if !ok1 || !ok2 || len(digest) == 0 || len(val) == 0 {
		return nil, bad("bad_request", "digest and value must be base64url")
	}
	var valid bool
	switch q.Alg {
	case "ES256":
		der, ok := derSig(val)
		if !ok {
			// a signature of the wrong length is one that does not verify
			return map[string]any{"value": false}, nil
		}
		var oe *kmsops.Error
		if valid, oe = c.svc.Verify(c.r.Context(), c.client, name, ver, digest, der); oe != nil {
			return nil, fromOps(oe)
		}
	case "HS256":
		var oe *kmsops.Error
		if valid, oe = c.svc.MacVerify(c.r.Context(), c.client, name, ver, digest, val); oe != nil {
			return nil, fromOps(oe)
		}
	default:
		return nil, bad("bad_algorithm", "the algorithm is not supported by this key")
	}
	return map[string]any{"value": valid}, nil
}

// ---- encrypt, decrypt (and wrapkey, unwrapkey: the same, for the algorithm A256KW): the clients' calls with a symmetric key. The names of the algorithms are those the clients send; the
// cipher is the one of the blob of the service (internal/kmsops), which names the key and the version and authenticates them. ----

func (c *call) algOK(alg string) bool { return alg == "A256GCM" || alg == "A256KW" }

func (c *call) encrypt(name string, ver int) (any, *kerr) {
	q, e := c.req()
	if e != nil {
		return nil, e
	}
	if _, e := c.key(name); e != nil {
		return nil, e
	}
	if !c.algOK(q.Alg) {
		return nil, bad("bad_algorithm", "the algorithm is not supported by this key")
	}
	plain, ok1 := dec(q.Value)
	aad, ok2 := dec(q.AAD)
	if !ok1 || !ok2 || len(plain) == 0 {
		return nil, bad("bad_request", "value and aad must be base64url")
	}
	blob, ver, oe := c.svc.Seal(c.r.Context(), c.client, name, ver, plain, aad, kmsops.AADBytes, maxPlain)
	if oe != nil {
		return nil, fromOps(oe)
	}
	out := map[string]any{"kid": c.kid(name, ver), "value": b64.EncodeToString(blob)}
	if len(aad) > 0 {
		out["aad"] = q.AAD
	}
	return out, nil
}

func (c *call) decrypt(name string, ver int) (any, *kerr) {
	q, e := c.req()
	if e != nil {
		return nil, e
	}
	if _, e := c.key(name); e != nil {
		return nil, e
	}
	if !c.algOK(q.Alg) {
		return nil, bad("bad_algorithm", "the algorithm is not supported by this key")
	}
	blob, ok1 := dec(q.Value)
	aad, ok2 := dec(q.AAD)
	if !ok1 || !ok2 {
		return nil, bad("bad_request", "value and aad must be base64url")
	}
	plain, _, v, oe := c.svc.Open(c.r.Context(), c.client, name, blob, aad, kmsops.AADBytes)
	if oe != nil {
		return nil, fromOps(oe)
	}
	defer kmsops.Wipe(plain)
	return map[string]any{"kid": c.kid(name, v), "value": b64.EncodeToString(plain)}, nil
}

// random: bytes of the operating system's generator, 1 to 128.
func (c *call) random(string, int) (any, *kerr) {
	q, e := c.req()
	if e != nil {
		return nil, e
	}
	if q.Count < 1 || q.Count > maxRandom {
		return nil, bad("bad_request", "count must be from 1 to 128")
	}
	b, oe := c.svc.Random(c.client, q.Count)
	if oe != nil {
		return nil, fromOps(oe)
	}
	return map[string]any{"value": b64.EncodeToString(b)}, nil
}

// LoadCreds reads the secrets and the public keys of the credentials of the clients, by client id.
func LoadCreds(cfg *config.Config) (map[string]Cred, error) {
	creds := map[string]Cred{}
	for _, cl := range cfg.Clients {
		o := cl.OAuth
		if o == nil {
			continue
		}
		c := Cred{Client: cl.Name, ID: o.ClientID, NoCert: o.NoCert}
		if o.SecretFile != "" {
			b, err := backend.ReadSecretFile(o.SecretFile, 256)
			if err != nil {
				return nil, fmt.Errorf("client %s: oauth.secret_file: %w", cl.Name, err)
			}
			c.Secret = []byte(strings.TrimSpace(string(b)))
			if len(c.Secret) < 32 {
				return nil, fmt.Errorf("client %s: the client secret is shorter than 32 bytes", cl.Name)
			}
		} else {
			pub, err := oauth.ReadRSAPublic(o.PublicKeyFile)
			if err != nil {
				return nil, fmt.Errorf("client %s: oauth.public_key_file: %w", cl.Name, err)
			}
			c.Pub = pub
		}
		from, err := (config.SigV4{AllowFrom: o.AllowFrom}).Prefixes()
		if err != nil {
			return nil, fmt.Errorf("client %s: %w", cl.Name, err)
		}
		c.From = from
		creds[o.ClientID] = c
	}
	return creds, nil
}
