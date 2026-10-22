// Package kmsgrpc is the face that speaks the API of a cloud key service the way its gRPC clients do, so that those clients (and the tools built on them) can use keys that stay on
// the token. It carries unary calls only, in the framing of gRPC over HTTP/2, with the messages of the public definition of the service encoded by hand (pb.go): no generated code
// and no gRPC library. What a method does is in internal/kmsops, shared with the other faces; here are the protocol, the names of resources, the authentication of the clients
// (auth.go) and the audit line of each call.
//
// Names here are descriptive. Each method says in its comment which function of the client library go.step.sm/crypto/kms/cloudkms (Apache-2.0) it serves; the wire constants (the
// service and method paths, the field numbers) are those the clients require.
package kmsgrpc

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

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
	face        = "kmsgrpc"
	servicePath = "/google.cloud.kms.v1.KeyManagementService/"
	maxBody     = 128 << 10
	maxPlain    = 64 << 10 // the largest plaintext of the service
	maxRandom   = 1024
)

// gRPC status codes.
const (
	cInvalid   = 3
	cDenied    = 7
	cExhausted = 8
	cUnimpl    = 12
	cInternal  = 13
	cUnavail   = 14
	cUnauth    = 16
)

// Enum values of the definition.
const (
	purposeEncrypt = 1
	purposeSign    = 5
	purposeMAC     = 9
	algSymmetric   = 1
	algECP256      = 12
	algHMAC        = 32
	stateEnabled   = 1
	levelHSM       = 2
)

type snap struct {
	cfg      *config.Config
	tokens   map[string]backend.Token
	pol      *policy.Policy
	identify func(*http.Request) (string, bool)
	creds    map[string]Cred
	names    names
}

// Face is the gRPC face.
type Face struct {
	Audit     *audit.Log
	Gate      *gate.Gate
	Macs      *kmsops.MacCache
	Fails     *peer.Failures
	Created   time.Time
	TokenPath string           // where clients ask for an access token; fixed for the life of the process
	Now       func() time.Time // for tests
	// NoCertificate says that the connection of a request showed no client certificate; nil: judged from the TLS state. For tests.
	NoCertificate func(*http.Request) bool

	gen    generation.Holder[*snap]
	tokens *oauth.Tokens
}

// New makes a face; Reload gives it its first generation.
func New(a *audit.Log, g *gate.Gate, tokenPath string) *Face {
	return &Face{Audit: a, Gate: g, Macs: kmsops.NewMacCache(), Fails: peer.NewFailures(), Created: time.Now(), TokenPath: tokenPath, tokens: oauth.NewTokens()}
}

// Reload replaces the generation for the requests that come after; the returned function waits for the requests of the previous one. The access tokens stay valid, but every request
// is judged again against the credentials of the new generation.
func (f *Face) Reload(cfg *config.Config, tokens map[string]backend.Token, pol *policy.Policy, id func(*http.Request) (string, bool), creds map[string]Cred) func() {
	f.Macs.Clear()
	g := cfg.KMSGRPC
	return f.gen.Set(&snap{cfg: cfg, tokens: tokens, pol: pol, identify: id, creds: creds, names: names{project: g.Project, location: g.Location, keyRing: g.KeyRing}})
}

// Handles: is this request for the face (a call of the service, or the request of a token)?
func (f *Face) Handles(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	return r.URL.Path == f.TokenPath || strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc")
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

func (f *Face) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s, release, ok := f.gen.Acquire()
	if !ok || !s.cfg.KMSGRPC.Enabled {
		http.NotFound(w, r)
		return
	}
	defer release()
	rid := requestID(r)
	w.Header().Set("X-Request-Id", rid)
	if r.URL.Path == f.TokenPath {
		f.token(w, r, s, rid)
		return
	}
	f.call(w, r, s, rid)
}

// login is what is known of a request before its token is looked at.
type login struct {
	client   string // from the certificate; empty when none was shown
	certless bool
	src      netip.Addr
}

// begin names the client of the connection and refuses a certificate-less caller that has failed too often.
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
	// only a request with no certificate is counted and blocked by address: a client that showed a certificate is already known, and a peer must not be able to lock out the clients
	// behind the same address by sending bad tokens
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

// bind checks that the credential may be used by this connection.
func (f *Face) bind(l login, r *http.Request, s *snap, issuer string) (Cred, string) {
	c, ok := s.creds[issuer]
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

// token trades a signed assertion (a JWT of the service account, grant type jwt-bearer) for an access token. For the clients of go.step.sm/crypto/kms/cloudkms this is the exchange that
// the Google client library makes with the token_uri of the service account file before its first call.
func (f *Face) token(w http.ResponseWriter, r *http.Request, s *snap, rid string) {
	ev := audit.Event{RequestID: rid, Face: face, Op: "token"}
	refuse := func(status int, code, desc, result string) {
		ev.Result = result
		f.Audit.Write(ev)
		oauthError(w, status, code, desc)
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		refuse(400, "invalid_request", "the request must be a form", "bad_request")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		refuse(400, "invalid_request", "the request cannot be read", "bad_request")
		return
	}
	if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		refuse(400, "unsupported_grant_type", "only the jwt-bearer grant is supported", "unsupported")
		return
	}
	l, why := f.begin(r, s)
	if why != "" {
		refuse(400, "invalid_client", "the client is not known to the service", why)
		return
	}
	assertion := r.PostForm.Get("assertion")
	issuer, ok := oauth.PeekIssuer(assertion)
	if !ok {
		f.failed(l)
		refuse(400, "invalid_grant", "the assertion is not valid", "bad_token")
		return
	}
	cred, why := f.bind(l, r, s, issuer)
	if why != "" {
		f.failed(l)
		refuse(400, "invalid_grant", "the assertion is not valid", why)
		return
	}
	if _, err := oauth.VerifyJWT(assertion, cred.Key, f.now()); err != nil {
		f.failed(l)
		refuse(400, "invalid_grant", "the assertion is not valid", "bad_token")
		return
	}
	ev.Client = cred.Client
	if !f.Audit.Healthy() && f.Audit.Write(audit.Event{RequestID: rid, Face: face, Op: "audit-probe", Result: "probe"}) != nil {
		oauthError(w, 503, "temporarily_unavailable", "audit log unavailable")
		return
	}
	tok, exp := f.tokens.Issue(issuer, f.now())
	ev.Result = "ok"
	if err := f.Audit.Write(ev); err != nil {
		oauthError(w, 503, "temporarily_unavailable", "audit log unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": int(exp.Sub(f.now()).Seconds())})
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

// ---- gRPC ----

// kerr is a failure of a call, in the words of gRPC.
type kerr struct {
	code   int
	msg    string
	result string
}

func fromOps(e *kmsops.Error) *kerr {
	k := &kerr{msg: e.Msg, result: e.Result}
	switch e.Kind {
	case kmsops.Denied:
		k.code = cDenied
	case kmsops.Usage, kmsops.Invalid, kmsops.BadCiphertext:
		k.code = cInvalid
	case kmsops.Throttled, kmsops.Busy:
		k.code = cExhausted
	case kmsops.Locked, kmsops.Unavailable:
		k.code = cUnavail
	default:
		k.code = cInternal
		k.msg = "internal error"
	}
	return k
}

func invalid(result, msg string) *kerr { return &kerr{cInvalid, msg, result} }

// grpcFail ends a call with a status and no message (the form "trailers only").
func grpcFail(w http.ResponseWriter, code int, msg string) {
	h := w.Header()
	h.Set("Content-Type", "application/grpc")
	h.Set("Grpc-Status", itoa(code))
	h.Set("Grpc-Message", msg)
	w.WriteHeader(200)
}

func grpcReply(w http.ResponseWriter, msg []byte) {
	h := w.Header()
	h.Set("Content-Type", "application/grpc")
	w.WriteHeader(200)
	frame := make([]byte, 5, 5+len(msg))
	binary.BigEndian.PutUint32(frame[1:], uint32(len(msg))) // #nosec G115 -- a reply is small
	w.Write(append(frame, msg...))
	h.Set(http.TrailerPrefix+"Grpc-Status", "0")
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoa(n/10) + string(rune('0'+n%10))
}

// bearer takes the access token out of the Authorization header.
func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:]), true
	}
	return "", false
}

func (f *Face) call(w http.ResponseWriter, r *http.Request, s *snap, rid string) {
	method := strings.TrimPrefix(r.URL.Path, servicePath)
	h, known := handlers[method]
	ev := audit.Event{RequestID: rid, Face: face, Op: strings.ToLower(method)}
	if !known {
		ev.Op = "unknown"
	}
	refuse := func(code int, msg, result string) {
		ev.Result = result
		f.Audit.Write(ev)
		grpcFail(w, code, msg)
	}
	if r.ProtoMajor != 2 || !strings.HasPrefix(r.URL.Path, servicePath) {
		refuse(cUnimpl, "unknown method", "unsupported")
		return
	}
	l, why := f.begin(r, s)
	switch why {
	case "throttled_auth":
		refuse(cExhausted, "too many refused tokens from this address", why)
		return
	case "":
	default:
		refuse(cUnauth, "the client is not known to the service", why)
		return
	}
	tok, ok := bearer(r)
	if !ok {
		f.failed(l)
		refuse(cUnauth, "no access token", "unauthenticated")
		return
	}
	issuer, ok := f.issuerOf(tok, s)
	if !ok {
		f.failed(l)
		refuse(cUnauth, "the access token is not valid", "bad_token")
		return
	}
	cred, why := f.bind(l, r, s, issuer)
	if why != "" {
		f.failed(l)
		refuse(cUnauth, "the access token is not valid", why)
		return
	}
	ev.Client = cred.Client
	if !known {
		refuse(cUnimpl, "the method is not supported by this service", "unsupported")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil || len(body) < 5 || body[0] != 0 || int(binary.BigEndian.Uint32(body[1:5])) != len(body)-5 {
		refuse(cInvalid, "the request is not a single uncompressed message", "bad_request")
		return
	}
	req, ok := parse(body[5:])
	if !ok {
		refuse(cInvalid, "the request cannot be read", "bad_request")
		return
	}
	if !f.Audit.Healthy() && f.Audit.Write(audit.Event{RequestID: rid, Face: face, Op: "audit-probe", Result: "probe"}) != nil {
		grpcFail(w, cUnavail, "audit log unavailable")
		return
	}
	c := &call{f: f, s: s, ctx: r.Context(), client: cred.Client, req: req, ev: &ev, svc: &kmsops.Service{Face: face, Cfg: s.cfg, Tokens: s.tokens, Policy: s.pol, Gate: f.Gate, Macs: f.Macs, Now: f.Now}}
	out, ke := h(c)
	if ke != nil {
		refuse(ke.code, ke.msg, ke.result)
		return
	}
	ev.Result = "ok"
	if err := f.Audit.Write(ev); err != nil {
		grpcFail(w, cUnavail, "audit log unavailable")
		return
	}
	grpcReply(w, out)
}

// issuerOf gives the issuer of a bearer: an access token this service gave, or a JWT signed by the service account itself (the client libraries use the latter when the call is made
// without the token exchange).
func (f *Face) issuerOf(tok string, s *snap) (string, bool) {
	if strings.HasPrefix(tok, "hg.") {
		return f.tokens.Lookup(tok, f.now())
	}
	issuer, ok := oauth.PeekIssuer(tok)
	if !ok {
		return "", false
	}
	c, ok := s.creds[issuer]
	if !ok {
		return "", false
	}
	if _, err := oauth.VerifyJWT(tok, c.Key, f.now()); err != nil {
		return "", false
	}
	return issuer, true
}

func requestID(*http.Request) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b)
}

// ---- the methods ----

type call struct {
	f      *Face
	s      *snap
	ctx    context.Context
	client string
	req    *reader
	ev     *audit.Event
	svc    *kmsops.Service
}

var handlers = map[string]func(*call) ([]byte, *kerr){
	"GetPublicKey":          (*call).getPublicKey,
	"AsymmetricSign":        (*call).asymmetricSign,
	"Encrypt":               (*call).encrypt,
	"Decrypt":               (*call).decrypt,
	"MacSign":               (*call).macSign,
	"MacVerify":             (*call).macVerify,
	"GetCryptoKey":          (*call).getCryptoKey,
	"GetCryptoKeyVersion":   (*call).getCryptoKeyVersion,
	"ListCryptoKeys":        (*call).listCryptoKeys,
	"ListCryptoKeyVersions": (*call).listCryptoKeyVersions,
	"GenerateRandomBytes":   (*call).generateRandomBytes,
}

// key reads the name of a key or of a version of a key, and finds the key for the client. Names of another project, location or ring are the same as a key that is not there.
func (c *call) key(name string) (key string, ver int, hasVer bool, e *kerr) {
	key, ver, hasVer, ok := c.s.names.parseKey(name)
	if !ok {
		return "", 0, false, &kerr{cDenied, "the key does not exist or the client has no right to it", "forbidden"}
	}
	if _, oe := c.svc.Key(c.client, key); oe != nil {
		return "", 0, false, fromOps(oe)
	}
	c.ev.Key = key
	return key, ver, hasVer, nil
}

// crcOK: a checksum that the client sent must match the bytes it sent along with it.
func crcOK(r *reader, n protowire.Number, data []byte) bool {
	v, present := r.int64Value(n)
	return !present || v == crc32c(data)
}

func wrongCRC(what string) *kerr {
	return invalid("bad_checksum", "the checksum of "+what+" does not match")
}

// getPublicKey serves cloudkms GetPublicKey and CreateSigner (which reads the public key once). Only a signing key has a public key.
func (c *call) getPublicKey() ([]byte, *kerr) {
	key, ver, _, e := c.key(c.req.str(1))
	if e != nil {
		return nil, e
	}
	der, ver, oe := c.svc.Public(c.ctx, c.client, key, ver)
	if oe != nil {
		return nil, fromOps(oe)
	}
	p := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	w := &writer{}
	w.str(1, string(p)).u64(2, algECP256).int64Value(3, crc32c(p)).str(4, c.s.names.version(key, ver)).u64(5, levelHSM)
	return w.b, nil
}

// asymmetricSign serves the Sign of the signer that cloudkms CreateSigner returns: ECDSA P-256 over a SHA-256 digest, made on the token.
func (c *call) asymmetricSign() ([]byte, *kerr) {
	key, ver, _, e := c.key(c.req.str(1))
	if e != nil {
		return nil, e
	}
	d, ok := c.req.msg(3)
	if !ok {
		return nil, invalid("bad_request", "a SHA-256 digest is required")
	}
	digest := d.raw(1)
	if len(digest) != 32 || d.has(2) || d.has(3) {
		return nil, invalid("bad_request", "a SHA-256 digest is required")
	}
	if !crcOK(c.req, 4, digest) {
		return nil, wrongCRC("the digest")
	}
	sig, ver, oe := c.svc.Sign(c.ctx, c.client, key, ver, digest)
	if oe != nil {
		return nil, fromOps(oe)
	}
	w := &writer{}
	w.bytes(1, sig).int64Value(2, crc32c(sig)).boolean(3, true).str(4, c.s.names.version(key, ver)).u64(6, levelHSM)
	return w.b, nil
}

// encrypt serves the encryption a client library makes with a symmetric key (cloudkms has no function of its own for it; a client library does it). The additional authenticated data
// is passed as it is.
func (c *call) encrypt() ([]byte, *kerr) {
	key, ver, _, e := c.key(c.req.str(1))
	if e != nil {
		return nil, e
	}
	plain, aad := c.req.raw(2), c.req.raw(3)
	if !crcOK(c.req, 7, plain) {
		return nil, wrongCRC("the plaintext")
	}
	if !crcOK(c.req, 8, aad) {
		return nil, wrongCRC("the additional authenticated data")
	}
	blob, ver, oe := c.svc.Seal(c.ctx, c.client, key, ver, plain, aad, kmsops.AADBytes, maxPlain)
	if oe != nil {
		return nil, fromOps(oe)
	}
	w := &writer{}
	w.str(1, c.s.names.version(key, ver)).bytes(2, blob).int64Value(4, crc32c(blob)).boolean(5, true).boolean(6, true).u64(7, levelHSM)
	return w.b, nil
}

// decrypt serves the decryption of a symmetric key. The name is that of the key: the version is in the ciphertext.
func (c *call) decrypt() ([]byte, *kerr) {
	key, _, hasVer, e := c.key(c.req.str(1))
	if e != nil {
		return nil, e
	}
	if hasVer {
		return nil, invalid("bad_request", "the name of a key is needed, not of a version")
	}
	blob, aad := c.req.raw(2), c.req.raw(3)
	if !crcOK(c.req, 5, blob) {
		return nil, wrongCRC("the ciphertext")
	}
	if !crcOK(c.req, 6, aad) {
		return nil, wrongCRC("the additional authenticated data")
	}
	plain, _, ver, oe := c.svc.Open(c.ctx, c.client, key, blob, aad, kmsops.AADBytes)
	if oe != nil {
		return nil, fromOps(oe)
	}
	defer kmsops.Wipe(plain)
	w := &writer{}
	w.bytes(1, plain).int64Value(2, crc32c(plain)).boolean(3, ver == len(c.s.cfg.Keys[key].Versions)).u64(4, levelHSM)
	return w.b, nil
}

// macSign and macVerify serve the MAC calls of a client library (HMAC-SHA-256 with a key derived on the token).
func (c *call) macSign() ([]byte, *kerr) {
	key, ver, _, e := c.key(c.req.str(1))
	if e != nil {
		return nil, e
	}
	data := c.req.raw(2)
	if !crcOK(c.req, 3, data) {
		return nil, wrongCRC("the data")
	}
	mac, ver, oe := c.svc.MacGenerate(c.ctx, c.client, key, ver, data)
	if oe != nil {
		return nil, fromOps(oe)
	}
	w := &writer{}
	w.str(1, c.s.names.version(key, ver)).bytes(2, mac).int64Value(3, crc32c(mac)).boolean(4, true).u64(5, levelHSM)
	return w.b, nil
}

func (c *call) macVerify() ([]byte, *kerr) {
	key, ver, hasVer, e := c.key(c.req.str(1))
	if e != nil {
		return nil, e
	}
	data, mac := c.req.raw(2), c.req.raw(4)
	if !crcOK(c.req, 3, data) {
		return nil, wrongCRC("the data")
	}
	if !crcOK(c.req, 5, mac) {
		return nil, wrongCRC("the MAC")
	}
	ok, oe := c.svc.MacVerify(c.ctx, c.client, key, ver, data, mac)
	if oe != nil {
		return nil, fromOps(oe)
	}
	name := c.s.names.key(key)
	if hasVer {
		name = c.s.names.version(key, ver)
	}
	w := &writer{}
	w.str(1, name).boolean(2, ok).boolean(3, true).boolean(4, true).boolean(5, true).u64(6, levelHSM)
	return w.b, nil
}

// ---- metadata: cloudkms uses these to find a key (GetPublicKey of a version name is the usual path; the rest are for tools) ----

func purposeOf(usage string) (purpose, alg uint64) {
	switch usage {
	case config.UsageSignVerify:
		return purposeSign, algECP256
	case config.UsageMAC:
		return purposeMAC, algHMAC
	}
	return purposeEncrypt, algSymmetric
}

func (c *call) versionMsg(key string, ver int, alg uint64) *writer {
	w := &writer{}
	w.str(1, c.s.names.version(key, ver)).u64(3, stateEnabled)
	w.timestamp(4, c.f.Created.Unix(), 0).u64(7, levelHSM).u64(10, alg)
	return w
}

func (c *call) keyMsg(key string, k config.Key) *writer {
	purpose, alg := purposeOf(k.Usage())
	w := &writer{}
	w.str(1, c.s.names.key(key))
	if purpose == purposeEncrypt { // only a key that encrypts has a primary version
		w.msg(2, c.versionMsg(key, len(k.Versions), alg))
	}
	w.u64(3, purpose).timestamp(5, c.f.Created.Unix(), 0)
	w.msg(11, (&writer{}).u64(1, levelHSM).u64(3, alg))
	return w
}

func (c *call) getCryptoKey() ([]byte, *kerr) {
	key, _, hasVer, e := c.key(c.req.str(1))
	if e != nil {
		return nil, e
	}
	if hasVer {
		return nil, invalid("bad_request", "the name of a key is needed, not of a version")
	}
	if _, oe := c.svc.Describe(c.client, key); oe != nil {
		return nil, fromOps(oe)
	}
	return c.keyMsg(key, c.s.cfg.Keys[key]).b, nil
}

func (c *call) getCryptoKeyVersion() ([]byte, *kerr) {
	key, ver, hasVer, e := c.key(c.req.str(1))
	if e != nil {
		return nil, e
	}
	k := c.s.cfg.Keys[key]
	if !hasVer || ver > len(k.Versions) {
		return nil, invalid("bad_version", "the name of an existing version of a key is needed")
	}
	if _, oe := c.svc.Describe(c.client, key); oe != nil {
		return nil, fromOps(oe)
	}
	_, alg := purposeOf(k.Usage())
	return c.versionMsg(key, ver, alg).b, nil
}

func (c *call) listCryptoKeys() ([]byte, *kerr) {
	if !c.s.names.isRing(c.req.str(1)) {
		return nil, &kerr{cDenied, "the key ring does not exist or the client has no right to it", "forbidden"}
	}
	list, oe := c.svc.List(c.client)
	if oe != nil {
		return nil, fromOps(oe)
	}
	w := &writer{}
	for _, name := range list {
		w.msg(1, c.keyMsg(name, c.s.cfg.Keys[name]))
	}
	w.u64(3, uint64(len(list)))
	return w.b, nil
}

func (c *call) listCryptoKeyVersions() ([]byte, *kerr) {
	key, _, hasVer, e := c.key(c.req.str(1))
	if e != nil {
		return nil, e
	}
	if hasVer {
		return nil, invalid("bad_request", "the name of a key is needed, not of a version")
	}
	if _, oe := c.svc.Describe(c.client, key); oe != nil {
		return nil, fromOps(oe)
	}
	k := c.s.cfg.Keys[key]
	_, alg := purposeOf(k.Usage())
	w := &writer{}
	for v := 1; v <= len(k.Versions); v++ {
		w.msg(1, c.versionMsg(key, v, alg))
	}
	w.u64(3, uint64(len(k.Versions)))
	return w.b, nil
}

// generateRandomBytes: random bytes of the operating system, 1 to 1024.
func (c *call) generateRandomBytes() ([]byte, *kerr) {
	if !c.s.names.isLocation(c.req.str(1)) {
		return nil, &kerr{cDenied, "the location does not exist or the client has no right to it", "forbidden"}
	}
	n := int(int32(c.req.u64(2))) // #nosec G115 -- an int32 field
	if n < 1 || n > maxRandom {
		return nil, invalid("bad_request", "length_bytes must be from 1 to 1024")
	}
	b, oe := c.svc.Random(c.client, n)
	if oe != nil {
		return nil, fromOps(oe)
	}
	w := &writer{}
	w.bytes(1, b).int64Value(3, crc32c(b))
	return w.b, nil
}
