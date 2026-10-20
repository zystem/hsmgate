// Package kmsjson is the second face of the service: a subset of the JSON API that cloud key services of this kind speak, enough for a client to fetch the public key of a key that
// stays on the token (GetPublicKey, DescribeKey, ListKeys, ListAliases) and to have the token do ECDH with a public key of its own choice (DeriveSharedSecret). The client then
// seals and opens by itself; the service never sees a data key. The names in this package are descriptive of the API shape; the service is not affiliated with the makers of any
// cloud service whose clients can talk to it, and the wire constants (X-Amz-Target, "TrentService.", the content type, error type names) are those the clients require.
//
// Authentication is two-fold, both required: the client certificate of the TLS connection (as for the Transit face) and a signature of the request (package sigv4) with the
// credential of the same client. Authorisation is the policy of the service: a key is visible to a client with any grant on it, and DeriveSharedSecret needs the right "derive".
// A key must have kmsjson: true; since this face has no context, it can only be a key in "fixed" mode (config.Validate).
package kmsjson

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zystem/hsmgate/internal/audit"
	"github.com/zystem/hsmgate/internal/backend"
	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/gate"
	"github.com/zystem/hsmgate/internal/keyops"
	"github.com/zystem/hsmgate/internal/policy"
	"github.com/zystem/hsmgate/internal/sigv4"
)

const (
	face        = "kmsjson"
	targetStart = "TrentService."
	contentType = "application/x-amz-json-1.1"
	maxBody     = 64 << 10
	keySpec     = "ECC_NIST_P256"
	account     = "000000000000"
)

// Cred is the credential of a client: the secret of an access key.
type Cred struct {
	Client string
	Secret []byte
	// NoCert: the client may call without a client certificate. From: the addresses the credential may be used from (empty: any).
	NoCert bool
	From   []netip.Prefix
}

type Face struct {
	Cfg    *config.Config
	Tokens map[string]backend.Token
	Policy *policy.Policy
	Audit  *audit.Log
	// Identify names the client of the TLS connection. ok with an empty name means "no certificate" (development mode on a loopback address): the client is then the one of the credential.
	Identify func(*http.Request) (client string, ok bool)
	Creds    map[string]Cred // by access key id
	Gate     *gate.Gate
	Created  time.Time
	Now      func() time.Time // for tests
	// NoCertificate says that the connection of a request showed no client certificate; nil: judged from the TLS state. For tests.
	NoCertificate func(*http.Request) bool
	// MacKeys keeps derived MAC keys for kmsjson.mac_cache_seconds; shared by the generations.
	MacKeys *macCache
	// Fails counts the refused signatures by the address of the peer; created by the first request, shared by the generations.
	Fails *Failures

	mu    sync.RWMutex
	track *tracker
}

type tracker struct{ wg sync.WaitGroup }

// Reload replaces the generation for the requests that come after; the returned function waits for the requests of the previous one (as in the Transit face).
func (f *Face) Reload(cfg *config.Config, tokens map[string]backend.Token, pol *policy.Policy, id func(*http.Request) (string, bool), creds map[string]Cred) (waitOld func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	old := f.track
	f.Cfg, f.Tokens, f.Policy, f.Identify, f.Creds = cfg, tokens, pol, id, creds
	f.track = &tracker{}
	if old == nil {
		return func() {}
	}
	return old.wg.Wait
}

func (f *Face) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.RLock()
	missing := f.track == nil
	f.mu.RUnlock()
	if missing {
		f.mu.Lock()
		if f.track == nil {
			f.track = &tracker{}
		}
		f.mu.Unlock()
	}
	f.mu.RLock()
	g := &Face{Cfg: f.Cfg, Tokens: f.Tokens, Policy: f.Policy, Audit: f.Audit, Identify: f.Identify, Creds: f.Creds, Gate: f.Gate, Created: f.Created, Now: f.Now, NoCertificate: f.NoCertificate, Fails: f.Fails, MacKeys: f.MacKeys}
	t := f.track
	t.wg.Add(1) // under the read lock, as in the Transit face
	f.mu.RUnlock()
	defer t.wg.Done()
	g.serve(w, r)
}

// IsKMSJSON: does the request look like a call of this face? The server uses it to choose between the faces.
func IsKMSJSON(r *http.Request) bool {
	return r.Method == http.MethodPost && strings.HasPrefix(r.Header.Get("X-Amz-Target"), targetStart)
}

func (f *Face) noCertificate(r *http.Request) bool {
	if f.NoCertificate != nil {
		return f.NoCertificate(r)
	}
	return r.TLS != nil && len(r.TLS.PeerCertificates) == 0
}

// peerAddr is the address of the TCP peer; a header is never believed.
func peerAddr(r *http.Request) netip.Addr {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		h = r.RemoteAddr
	}
	a, err := netip.ParseAddr(h)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

func fromAllowed(from []netip.Prefix, a netip.Addr) bool {
	for _, p := range from {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (f *Face) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *Face) serve(w http.ResponseWriter, r *http.Request) {
	rid := requestID(r)
	w.Header().Set("X-Request-Id", rid)
	w.Header().Set("x-amzn-RequestId", rid)
	op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), targetStart)
	ev := audit.Event{RequestID: rid, Face: face, Op: strings.ToLower(op)}
	refuse := func(status int, typ, msg, result string, retry bool) {
		ev.Result = result
		f.Audit.Write(ev)
		fail(w, status, typ, msg, retry)
	}
	if !f.Cfg.KMSJSON.Enabled || r.URL.Path != "/" || !IsKMSJSON(r) {
		fail(w, 404, "UnknownOperationException", "unknown operation", false)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		refuse(400, "ValidationException", "the request body is too large or cannot be read", "bad_request", false)
		return
	}

	// who: the certificate, then the signature, and they must agree. A request with no certificate at all is judged after the signature: only a credential marked no_cert may be used so.
	src := peerAddr(r)
	client, ok := f.Identify(r)
	certless := false
	if !ok {
		if !f.noCertificate(r) {
			refuse(403, "AccessDeniedException", "the client is not known to the service", "unauthenticated", false)
			return
		}
		certless, client = true, ""
		// only a request with no certificate is counted and blocked by address: a client that showed a certificate is already known, and a peer must not be able to lock out
		// the clients behind the same address (a node, a NAT) by sending bad signatures
		if f.Fails.Blocked(src, f.now()) {
			w.Header().Set("Retry-After", "60")
			refuse(400, "ThrottlingException", "too many refused signatures from this address", "throttled_auth", true)
			return
		}
	}
	count := func() {
		if certless {
			f.Fails.Add(src, f.now())
		}
	}
	v := &sigv4.Verifier{Region: f.Cfg.KMSJSON.Region, Service: "kms", Now: f.Now, Secrets: func(akid string) ([]byte, bool) {
		c, ok := f.Creds[akid]
		return c.Secret, ok
	}}
	akid, err := v.Verify(r, body)
	if err != nil {
		typ, result := "InvalidSignatureException", "bad_signature"
		switch {
		case errors.Is(err, sigv4.ErrMissing):
			typ, result = "MissingAuthenticationTokenException", "unsigned"
		case errors.Is(err, sigv4.ErrUnknown):
			typ, result = "UnrecognizedClientException", "unknown_access_key"
		case errors.Is(err, sigv4.ErrMalformed):
			typ, result = "IncompleteSignatureException", "malformed_signature"
		}
		count()
		refuse(400, typ, err.Error(), result, false)
		return
	}
	cred := f.Creds[akid]
	if certless && !cred.NoCert {
		count()
		refuse(403, "AccessDeniedException", "the client is not known to the service", "unauthenticated", false)
		return
	}
	if len(cred.From) > 0 && !fromAllowed(cred.From, src) {
		count()
		refuse(403, "AccessDeniedException", "the credential may not be used from this address", "address_refused", false)
		return
	}
	if client != "" && client != cred.Client {
		refuse(403, "AccessDeniedException", "the credential does not belong to the client certificate", "credential_mismatch", false)
		return
	}
	client = cred.Client
	ev.Client = client
	if !f.Audit.Healthy() && f.Audit.Write(audit.Event{RequestID: rid, Face: face, Op: "audit-probe", Result: "probe"}) != nil {
		w.Header().Set("Retry-After", "5")
		fail(w, 500, "KMSInternalException", "audit log unavailable", true)
		return
	}
	succeed := func(payload any) {
		ev.Result = "ok"
		if err := f.Audit.Write(ev); err != nil {
			w.Header().Set("Retry-After", "5")
			fail(w, 500, "KMSInternalException", "audit log unavailable", true)
			return
		}
		reply(w, 200, payload)
	}

	switch {
	case isCryptoOp(op):
		(&call{f: f, w: w, r: r, client: client, ev: &ev, refuse: refuse, succeed: succeed}).crypto(op, body)
		return
	}
	switch op {
	case "GetPublicKey", "DescribeKey", "DeriveSharedSecret":
	case "ListKeys", "ListAliases":
		if f.Policy.CheckList(client) != policy.Allow {
			refuse(400, "ThrottlingException", "rate limit exceeded", "throttled", true)
			return
		}
		f.list(op, client, succeed)
		return
	default:
		refuse(400, "UnsupportedOperationException", "the operation is not supported by this service", "unsupported", false)
		return
	}

	var req struct {
		KeyID                 string          `json:"KeyId"`
		KeyAgreementAlgorithm string          `json:"KeyAgreementAlgorithm"`
		PublicKey             string          `json:"PublicKey"`
		DryRun                bool            `json:"DryRun"`
		Recipient             json.RawMessage `json:"Recipient"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		refuse(400, "SerializationException", "the request is not valid JSON", "bad_request", false)
		return
	}
	name, ver, found := f.resolve(req.KeyID)
	if !found || !f.Policy.Allowed(client, name) {
		ev.Key = ""
		// a key that does not exist and a key the client may not see get the same answer
		refuse(400, "AccessDeniedException", "the key does not exist or the client has no right to it", "forbidden", false)
		return
	}
	ev.Key = name
	key := f.Cfg.Keys[name]
	if ver == 0 {
		ver = len(key.Versions)
	}
	version := key.Versions[ver-1]

	if key.Usage() == config.UsageEncryptDecrypt || key.Usage() == config.UsageMAC {
		switch op {
		case "DescribeKey":
			if f.Policy.CheckMeta(client, name) != policy.Allow {
				refuse(400, "ThrottlingException", "rate limit exceeded", "throttled", true)
				return
			}
			succeed(map[string]any{"KeyMetadata": f.metadata(name, ver, key)})
		case "GetPublicKey":
			refuse(400, "UnsupportedOperationException", "the key is a symmetric key: it has no public key", "unsupported", false)
		default:
			refuse(400, "InvalidKeyUsageException", usageErrText, "bad_usage", false)
		}
		return
	}
	if key.Usage() == config.UsageSignVerify && op == "DeriveSharedSecret" {
		refuse(400, "InvalidKeyUsageException", usageErrText, "bad_usage", false)
		return
	}
	if op != "DeriveSharedSecret" { // public information: no token operation of its own, a small budget
		if f.Policy.CheckMeta(client, name) != policy.Allow {
			refuse(400, "ThrottlingException", "rate limit exceeded", "throttled", true)
			return
		}
		release, ok := f.Gate.Take(r.Context())
		if !ok {
			refuse(400, "ThrottlingException", "the service is busy", "busy", true)
			return
		}
		defer release()
		point, err := keyops.PointOf(f.Tokens, version)
		if err != nil {
			f.tokenFailure(refuse, err)
			return
		}
		der := spki(point)
		if op == "GetPublicKey" {
			out := map[string]any{"KeyId": f.arn(name), "PublicKey": base64.StdEncoding.EncodeToString(der), "KeySpec": keySpec, "CustomerMasterKeySpec": keySpec,
				"KeyUsage": "KEY_AGREEMENT", "KeyAgreementAlgorithms": []string{"ECDH"}}
			if key.Usage() == config.UsageSignVerify {
				delete(out, "KeyAgreementAlgorithms")
				out["KeyUsage"], out["SigningAlgorithms"] = "SIGN_VERIFY", []string{"ECDSA_SHA_256"}
			}
			succeed(out)
			return
		}
		succeed(map[string]any{"KeyMetadata": f.metadata(name, ver, key)})
		return
	}

	// DeriveSharedSecret
	switch f.Policy.Check(client, name, "derive") {
	case policy.Forbidden:
		refuse(400, "AccessDeniedException", "the client has no right to derive with this key", "forbidden", false)
		return
	case policy.Throttled:
		w.Header().Set("Retry-After", "5")
		refuse(400, "ThrottlingException", "rate limit exceeded", "throttled", true)
		return
	}
	if req.KeyAgreementAlgorithm != "ECDH" {
		refuse(400, "ValidationException", "KeyAgreementAlgorithm must be ECDH", "bad_request", false)
		return
	}
	if len(req.Recipient) > 0 && string(req.Recipient) != "null" {
		refuse(400, "ValidationException", "Recipient (an attestation document) is not supported", "bad_request", false)
		return
	}
	der, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(der) == 0 || len(der) > 8192 {
		refuse(400, "ValidationException", "PublicKey must be a base64 DER SubjectPublicKeyInfo of at most 8192 bytes", "bad_request", false)
		return
	}
	peer, err := peerPoint(der)
	if err != nil {
		refuse(400, "ValidationException", err.Error(), "bad_request", false)
		return
	}
	sum := sha256.Sum256(peer)
	ev.Context = "peer=" + hex.EncodeToString(sum[:6]) // public by nature; ties a line of the log to the key of the caller without keeping it
	if req.DryRun {
		refuse(400, "DryRunOperationException", "the request would have succeeded, but the DryRun option is set", "dry_run", false)
		return
	}
	release, ok := f.Gate.Take(r.Context())
	if !ok {
		refuse(400, "ThrottlingException", "the service is busy", "busy", true)
		return
	}
	defer release()
	z, err := keyops.Derive(f.Tokens, version, peer)
	if err != nil {
		f.tokenFailure(refuse, err)
		return
	}
	defer func() {
		for i := range z {
			z[i] = 0
		}
	}()
	succeed(map[string]any{"KeyId": f.arn(name), "KeyAgreementAlgorithm": "ECDH", "SharedSecret": base64.StdEncoding.EncodeToString(z)})
}

func (f *Face) tokenFailure(refuse func(int, string, string, string, bool), err error) {
	switch {
	case errors.Is(err, backend.ErrLocked):
		refuse(500, "KeyUnavailableException", "the token is locked", "locked", true)
	case errors.Is(err, backend.ErrUnavailable):
		refuse(500, "KeyUnavailableException", "the token is not available", "unavailable", true)
	default:
		refuse(500, "KMSInternalException", "internal error", "internal_error", true)
	}
}

// resolve reads a KeyId: the name, alias/name, an identifier of our form (arn:hsmgate:kms:REGION:ACCOUNT:key/name or .../alias/name); "@N" after the name selects version N (an extension: the
// protocol has no version), else the latest. found is false for a key that is not enabled for this face.
func (f *Face) resolve(id string) (name string, version int, found bool) {
	s := id
	if strings.HasPrefix(s, "arn:") {
		if i := strings.LastIndex(s, ":key/"); i >= 0 {
			s = s[i+len(":key/"):]
		} else if i := strings.LastIndex(s, ":alias/"); i >= 0 {
			s = s[i+len(":alias/"):]
		} else {
			return "", 0, false
		}
	}
	s = strings.TrimPrefix(s, "alias/")
	if i := strings.LastIndex(s, "@"); i >= 0 {
		n, err := strconv.Atoi(s[i+1:])
		if err != nil || n < 1 {
			return "", 0, false
		}
		version, s = n, s[:i]
	}
	k, known := f.Cfg.Keys[s]
	if !known || !k.KMSJSON || version > len(k.Versions) {
		return "", 0, false
	}
	return s, version, true
}

func (f *Face) arn(name string) string {
	return "arn:hsmgate:kms:" + f.Cfg.KMSJSON.Region + ":" + account + ":key/" + name
}

func (f *Face) metadata(name string, ver int, k config.Key) map[string]any {
	created := float64(f.Created.Unix())
	state := "Enabled"
	if k.Usage() == config.UsageMAC {
		return map[string]any{"KeyId": name, "Arn": f.arn(name), "CreationDate": created, "Enabled": true, "Description": "key " + name + " of the key service",
			"KeyUsage": "GENERATE_VERIFY_MAC", "KeyState": state, "KeySpec": "HMAC_256", "CustomerMasterKeySpec": "HMAC_256", "MacAlgorithms": []string{"HMAC_SHA_256"},
			"KeyManager": "CUSTOMER", "MultiRegion": false, "HsmgateVersion": ver, "HsmgateLatestVersion": len(k.Versions)}
	}
	if k.Usage() == config.UsageSignVerify {
		return map[string]any{"KeyId": name, "Arn": f.arn(name), "CreationDate": created, "Enabled": true, "Description": "key " + name + " of the key service",
			"KeyUsage": "SIGN_VERIFY", "KeyState": state, "KeySpec": keySpec, "CustomerMasterKeySpec": keySpec, "SigningAlgorithms": []string{"ECDSA_SHA_256"},
			"KeyManager": "CUSTOMER", "MultiRegion": false, "HsmgateVersion": ver, "HsmgateLatestVersion": len(k.Versions)}
	}
	if k.Usage() == config.UsageEncryptDecrypt {
		return map[string]any{"KeyId": name, "Arn": f.arn(name), "CreationDate": created, "Enabled": true, "Description": "key " + name + " of the key service",
			"KeyUsage": "ENCRYPT_DECRYPT", "KeyState": state, "KeySpec": "SYMMETRIC_DEFAULT", "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT", "EncryptionAlgorithms": []string{algorithm},
			"KeyManager": "CUSTOMER", "MultiRegion": false, "HsmgateVersion": ver, "HsmgateLatestVersion": len(k.Versions)}
	}
	return map[string]any{"KeyId": name, "Arn": f.arn(name), "CreationDate": created, "Enabled": true, "Description": "key " + name + " of the key service",
		"KeyUsage": "KEY_AGREEMENT", "KeyState": state, "KeySpec": keySpec, "CustomerMasterKeySpec": keySpec, "KeyAgreementAlgorithms": []string{"ECDH"},
		"KeyManager": "CUSTOMER", "MultiRegion": false, "HsmgateVersion": ver, "HsmgateLatestVersion": len(k.Versions)}
}

func (f *Face) list(op, client string, succeed func(any)) {
	var names []string
	for n, k := range f.Cfg.Keys {
		if k.KMSJSON && f.Policy.Allowed(client, n) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	if op == "ListKeys" {
		keys := []map[string]string{}
		for _, n := range names {
			keys = append(keys, map[string]string{"KeyId": n, "KeyArn": f.arn(n)})
		}
		succeed(map[string]any{"Keys": keys, "Truncated": false})
		return
	}
	aliases := []map[string]any{}
	for _, n := range names {
		aliases = append(aliases, map[string]any{"AliasName": "alias/" + n, "AliasArn": "arn:hsmgate:kms:" + f.Cfg.KMSJSON.Region + ":" + account + ":alias/" + n,
			"TargetKeyId": n, "CreationDate": float64(f.Created.Unix()), "LastUpdatedDate": float64(f.Created.Unix())})
	}
	succeed(map[string]any{"Aliases": aliases, "Truncated": false})
}

// peerPoint reads the public key of the caller: a DER SubjectPublicKeyInfo of a point on P-256. A point that is not on the curve, or another curve, is refused before the token sees it.
func peerPoint(der []byte) ([]byte, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errors.New("PublicKey is not a DER SubjectPublicKeyInfo")
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("PublicKey must be a P-256 key")
	}
	e, err := ec.ECDH()
	if err != nil {
		return nil, errors.New("PublicKey is not a point of the curve")
	}
	return e.Bytes(), nil
}

// spki is the DER SubjectPublicKeyInfo of a P-256 point of 65 bytes.
func spki(point []byte) []byte {
	return append([]byte{0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00}, point...)
}

func itoa(n int) string { return strconv.Itoa(n) }

func requestID(r *http.Request) string {
	if id := r.Header.Get("X-Request-Id"); id != "" && len(id) <= 64 && safeID(id) {
		return id
	}
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func safeID(s string) bool {
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	b, _ := json.Marshal(v)
	io.Copy(w, bytes.NewReader(b))
}

func fail(w http.ResponseWriter, status int, typ, msg string, retry bool) {
	w.Header().Set("x-amzn-ErrorType", typ)
	w.Header().Set("X-Hsmgate-Retryable", strconv.FormatBool(retry))
	reply(w, status, map[string]string{"__type": typ, "message": msg})
}

// Failures counts the refused signatures and credentials by the address of the peer: from an address with too many in a minute nothing is judged for the next minute. It bounds the guessing
// of a secret (which a secret of 20 bytes or more already makes pointless) and the cost of a noisy client.
type Failures struct {
	mu sync.Mutex
	by map[netip.Addr][]time.Time
}

const (
	failLimit  = 20
	failWindow = time.Minute
)

func NewFailures() *Failures { return &Failures{by: map[netip.Addr][]time.Time{}} }

func (x *Failures) recent(a netip.Addr, now time.Time) []time.Time {
	keep := x.by[a][:0]
	for _, t := range x.by[a] {
		if now.Sub(t) < failWindow {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(x.by, a)
	} else {
		x.by[a] = keep
	}
	return keep
}

func (x *Failures) Add(a netip.Addr, now time.Time) {
	if x == nil || !a.IsValid() {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if len(x.by) > 10000 { // a flood from many addresses must not grow the table without end
		x.by = map[netip.Addr][]time.Time{}
	}
	x.by[a] = append(x.recent(a, now), now)
}

func (x *Failures) Blocked(a netip.Addr, now time.Time) bool {
	if x == nil || !a.IsValid() {
		return false
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	return len(x.recent(a, now)) >= failLimit
}
