package kmsops

import (
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strings"
	"time"

	"bytes"

	"github.com/zystem/hsmgate/internal/backend"
	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/gate"
	"github.com/zystem/hsmgate/internal/keyops"
	"github.com/zystem/hsmgate/internal/policy"
	"github.com/zystem/hsmgate/internal/scheme/ecies"
)

// AADMode says how the additional data of a request is judged against the rules of a key in context mode. AADBytes: the bytes as they are (the rule of the Transit face; a gRPC
// "additional authenticated data" field). AADLines: the bytes are lines "name=value" (the canonical form of a map) and one line must begin with an allowed prefix.
type AADMode int

const (
	AADBytes AADMode = iota
	AADLines
)

const maxContext = 1024 // the additional data is written to the audit by some faces: keep a line small

// Service is the shared part of one generation of one face. Faces make a new Service at every reload.
type Service struct {
	Face   string // "kmsjson", "kmsgrpc" or "kmsvault": which flag of a key puts it on this face
	Cfg    *config.Config
	Tokens map[string]backend.Token
	Policy *policy.Policy
	Gate   *gate.Gate
	Macs   *MacCache
	Now    func() time.Time // for tests
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func tokenErr(err error) *Error {
	switch {
	case errors.Is(err, backend.ErrLocked):
		return fail(Locked, "locked", "the token is locked", true)
	case errors.Is(err, backend.ErrUnavailable):
		return fail(Unavailable, "unavailable", "the token is not available", true)
	}
	return fail(Internal, "internal_error", "internal error", true)
}

// Key finds a key for a client on this face. A key that does not exist, is not on this face, or is not granted to the client gives the same answer.
func (s *Service) Key(client, name string) (config.Key, *Error) {
	k, ok := s.Cfg.Keys[name]
	if !ok || !k.OnFace(s.Face) || !s.Policy.Allowed(client, name) {
		return config.Key{}, fail(Denied, "forbidden", "the key does not exist or the client has no right to it", false)
	}
	return k, nil
}

// check judges a request: the key is on the face and granted, it has the usage the operation needs, the client has the right for op and budget left.
func (s *Service) check(client, name, op, usage string) (config.Key, *Error) {
	k, e := s.Key(client, name)
	if e != nil {
		return k, e
	}
	if k.Usage() != usage {
		return k, fail(Usage, "bad_usage", "the key cannot be used for this operation", false)
	}
	switch s.Policy.Check(client, name, op) {
	case policy.Forbidden:
		return k, fail(Denied, "forbidden", "the client has no right to "+op+" with this key", false)
	case policy.Throttled:
		return k, fail(Throttled, "throttled", "rate limit exceeded", true)
	}
	return k, nil
}

func version(k config.Key, ver int) (int, *Error) {
	if ver == 0 {
		return len(k.Versions), nil
	}
	if ver < 1 || ver > len(k.Versions) {
		return 0, fail(Invalid, "bad_version", "the key has no such version", false)
	}
	return ver, nil
}

// aad makes the additional data: a key in fixed mode takes none and has a constant; a key in context mode needs some, and it must be within what the key and the grant allow.
func (s *Service) aad(client, name string, k config.Key, raw []byte, mode AADMode) ([]byte, *Error) {
	if k.AAD.Mode == "fixed" {
		if len(raw) > 0 {
			return nil, fail(Invalid, "bad_context", "this key takes no additional authenticated data", false)
		}
		return []byte(k.FixedAAD(name)), nil
	}
	if len(raw) == 0 {
		return nil, fail(Invalid, "bad_context", "this key needs additional authenticated data", false)
	}
	if len(raw) > maxContext {
		return nil, fail(Invalid, "bad_context", "the additional authenticated data is too long", false)
	}
	okGrant := func(b []byte) bool { return s.Policy.ContextOK(client, name, b) }
	okKey := func(b []byte) bool { return policy.ContextAllowed(k, b) }
	if mode == AADLines {
		if !anyLine(raw, okGrant) {
			return nil, fail(Denied, "forbidden_context", "the client has no right to this context", false)
		}
		if !anyLine(raw, okKey) {
			return nil, fail(Invalid, "bad_context", "this context is not allowed for this key", false)
		}
		return raw, nil
	}
	if !okGrant(raw) {
		return nil, fail(Denied, "forbidden_context", "the client has no right to this context", false)
	}
	if !okKey(raw) {
		return nil, fail(Invalid, "bad_context", "this context is not allowed for this key", false)
	}
	return raw, nil
}

// anyLine: a context of lines is allowed when one of its lines begins with an allowed prefix (such as "purpose=dek").
func anyLine(ctx []byte, ok func([]byte) bool) bool {
	for _, l := range bytes.Split(ctx, []byte("\n")) {
		if ok(l) {
			return true
		}
	}
	return false
}

// MaxOf is the largest plaintext of a key: its max_bytes, else the default of the service.
func MaxOf(k config.Key) int {
	if k.MaxBytes > 0 {
		return k.MaxBytes
	}
	return config.DefaultMaxBytes
}

func (s *Service) take(ctx context.Context) (func(), *Error) {
	release, ok := s.Gate.Take(ctx)
	if !ok {
		return nil, fail(Busy, "busy", "the service is busy", true)
	}
	return release, nil
}

// Seal seals plain under the latest (or the asked) version of a key with the usage encrypt_decrypt. faceMax is the largest plaintext the protocol of the face takes.
func (s *Service) Seal(ctx context.Context, client, name string, ver int, plain, rawAAD []byte, mode AADMode, faceMax int) ([]byte, int, *Error) {
	k, e := s.check(client, name, "encrypt", config.UsageEncryptDecrypt)
	if e != nil {
		return nil, 0, e
	}
	ver, e = version(k, ver)
	if e != nil {
		return nil, 0, e
	}
	aad, e := s.aad(client, name, k, rawAAD, mode)
	if e != nil {
		return nil, 0, e
	}
	max := faceMax
	if m := MaxOf(k); m < max {
		max = m
	}
	if len(plain) > max {
		return nil, 0, fail(Invalid, "too_large", "the plaintext is larger than the key takes", false)
	}
	release, e := s.take(ctx)
	if e != nil {
		return nil, 0, e
	}
	defer release()
	point, err := keyops.PointOf(s.Tokens, k.Versions[ver-1])
	if err != nil {
		return nil, 0, tokenErr(err)
	}
	text, err := ecies.Wrap(point, plain, BindAAD(name, ver, aad))
	if err != nil {
		return nil, 0, fail(Internal, "internal_error", "internal error", true)
	}
	return MakeBlob(name, ver, text), ver, nil
}

// BlobKey reads the name of the key from a blob (a face needs it to refuse early, or to find the key of a Decrypt without a key id).
func BlobKey(blob []byte) (name string, ver int, err *Error) {
	n, v, _, e := ParseBlob(blob)
	if e != nil {
		return "", 0, fail(BadCiphertext, "bad_ciphertext", "the ciphertext is not valid", false)
	}
	return n, v, nil
}

// Open opens a blob. hint, when not empty, is the key the client says it is for; a blob of another key is refused.
func (s *Service) Open(ctx context.Context, client, hint string, blob, rawAAD []byte, mode AADMode) ([]byte, string, int, *Error) {
	name, ver, text, perr := ParseBlob(blob)
	if perr != nil {
		return nil, "", 0, fail(BadCiphertext, "bad_ciphertext", "the ciphertext is not valid", false)
	}
	if hint != "" && hint != name {
		return nil, "", 0, fail(Invalid, "wrong_key", "the ciphertext is not for this key", false)
	}
	k, e := s.check(client, name, "decrypt", config.UsageEncryptDecrypt)
	if e != nil {
		return nil, "", 0, e
	}
	if ver < 1 || ver > len(k.Versions) {
		return nil, "", 0, fail(BadCiphertext, "bad_ciphertext", "the ciphertext is not valid for this key", false)
	}
	aad, e := s.aad(client, name, k, rawAAD, mode)
	if e != nil {
		return nil, "", 0, e
	}
	release, e := s.take(ctx)
	if e != nil {
		return nil, "", 0, e
	}
	defer release()
	plain, err := keyops.Open(s.Tokens, k.Versions[ver-1], text, BindAAD(name, ver, aad))
	if err != nil {
		if errors.Is(err, ecies.ErrDamaged) || errors.Is(err, ecies.ErrWrongKey) {
			return nil, "", 0, fail(BadCiphertext, "bad_ciphertext", "the ciphertext cannot be opened with this key and context", false)
		}
		return nil, "", 0, tokenErr(err)
	}
	// the limit of the key holds for what comes out as for what goes in
	if len(plain) > MaxOf(k) {
		Wipe(plain)
		return nil, "", 0, fail(BadCiphertext, "too_large", "the data is larger than max_bytes of this key", false)
	}
	return plain, name, ver, nil
}

// SPKI is the DER SubjectPublicKeyInfo of a P-256 point of 65 bytes.
func SPKI(point []byte) []byte {
	return append([]byte{0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00}, point...)
}

// Public gives the public key (DER SubjectPublicKeyInfo) of a version of a signing key.
func (s *Service) Public(ctx context.Context, client, name string, ver int) ([]byte, int, *Error) {
	k, e := s.Key(client, name)
	if e != nil {
		return nil, 0, e
	}
	if k.Usage() != config.UsageSignVerify {
		return nil, 0, fail(Usage, "bad_usage", "the key has no public key", false)
	}
	if s.Policy.CheckMeta(client, name) != policy.Allow {
		return nil, 0, fail(Throttled, "throttled", "rate limit exceeded", true)
	}
	ver, e = version(k, ver)
	if e != nil {
		return nil, 0, e
	}
	release, e := s.take(ctx)
	if e != nil {
		return nil, 0, e
	}
	defer release()
	point, err := keyops.PointOf(s.Tokens, k.Versions[ver-1])
	if err != nil {
		return nil, 0, tokenErr(err)
	}
	return SPKI(point), ver, nil
}

// Sign signs a digest of 32 bytes (SHA-256) with ECDSA P-256 on the token; the signature is ASN.1 DER.
func (s *Service) Sign(ctx context.Context, client, name string, ver int, digest []byte) ([]byte, int, *Error) {
	k, e := s.check(client, name, "sign", config.UsageSignVerify)
	if e != nil {
		return nil, 0, e
	}
	ver, e = version(k, ver)
	if e != nil {
		return nil, 0, e
	}
	if len(digest) != 32 {
		return nil, 0, fail(Invalid, "bad_request", "the digest must be 32 bytes (SHA-256)", false)
	}
	release, e := s.take(ctx)
	if e != nil {
		return nil, 0, e
	}
	defer release()
	sig, err := keyops.Sign(s.Tokens, k.Versions[ver-1], digest)
	if err != nil {
		return nil, 0, tokenErr(err)
	}
	return sig, ver, nil
}

// Verify checks a signature of a digest with the public key; ver 0 tries the latest version and then the earlier ones (a signature carries no version).
func (s *Service) Verify(ctx context.Context, client, name string, ver int, digest, sig []byte) (bool, *Error) {
	k, e := s.check(client, name, "verify", config.UsageSignVerify)
	if e != nil {
		return false, e
	}
	if len(digest) != 32 {
		return false, fail(Invalid, "bad_request", "the digest must be 32 bytes (SHA-256)", false)
	}
	var versions []int
	if ver == 0 {
		for v := len(k.Versions); v >= 1; v-- {
			versions = append(versions, v)
		}
	} else if _, e := version(k, ver); e != nil {
		return false, e
	} else {
		versions = []int{ver}
	}
	release, e := s.take(ctx)
	if e != nil {
		return false, e
	}
	defer release()
	for _, v := range versions {
		point, err := keyops.PointOf(s.Tokens, k.Versions[v-1])
		if err != nil {
			return false, tokenErr(err)
		}
		pub, err := x509.ParsePKIXPublicKey(SPKI(point))
		if err != nil {
			return false, fail(Internal, "internal_error", "internal error", true)
		}
		if ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), digest, sig) {
			return true, nil
		}
	}
	return false, nil
}

func (s *Service) macKey(ctx context.Context, name string, ver int, k config.Key) ([]byte, *Error) {
	ttl := time.Duration(s.Cfg.KMSJSON.MacCacheSeconds) * time.Second
	id := name + "@" + itoa(ver)
	if ttl > 0 {
		if point, err := keyops.PointOf(s.Tokens, k.Versions[ver-1]); err == nil { // no token operation: the public key is kept
			id += "|" + ecies.Fingerprint(point)
			if key, ok := s.Macs.get(id, s.now()); ok {
				return key, nil
			}
		}
	}
	release, e := s.take(ctx)
	if e != nil {
		return nil, e
	}
	defer release()
	key, err := keyops.MacKey(s.Tokens, k.Versions[ver-1])
	if err != nil {
		return nil, tokenErr(err)
	}
	if ttl > 0 {
		s.Macs.put(id, key, s.now().Add(ttl))
	}
	return key, nil
}

func hmacSum(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// MacGenerate gives HMAC-SHA-256 of msg under the MAC key derived on the token for the latest (or the asked) version.
func (s *Service) MacGenerate(ctx context.Context, client, name string, ver int, msg []byte) ([]byte, int, *Error) {
	k, e := s.check(client, name, "generate_mac", config.UsageMAC)
	if e != nil {
		return nil, 0, e
	}
	ver, e = version(k, ver)
	if e != nil {
		return nil, 0, e
	}
	key, e := s.macKey(ctx, name, ver, k)
	if e != nil {
		return nil, 0, e
	}
	defer Wipe(key)
	return hmacSum(key, msg), ver, nil
}

// MacVerify checks a MAC; ver 0 tries the latest version and then the earlier ones.
func (s *Service) MacVerify(ctx context.Context, client, name string, ver int, msg, mac []byte) (bool, *Error) {
	k, e := s.check(client, name, "verify_mac", config.UsageMAC)
	if e != nil {
		return false, e
	}
	var versions []int
	if ver == 0 {
		for v := len(k.Versions); v >= 1; v-- {
			versions = append(versions, v)
		}
	} else if _, e := version(k, ver); e != nil {
		return false, e
	} else {
		versions = []int{ver}
	}
	valid := false
	for _, v := range versions {
		key, e := s.macKey(ctx, name, v, k)
		if e != nil {
			return false, e
		}
		valid = hmac.Equal(hmacSum(key, msg), mac) || valid
		Wipe(key)
		if valid {
			break
		}
	}
	return valid, nil
}

// Random gives n bytes of the operating system's generator (not the token's), from a small budget of its own.
func (s *Service) Random(client string, n int) ([]byte, *Error) {
	if s.Policy.CheckList(client) != policy.Allow {
		return nil, fail(Throttled, "throttled", "rate limit exceeded", true)
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fail(Internal, "internal_error", "internal error", true)
	}
	return b, nil
}

// Meta is what a face may say about a key without touching the token.
type Meta struct {
	Name     string
	Usage    string
	Versions int
}

// Describe gives the metadata of a key, from a small budget of its own.
func (s *Service) Describe(client, name string) (Meta, *Error) {
	k, e := s.Key(client, name)
	if e != nil {
		return Meta{}, e
	}
	if s.Policy.CheckMeta(client, name) != policy.Allow {
		return Meta{}, fail(Throttled, "throttled", "rate limit exceeded", true)
	}
	return Meta{Name: name, Usage: k.Usage(), Versions: len(k.Versions)}, nil
}

// List gives the names of the keys on this face that a client may see, in order, from the small budget of listing.
func (s *Service) List(client string) ([]string, *Error) {
	if s.Policy.CheckList(client) != policy.Allow {
		return nil, fail(Throttled, "throttled", "rate limit exceeded", true)
	}
	var names []string
	for n, k := range s.Cfg.Keys {
		if k.OnFace(s.Face) && s.Policy.Allowed(client, n) {
			names = append(names, n)
		}
	}
	sortStrings(names)
	return names, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && strings.Compare(a[j-1], a[j]) > 0; j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
}
