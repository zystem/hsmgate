package kmsjson

// The sealing operations of the face: Encrypt, Decrypt, ReEncrypt, GenerateDataKey, GenerateDataKeyWithoutPlaintext and GenerateRandom, for keys with the usage encrypt_decrypt.
// The service seals and opens, as in the Transit face (ecies1; the token does only the ECDH of the opening), and it sees the plaintext while it works. The EncryptionContext of
// the request is the additional data of the AEAD (a key in context mode) or must be absent (a key in fixed mode). The ciphertext blob is ours: opaque to clients, which only
// carry it; it names the key and its version, so that Decrypt works without a KeyId, as clients expect.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zystem/hsmgate/internal/audit"
	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/keyops"
	"github.com/zystem/hsmgate/internal/policy"
	"github.com/zystem/hsmgate/internal/scheme/ecies"
)

const (
	blobMagic    = "HGK2"
	algorithm    = "SYMMETRIC_DEFAULT"
	maxPlaintext = 4096 // the limit of the cloud service for Encrypt
	maxRandom    = 1024
	maxContext   = 1024 // written to the audit: keep a line small
	usageErrText = "the key cannot be used for this operation"
)

// call is one authenticated request that is being served.
type call struct {
	f       *Face
	w       http.ResponseWriter
	r       *http.Request
	client  string
	ev      *audit.Event
	refuse  func(status int, typ, msg, result string, retry bool)
	succeed func(any)
}

type cryptoReq struct {
	KeyID                          string            `json:"KeyId"`
	Plaintext                      []byte            `json:"Plaintext"`
	CiphertextBlob                 []byte            `json:"CiphertextBlob"`
	EncryptionContext              map[string]string `json:"EncryptionContext"`
	EncryptionAlgorithm            string            `json:"EncryptionAlgorithm"`
	DryRun                         bool              `json:"DryRun"`
	KeySpec                        string            `json:"KeySpec"`
	NumberOfBytes                  *int              `json:"NumberOfBytes"`
	SourceKeyID                    string            `json:"SourceKeyId"`
	DestinationKeyID               string            `json:"DestinationKeyId"`
	SourceEncryptionContext        map[string]string `json:"SourceEncryptionContext"`
	DestinationEncryptionContext   map[string]string `json:"DestinationEncryptionContext"`
	SourceEncryptionAlgorithm      string            `json:"SourceEncryptionAlgorithm"`
	DestinationEncryptionAlgorithm string            `json:"DestinationEncryptionAlgorithm"`
	CustomKeyStoreID               string            `json:"CustomKeyStoreId"`
	Message                        []byte            `json:"Message"`
	MessageType                    string            `json:"MessageType"`
	SigningAlgorithm               string            `json:"SigningAlgorithm"`
	MacAlgorithm                   string            `json:"MacAlgorithm"`
	Mac                            []byte            `json:"Mac"`
	Signature                      []byte            `json:"Signature"`
	Recipient                      json.RawMessage   `json:"Recipient"`
}

func isCryptoOp(op string) bool {
	switch op {
	case "Encrypt", "Decrypt", "ReEncrypt", "GenerateDataKey", "GenerateDataKeyWithoutPlaintext", "GenerateRandom", "Sign", "Verify", "GenerateMac", "VerifyMac":
		return true
	}
	return false
}

func (c *call) crypto(op string, body []byte) {
	var req cryptoReq
	if err := json.Unmarshal(body, &req); err != nil {
		c.refuse(400, "SerializationException", "the request is not valid JSON", "bad_request", false)
		return
	}
	if len(req.Recipient) > 0 && string(req.Recipient) != "null" {
		c.refuse(400, "ValidationException", "Recipient (an attestation document) is not supported", "bad_request", false)
		return
	}
	if req.CustomKeyStoreID != "" {
		c.refuse(400, "ValidationException", "custom key stores are not supported", "bad_request", false)
		return
	}
	switch op {
	case "GenerateRandom":
		c.random(req)
	case "GenerateMac", "VerifyMac":
		c.mac(op, req)
	case "Sign":
		c.sign(req)
	case "Verify":
		c.verify(req)
	case "Encrypt":
		c.encrypt(req)
	case "Decrypt":
		c.decrypt(req)
	case "ReEncrypt":
		c.reencrypt(req)
	default:
		c.dataKey(op, req)
	}
}

// knownAlgorithms are the names the cloud service has for its other key types: asked for one of them, the answer is the one that service gives for a key of another type
// (InvalidKeyUsageException); any other string is a malformed request.
var knownAlgorithms = map[string]bool{"RSAES_OAEP_SHA_1": true, "RSAES_OAEP_SHA_256": true, "SM2PKE": true, "SYMMETRIC_DEFAULT": true,
	"RSASSA_PKCS1_V1_5_SHA_256": true, "RSASSA_PKCS1_V1_5_SHA_384": true, "RSASSA_PKCS1_V1_5_SHA_512": true, "RSASSA_PSS_SHA_256": true, "RSASSA_PSS_SHA_384": true,
	"RSASSA_PSS_SHA_512": true, "ECDSA_SHA_256": true, "ECDSA_SHA_384": true, "ECDSA_SHA_512": true, "SM2DSA": true, "HMAC_SHA_224": true, "HMAC_SHA_256": true, "HMAC_SHA_384": true, "HMAC_SHA_512": true}

func (c *call) badAlgorithm(field, given string) {
	if knownAlgorithms[given] {
		c.refuse(400, "InvalidKeyUsageException", "Algorithm "+given+" is incompatible with the key", "bad_algorithm", false)
		return
	}
	c.refuse(400, "ValidationException", field+" is not a known algorithm", "bad_request", false)
}

func okAlgorithm(a string) bool { return a == "" || a == algorithm }

// target finds the key of an id for an operation and judges the request: the key is enabled for the face with the usage encrypt_decrypt, the client has the right and the budget,
// and the context is acceptable. ver 0 is the latest.
func (c *call) target(id string, ver int, op string, ctx map[string]string) (name string, v int, key config.Key, aad []byte, ok bool) {
	f := c.f
	name, idVer, found := f.resolve(id)
	if !found || !f.Policy.Allowed(c.client, name) {
		c.refuse(400, "AccessDeniedException", "the key does not exist or the client has no right to it", "forbidden", false)
		return
	}
	if ver == 0 {
		ver = idVer
	}
	key = f.Cfg.Keys[name]
	c.ev.Key = name
	want := config.UsageEncryptDecrypt
	switch op {
	case "sign", "verify":
		want = config.UsageSignVerify
	case "generate_mac", "verify_mac":
		want = config.UsageMAC
	}
	if key.Usage() != want {
		c.refuse(400, "InvalidKeyUsageException", usageErrText, "bad_usage", false)
		return
	}
	switch f.Policy.Check(c.client, name, op) {
	case policy.Forbidden:
		c.refuse(400, "AccessDeniedException", "the client has no right to "+op+" with this key", "forbidden", false)
		return
	case policy.Throttled:
		c.w.Header().Set("Retry-After", "5")
		c.refuse(400, "ThrottlingException", "rate limit exceeded", "throttled", true)
		return
	}
	if ver == 0 {
		ver = len(key.Versions)
	}
	if ver < 1 || ver > len(key.Versions) {
		c.refuse(400, "InvalidCiphertextException", "the ciphertext is not valid for this key", "bad_ciphertext", false)
		return
	}
	if want == config.UsageSignVerify || want == config.UsageMAC { // no additional data: a signature or a MAC has none
		return name, ver, key, nil, true
	}
	aad, ok = c.aadOf(name, key, ctx)
	return name, ver, key, aad, ok
}

// aadOf: the additional data of a request. A key in fixed mode takes no context; a key in context mode needs one, which is made canonical (sorted "name=value" lines) and judged by the
// same rules as the context of the Transit face.
func (c *call) aadOf(name string, k config.Key, ctx map[string]string) ([]byte, bool) {
	if k.AAD.Mode == "fixed" {
		if len(ctx) > 0 {
			c.refuse(400, "ValidationException", "this key takes no encryption context", "bad_context", false)
			return nil, false
		}
		return []byte(k.FixedAAD(name)), true
	}
	if len(ctx) == 0 {
		c.refuse(400, "ValidationException", "this key needs an encryption context", "bad_context", false)
		return nil, false
	}
	names := make([]string, 0, len(ctx))
	for n := range ctx {
		if n == "" || strings.ContainsAny(n, "=\n") || strings.Contains(ctx[n], "\n") {
			c.refuse(400, "ValidationException", "an encryption context name or value has a forbidden character", "bad_context", false)
			return nil, false
		}
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for i, n := range names {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(n + "=" + ctx[n])
	}
	aad := []byte(b.String())
	if len(aad) > maxContext {
		c.refuse(400, "ValidationException", "the encryption context is too long", "bad_context", false)
		return nil, false
	}
	c.ev.Context = string(aad) // public by rule, as in the Transit face
	if !anyLine(aad, func(l []byte) bool { return c.f.Policy.ContextOK(c.client, name, l) }) {
		c.refuse(400, "AccessDeniedException", "the client has no right to this encryption context", "forbidden_context", false)
		return nil, false
	}
	if !anyLine(aad, func(l []byte) bool { return policy.ContextAllowed(k, l) }) {
		c.refuse(400, "ValidationException", "this encryption context is not allowed for this key", "bad_context", false)
		return nil, false
	}
	return aad, true
}

// anyLine: the patterns of a key and of a grant are prefixes (as in the Transit face); a context here is a set of "name=value" lines, so it is allowed when one of its lines begins with
// an allowed prefix, such as "purpose=dek". The same pattern, "purpose=dek", is then a requirement on the field "purpose".
func anyLine(ctx []byte, ok func([]byte) bool) bool {
	for _, l := range bytes.Split(ctx, []byte("\n")) {
		if ok(l) {
			return true
		}
	}
	return false
}

// bindAAD is what the AEAD authenticates for a blob: the domain, the name of the key, its version and the additional data of the request. The name and the version are also in the
// clear in the blob, so that Decrypt can find the key; because they are authenticated here, a blob cannot be relabelled to another key (even one with the same key material and
// context) or to another version (audit 2026-10-21, CR-02). The blob format is "HGK2"; "HGK1" blobs (which bound nothing) were never in a release and are not read.
func bindAAD(name string, ver int, aad []byte) []byte {
	b := append([]byte("hsmgate/kmsjson/blob/v2\x00"), byte(len(name)))
	b = append(b, name...)
	b = binary.BigEndian.AppendUint16(b, uint16(ver))
	return append(b, aad...)
}

func makeBlob(name string, ver int, text string) []byte {
	b := append([]byte(blobMagic), byte(len(name)))
	b = append(b, name...)
	b = binary.BigEndian.AppendUint16(b, uint16(ver))
	return append(b, text...)
}

var errBlob = errors.New("the ciphertext is not valid")

func parseBlob(b []byte) (name string, ver int, text string, err error) {
	if len(b) < len(blobMagic)+1+1+2+1 || string(b[:len(blobMagic)]) != blobMagic {
		return "", 0, "", errBlob
	}
	n := int(b[len(blobMagic)])
	rest := b[len(blobMagic)+1:]
	if n == 0 || len(rest) < n+2+1 {
		return "", 0, "", errBlob
	}
	name = string(rest[:n])
	ver = int(binary.BigEndian.Uint16(rest[n : n+2]))
	text = string(rest[n+2:])
	if ver < 1 || !strings.HasPrefix(text, ecies.FormatTag+".") {
		return "", 0, "", errBlob
	}
	return name, ver, text, nil
}

func (c *call) seal(name string, ver int, key config.Key, plain, aad []byte) ([]byte, bool) {
	f := c.f
	release, ok := f.Gate.Take(c.r.Context())
	if !ok {
		c.refuse(400, "ThrottlingException", "the service is busy", "busy", true)
		return nil, false
	}
	defer release()
	point, err := keyops.PointOf(f.Tokens, key.Versions[ver-1])
	if err != nil {
		f.tokenFailure(c.refuse, err)
		return nil, false
	}
	text, err := ecies.Wrap(point, plain, bindAAD(name, ver, aad))
	if err != nil {
		c.refuse(500, "KMSInternalException", "internal error", "internal_error", true)
		return nil, false
	}
	return makeBlob(name, ver, text), true
}

func (c *call) open(name string, key config.Key, ver int, text string, aad []byte) ([]byte, bool) {
	f := c.f
	release, ok := f.Gate.Take(c.r.Context())
	if !ok {
		c.refuse(400, "ThrottlingException", "the service is busy", "busy", true)
		return nil, false
	}
	defer release()
	plain, err := keyops.Open(f.Tokens, key.Versions[ver-1], text, bindAAD(name, ver, aad))
	if err != nil {
		if errors.Is(err, ecies.ErrDamaged) || errors.Is(err, ecies.ErrWrongKey) {
			c.refuse(400, "InvalidCiphertextException", "the ciphertext cannot be opened with this key and context", "bad_ciphertext", false)
		} else {
			f.tokenFailure(c.refuse, err)
		}
		return nil, false
	}
	// the limit of the key holds for what comes out as for what goes in (the Transit face does the same): a blob made elsewhere, or under a larger limit, is not opened to more
	if len(plain) > maxOf(key) {
		wipe(plain)
		c.refuse(400, "InvalidCiphertextException", "the data is larger than max_bytes of this key", "too_large", false)
		return nil, false
	}
	return plain, true
}

// maxOf is the largest plaintext of a key: its max_bytes, else the default of the service.
func maxOf(k config.Key) int {
	if k.MaxBytes > 0 {
		return k.MaxBytes
	}
	return config.DefaultMaxBytes
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func (c *call) encrypt(req cryptoReq) {
	if !okAlgorithm(req.EncryptionAlgorithm) {
		c.badAlgorithm("EncryptionAlgorithm", req.EncryptionAlgorithm)
		return
	}
	name, ver, key, aad, ok := c.target(req.KeyID, 0, "encrypt", req.EncryptionContext)
	if !ok {
		return
	}
	max := maxPlaintext
	if m := maxOf(key); m < max {
		max = m
	}
	if len(req.Plaintext) == 0 || len(req.Plaintext) > max {
		c.refuse(400, "ValidationException", "Plaintext must be 1 to "+itoa(max)+" bytes", "bad_request", false)
		return
	}
	if req.DryRun {
		c.refuse(400, "DryRunOperationException", "the request would have succeeded, but the DryRun option is set", "dry_run", false)
		return
	}
	blob, ok := c.seal(name, ver, key, req.Plaintext, aad)
	if !ok {
		return
	}
	c.succeed(map[string]any{"CiphertextBlob": b64(blob), "KeyId": c.f.arnFor(req.KeyID, name), "EncryptionAlgorithm": algorithm})
}

// source reads the blob of a request and the key it names; id, when the client gave one, must be that key.
func (c *call) source(blob []byte, id string, ctx map[string]string) (name string, ver int, key config.Key, text string, aad []byte, ok bool) {
	bname, bver, text, err := parseBlob(blob)
	if err != nil {
		c.refuse(400, "InvalidCiphertextException", "the ciphertext is not valid", "bad_ciphertext", false)
		return
	}
	if id != "" {
		given, _, found := c.f.resolve(id)
		if !found || !c.f.Policy.Allowed(c.client, given) {
			c.refuse(400, "AccessDeniedException", "the key does not exist or the client has no right to it", "forbidden", false)
			return
		}
		if given != bname {
			c.ev.Key = given
			c.refuse(400, "IncorrectKeyException", "the key does not match the ciphertext", "wrong_key", false)
			return
		}
	}
	name, ver, key, aad, ok = c.target(bname, bver, "decrypt", ctx)
	return name, ver, key, text, aad, ok
}

func (c *call) decrypt(req cryptoReq) {
	if !okAlgorithm(req.EncryptionAlgorithm) {
		c.badAlgorithm("EncryptionAlgorithm", req.EncryptionAlgorithm)
		return
	}
	name, ver, key, text, aad, ok := c.source(req.CiphertextBlob, req.KeyID, req.EncryptionContext)
	if !ok {
		return
	}
	if req.DryRun {
		c.refuse(400, "DryRunOperationException", "the request would have succeeded, but the DryRun option is set", "dry_run", false)
		return
	}
	plain, ok := c.open(name, key, ver, text, aad)
	if !ok {
		return
	}
	defer wipe(plain)
	c.succeed(map[string]any{"KeyId": c.f.arnFor(req.KeyID, name), "Plaintext": b64(plain), "EncryptionAlgorithm": algorithm})
}

func (c *call) reencrypt(req cryptoReq) {
	if !okAlgorithm(req.SourceEncryptionAlgorithm) || !okAlgorithm(req.DestinationEncryptionAlgorithm) {
		c.badAlgorithm("EncryptionAlgorithm", req.SourceEncryptionAlgorithm+req.DestinationEncryptionAlgorithm)
		return
	}
	if req.DestinationKeyID == "" {
		c.refuse(400, "ValidationException", "DestinationKeyId is required", "bad_request", false)
		return
	}
	sname, sver, skey, text, saad, ok := c.source(req.CiphertextBlob, req.SourceKeyID, req.SourceEncryptionContext)
	if !ok {
		return
	}
	dname, dver, dkey, daad, ok := c.target(req.DestinationKeyID, 0, "encrypt", req.DestinationEncryptionContext)
	if !ok {
		return
	}
	c.ev.Key = sname
	c.ev.Context = "to=" + dname
	if req.DryRun {
		c.refuse(400, "DryRunOperationException", "the request would have succeeded, but the DryRun option is set", "dry_run", false)
		return
	}
	plain, ok := c.open(sname, skey, sver, text, saad)
	if !ok {
		return
	}
	defer wipe(plain)
	blob, ok := c.seal(dname, dver, dkey, plain, daad) // the version the destination id names, else the latest
	if !ok {
		return
	}
	c.succeed(map[string]any{"CiphertextBlob": b64(blob), "SourceKeyId": c.f.arnFor(req.SourceKeyID, sname), "KeyId": c.f.arnFor(req.DestinationKeyID, dname),
		"SourceEncryptionAlgorithm": algorithm, "DestinationEncryptionAlgorithm": algorithm})
}

func (c *call) dataKey(op string, req cryptoReq) {
	if !okAlgorithm(req.EncryptionAlgorithm) {
		c.badAlgorithm("EncryptionAlgorithm", req.EncryptionAlgorithm)
		return
	}
	var n int
	switch {
	case req.KeySpec != "" && req.NumberOfBytes != nil:
		c.refuse(400, "ValidationException", "give KeySpec or NumberOfBytes, not both", "bad_request", false)
		return
	case req.KeySpec == "AES_256":
		n = 32
	case req.KeySpec == "AES_128":
		n = 16
	case req.KeySpec == "" && req.NumberOfBytes != nil && *req.NumberOfBytes >= 1 && *req.NumberOfBytes <= maxRandom:
		n = *req.NumberOfBytes
	default:
		c.refuse(400, "ValidationException", "KeySpec must be AES_128 or AES_256, or NumberOfBytes 1 to "+itoa(maxRandom), "bad_request", false)
		return
	}
	name, ver, key, aad, ok := c.target(req.KeyID, 0, "encrypt", req.EncryptionContext)
	if !ok {
		return
	}
	if req.DryRun {
		c.refuse(400, "DryRunOperationException", "the request would have succeeded, but the DryRun option is set", "dry_run", false)
		return
	}
	dek := make([]byte, n)
	if _, err := rand.Read(dek); err != nil {
		c.refuse(500, "KMSInternalException", "internal error", "internal_error", true)
		return
	}
	defer wipe(dek)
	blob, ok := c.seal(name, ver, key, dek, aad)
	if !ok {
		return
	}
	out := map[string]any{"CiphertextBlob": b64(blob), "KeyId": c.f.arnFor(req.KeyID, name)}
	if op == "GenerateDataKey" {
		out["Plaintext"] = b64(dek)
	}
	c.succeed(out)
}

// random: bytes of the operating system's generator, not of the token (a card's generator is slow and a single session; the bytes are not secret keys of the service).
func (c *call) random(req cryptoReq) {
	if req.NumberOfBytes == nil || *req.NumberOfBytes < 1 || *req.NumberOfBytes > maxRandom {
		c.refuse(400, "ValidationException", "NumberOfBytes must be 1 to "+itoa(maxRandom), "bad_request", false)
		return
	}
	if c.f.Policy.CheckList(c.client) != policy.Allow {
		c.refuse(400, "ThrottlingException", "rate limit exceeded", "throttled", true)
		return
	}
	b := make([]byte, *req.NumberOfBytes)
	if _, err := rand.Read(b); err != nil {
		c.refuse(500, "KMSInternalException", "internal error", "internal_error", true)
		return
	}
	defer wipe(b)
	c.succeed(map[string]any{"Plaintext": b64(b)})
}

const maxMessage = 4096 // the limit of the cloud service for a message to sign; longer ones are signed by digest

// digestOf makes the 32 bytes that ECDSA signs from a request: the SHA-256 of a RAW message, or a DIGEST as given. Only ECDSA_SHA_256 is served.
func (c *call) digestOf(req cryptoReq) ([]byte, bool) {
	if req.SigningAlgorithm != "ECDSA_SHA_256" {
		c.badAlgorithm("SigningAlgorithm", req.SigningAlgorithm)
		return nil, false
	}
	switch req.MessageType {
	case "", "RAW":
		if len(req.Message) == 0 || len(req.Message) > maxMessage {
			c.refuse(400, "ValidationException", "Message must be 1 to "+itoa(maxMessage)+" bytes (use MessageType DIGEST for more)", "bad_request", false)
			return nil, false
		}
		d := sha256.Sum256(req.Message)
		return d[:], true
	case "DIGEST":
		if len(req.Message) != 32 {
			c.refuse(400, "ValidationException", "a DIGEST for ECDSA_SHA_256 is 32 bytes", "bad_request", false)
			return nil, false
		}
		return req.Message, true
	}
	c.refuse(400, "ValidationException", "MessageType must be RAW or DIGEST", "bad_request", false)
	return nil, false
}

func (c *call) sign(req cryptoReq) {
	name, ver, key, _, ok := c.target(req.KeyID, 0, "sign", nil)
	if !ok {
		return
	}
	digest, ok := c.digestOf(req)
	if !ok {
		return
	}
	c.messageMark("digest", digest)
	if req.DryRun {
		c.refuse(400, "DryRunOperationException", "the request would have succeeded, but the DryRun option is set", "dry_run", false)
		return
	}
	release, ok := c.f.Gate.Take(c.r.Context())
	if !ok {
		c.refuse(400, "ThrottlingException", "the service is busy", "busy", true)
		return
	}
	defer release()
	sig, err := keyops.Sign(c.f.Tokens, key.Versions[ver-1], digest)
	if err != nil {
		c.f.tokenFailure(c.refuse, err)
		return
	}
	c.succeed(map[string]any{"KeyId": c.f.arnFor(req.KeyID, name), "Signature": b64(sig), "SigningAlgorithm": "ECDSA_SHA_256"})
}

// verify checks a signature with the public key of the key (the token is asked for the key only, not to sign). A signature carries no version: it is checked against the latest
// version and then the earlier ones, so that a signature made before a rotation still verifies (a version can be asked for as "name@N", then only it is tried).
func (c *call) verify(req cryptoReq) {
	_, pinned, _ := c.f.resolve(req.KeyID)
	name, ver, key, _, ok := c.target(req.KeyID, 0, "verify", nil)
	if !ok {
		return
	}
	digest, ok := c.digestOf(req)
	if !ok {
		return
	}
	c.messageMark("digest", digest)
	if len(req.Signature) == 0 || len(req.Signature) > 128 {
		c.refuse(400, "ValidationException", "Signature must be an ASN.1 DER ECDSA signature", "bad_request", false)
		return
	}
	if req.DryRun {
		c.refuse(400, "DryRunOperationException", "the request would have succeeded, but the DryRun option is set", "dry_run", false)
		return
	}
	release, ok := c.f.Gate.Take(c.r.Context())
	if !ok {
		c.refuse(400, "ThrottlingException", "the service is busy", "busy", true)
		return
	}
	defer release()
	versions := []int{ver}
	if pinned == 0 {
		versions = versions[:0]
		for v := len(key.Versions); v >= 1; v-- {
			versions = append(versions, v)
		}
	}
	valid := false
	for _, v := range versions {
		point, err := keyops.PointOf(c.f.Tokens, key.Versions[v-1])
		if err != nil {
			c.f.tokenFailure(c.refuse, err)
			return
		}
		pub, err := x509.ParsePKIXPublicKey(spki(point))
		if err != nil {
			c.refuse(500, "KMSInternalException", "internal error", "internal_error", true)
			return
		}
		if ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), digest, req.Signature) {
			valid = true
			break
		}
	}
	if !valid {
		c.refuse(400, "KMSInvalidSignatureException", "the signature is not valid for this message and key", "bad_signature_value", false)
		return
	}
	c.succeed(map[string]any{"KeyId": c.f.arnFor(req.KeyID, name), "SignatureValid": true, "SigningAlgorithm": "ECDSA_SHA_256"})
}

// messageMark puts a short prefix of the hash of a message into the audit line when the configuration asks for it (kmsjson.audit_message_prefix). It is off by default: the hash of
// a message with little variety can be tested against guesses by whoever reads the log.
func (c *call) messageMark(label string, hash []byte) {
	if c.f.Cfg.KMSJSON.AuditMessagePrefix {
		c.ev.Context = label + "=" + hex.EncodeToString(hash[:6])
	}
}

// ---- MAC

const maxMacMessage = 4096

type macEntry struct {
	key     []byte
	expires time.Time
}

// macCache keeps the MAC keys derived from the keys on the token for kmsjson.mac_cache_seconds. Shared by the generations; an entry is named by the fingerprint of the public key
// and the version, so a key that was replaced is never answered from the old entry.
type macCache struct {
	mu sync.Mutex
	m  map[string]macEntry
}

func (k *macCache) get(id string, now time.Time) ([]byte, bool) {
	if k == nil {
		return nil, false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	e, ok := k.m[id]
	if !ok {
		return nil, false
	}
	if !now.Before(e.expires) {
		wipe(e.key)
		delete(k.m, id)
		return nil, false
	}
	return append([]byte{}, e.key...), true // a copy made under the lock: put and clear wipe the cache's own memory (audit 2026-10-21, CR-03)
}

// clear drops every derived key (a reload: the configuration, the clients or the tokens may have changed).
func (k *macCache) clear() {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for id, e := range k.m {
		wipe(e.key)
		delete(k.m, id)
	}
}

func (k *macCache) put(id string, key []byte, until time.Time) {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.m == nil {
		k.m = map[string]macEntry{}
	}
	if old, ok := k.m[id]; ok {
		wipe(old.key)
	}
	k.m[id] = macEntry{append([]byte{}, key...), until}
}

// NewMacKeys makes the cache of derived MAC keys.
func NewMacKeys() *macCache { return &macCache{m: map[string]macEntry{}} }

// macKey is the MAC key of a version, from the cache or from the token.
func (c *call) macKey(name string, ver int, key config.Key) ([]byte, bool) {
	f := c.f
	ttl := time.Duration(f.Cfg.KMSJSON.MacCacheSeconds) * time.Second
	id := name + "@" + itoa(ver)
	if ttl > 0 {
		if point, err := keyops.PointOf(f.Tokens, key.Versions[ver-1]); err == nil { // no token operation: the public key is kept
			id += "|" + ecies.Fingerprint(point)
			if k, ok := f.MacKeys.get(id, f.now()); ok {
				return k, true
			}
		}
	}
	release, ok := f.Gate.Take(c.r.Context())
	if !ok {
		c.refuse(400, "ThrottlingException", "the service is busy", "busy", true)
		return nil, false
	}
	defer release()
	k, err := keyops.MacKey(f.Tokens, key.Versions[ver-1])
	if err != nil {
		f.tokenFailure(c.refuse, err)
		return nil, false
	}
	if ttl > 0 {
		f.MacKeys.put(id, k, f.now().Add(ttl))
	}
	return k, true
}

func hmacSum(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func (c *call) mac(op string, req cryptoReq) {
	generate := op == "GenerateMac"
	right := "verify_mac"
	if generate {
		right = "generate_mac"
	}
	if req.MacAlgorithm != "HMAC_SHA_256" {
		c.badAlgorithm("MacAlgorithm", req.MacAlgorithm)
		return
	}
	// a version is asked for by "name@N"; else a MAC is made with the latest and checked against the latest and then the earlier ones (a MAC carries no version)
	_, pinned, _ := c.f.resolve(req.KeyID)
	name, ver, key, _, ok := c.target(req.KeyID, 0, right, nil)
	if !ok {
		return
	}
	if len(req.Message) == 0 || len(req.Message) > maxMacMessage {
		c.refuse(400, "ValidationException", "Message must be 1 to "+itoa(maxMacMessage)+" bytes", "bad_request", false)
		return
	}
	if !generate && (len(req.Mac) == 0 || len(req.Mac) > 64) {
		c.refuse(400, "ValidationException", "Mac must be 1 to 64 bytes", "bad_request", false)
		return
	}
	sum := sha256.Sum256(req.Message)
	c.messageMark("msg", sum[:])
	if req.DryRun {
		c.refuse(400, "DryRunOperationException", "the request would have succeeded, but the DryRun option is set", "dry_run", false)
		return
	}
	if generate {
		k, ok := c.macKey(name, ver, key)
		if !ok {
			return
		}
		defer wipe(k)
		c.succeed(map[string]any{"Mac": b64(hmacSum(k, req.Message)), "MacAlgorithm": "HMAC_SHA_256", "KeyId": c.f.arnFor(req.KeyID, name)})
		return
	}
	versions := []int{ver}
	if pinned == 0 {
		versions = versions[:0]
		for v := len(key.Versions); v >= 1; v-- {
			versions = append(versions, v)
		}
	}
	valid := false
	for _, v := range versions {
		k, ok := c.macKey(name, v, key)
		if !ok {
			return
		}
		valid = hmac.Equal(hmacSum(k, req.Message), req.Mac) || valid
		wipe(k)
		if valid {
			break
		}
	}
	if !valid {
		c.refuse(400, "KMSInvalidMacException", "the MAC is not valid for this message and key", "bad_mac", false)
		return
	}
	c.succeed(map[string]any{"KeyId": c.f.arnFor(req.KeyID, name), "MacValid": true, "MacAlgorithm": "HMAC_SHA_256"})
}
