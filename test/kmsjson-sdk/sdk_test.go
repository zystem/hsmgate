// A black-box test of the KMS-JSON face with the official Go SDK of the cloud service whose API the face imitates: the real hsmgate binary is built and started, with a client
// certificate and a signing credential, and the SDK calls it. It is the check that the wire format, the request signature, the types and the errors are what a real client expects.
// It is a module of its own, so that the SDK does not become a dependency of the service.
package kmsjsonsdk

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
)

const (
	akid   = "AKIDSDKTESTSDKTEST1"
	secret = "a-signing-secret-of-the-test-0123456789"
)

var (
	endpoint string
	httpc    *http.Client
	workdir  string
)

type ident struct {
	cert tls.Certificate
	pem  []byte
	x    *x509.Certificate
}

func mk(cn string, ca *ident, isCA, srv bool) ident {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: isCA, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}
	if srv {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else if !isCA {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	parent, pk := tpl, k
	if ca != nil {
		parent, pk = ca.x, ca.cert.PrivateKey.(*ecdsa.PrivateKey)
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &k.PublicKey, pk)
	if err != nil {
		panic(err)
	}
	x, _ := x509.ParseCertificate(der)
	return ident{tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), x}
}

func writeKey(path string, id ident) {
	b, _ := x509.MarshalECPrivateKey(id.cert.PrivateKey.(*ecdsa.PrivateKey))
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), 0o600)
}

func TestMain(m *testing.M) { os.Exit(run(m)) }

func run(m *testing.M) int {
	var err error
	workdir, err = os.MkdirTemp("", "kmsjson-sdk")
	if err != nil {
		fmt.Println(err)
		return 1
	}
	defer os.RemoveAll(workdir)
	bin := filepath.Join(workdir, "hsmgate")
	build := exec.Command("go", "build", "-o", bin, "./cmd/hsmgate")
	build.Dir = "../.." // the main module; this one is separate
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Println("build:", err)
		return 1
	}
	ca := mk("ca", nil, true, false)
	srv := mk("hsmgate", &ca, false, true)
	cli := mk("sdk-client", &ca, false, false)
	f := func(n string) string { return filepath.Join(workdir, n) }
	os.WriteFile(f("ca.pem"), ca.pem, 0o600)
	os.WriteFile(f("srv.pem"), srv.pem, 0o600)
	writeKey(f("srv.key"), srv)
	os.WriteFile(f("sigv4-secret"), []byte(secret+"\n"), 0o600)
	os.WriteFile(f("k1.hex"), bytes.Repeat([]byte("07"), 32), 0o600)
	os.WriteFile(f("k2.hex"), bytes.Repeat([]byte("09"), 32), 0o600)
	os.WriteFile(f("k3.hex"), bytes.Repeat([]byte("0b"), 32), 0o600)
	os.WriteFile(f("k4.hex"), bytes.Repeat([]byte("0d"), 32), 0o600)
	os.WriteFile(f("k5.hex"), bytes.Repeat([]byte("0e"), 32), 0o600)
	os.WriteFile(f("k6.hex"), bytes.Repeat([]byte("0f"), 32), 0o600)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	os.WriteFile(f("hsmgate.yaml"), []byte(fmt.Sprintf(`listen: %s
tls: {cert: %s, key: %s, client_ca: %s}
kmsjson: {enabled: true, region: local}
tokens: [{name: soft, type: soft, keys: {m1: %s, m2: %s, m3: %s, m4: %s, m5: %s, m6: %s}}]
keys:
  etcd: {kmsjson: true, versions: [{token: soft, label: m1}, {token: soft, label: m2}], aad: {mode: fixed}}
  mac: {kmsjson: true, kmsjson_usage: generate_verify_mac, versions: [{token: soft, label: m4}], aad: {mode: fixed}}
  sig: {kmsjson: true, kmsjson_usage: sign_verify, versions: [{token: soft, label: m3}], aad: {mode: fixed}}
  seal: {kmsjson: true, kmsjson_usage: encrypt_decrypt, versions: [{token: soft, label: m5}], aad: {mode: fixed}}
  hidden: {versions: [{token: soft, label: m6}], aad: {mode: fixed}}
clients:
  - name: sdk
    identity: {cn: sdk-client}
    sigv4: {access_key_id: %s, secret_file: %s}
    keys: {etcd: {ops: [derive]}, seal: {ops: [encrypt, decrypt]}, sig: {ops: [sign, verify]}, mac: {ops: [generate_mac, verify_mac]}}
`, addr, f("srv.pem"), f("srv.key"), f("ca.pem"), f("k1.hex"), f("k2.hex"), f("k3.hex"), f("k4.hex"), f("k5.hex"), f("k6.hex"), akid, f("sigv4-secret"))), 0o600)
	cmd := exec.Command(bin, "serve", "-config", f("hsmgate.yaml"))
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Println(err)
		return 1
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	pool := x509.NewCertPool()
	pool.AddCert(ca.x)
	httpc = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cli.cert}}}, Timeout: 20 * time.Second}
	endpoint = "https://" + addr
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return m.Run()
}

func client(secretKey string) *kms.Client {
	return kms.New(kms.Options{
		Region:           "local",
		BaseEndpoint:     aws.String(endpoint),
		Credentials:      credentials.NewStaticCredentialsProvider(akid, secretKey, ""),
		HTTPClient:       httpc,
		RetryMaxAttempts: 1, // a refusal is the answer; the SDK would repeat some of them
	})
}

func code(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return fmt.Sprintf("(not an API error: %v)", err)
}

func publicKey(t *testing.T, c *kms.Client, id string) *ecdh.PublicKey {
	out, err := c.GetPublicKey(context.Background(), &kms.GetPublicKeyInput{KeyId: aws.String(id)})
	if err != nil {
		t.Fatalf("GetPublicKey %s: %v", id, err)
	}
	if out.KeySpec != types.KeySpecEccNistP256 || out.KeyUsage != types.KeyUsageTypeKeyAgreement || len(out.KeyAgreementAlgorithms) != 1 || out.KeyAgreementAlgorithms[0] != types.KeyAgreementAlgorithmSpecEcdh {
		t.Fatalf("GetPublicKey: %+v", out)
	}
	pub, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	e, err := pub.(*ecdsa.PublicKey).ECDH()
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// The whole use of the face: the client fetches the public key, makes its own key pair, asks the service for the ECDH, and gets what it computes locally.
func TestDeriveSharedSecretMatchesLocalECDH(t *testing.T) {
	c := client(secret)
	master := publicKey(t, c, "alias/etcd")
	mine, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&mine.PublicKey)
	out, err := c.DeriveSharedSecret(context.Background(), &kms.DeriveSharedSecretInput{KeyId: aws.String("etcd"), KeyAgreementAlgorithm: types.KeyAgreementAlgorithmSpecEcdh, PublicKey: der})
	if err != nil {
		t.Fatal(err)
	}
	me, _ := mine.ECDH()
	want, _ := me.ECDH(master)
	if !bytes.Equal(out.SharedSecret, want) || out.KeyAgreementAlgorithm != types.KeyAgreementAlgorithmSpecEcdh || aws.ToString(out.KeyId) == "" {
		t.Errorf("shared secret %x, want %x", out.SharedSecret, want)
	}
	// an older version of the key by the "@N" form
	v1 := publicKey(t, c, "etcd@1")
	out, err = c.DeriveSharedSecret(context.Background(), &kms.DeriveSharedSecretInput{KeyId: aws.String("etcd@1"), KeyAgreementAlgorithm: types.KeyAgreementAlgorithmSpecEcdh, PublicKey: der})
	if err != nil {
		t.Fatal(err)
	}
	if want1, _ := me.ECDH(v1); !bytes.Equal(out.SharedSecret, want1) || bytes.Equal(want1, want) {
		t.Errorf("version 1")
	}
}

func TestDescribeListAndTheTypesOfTheSDK(t *testing.T) {
	c := client(secret)
	d, err := c.DescribeKey(context.Background(), &kms.DescribeKeyInput{KeyId: aws.String("etcd")})
	if err != nil {
		t.Fatal(err)
	}
	md := d.KeyMetadata
	if aws.ToString(md.KeyId) != "etcd" || !md.Enabled || md.KeyState != types.KeyStateEnabled || md.KeyUsage != types.KeyUsageTypeKeyAgreement || md.CreationDate == nil || md.CreationDate.IsZero() {
		t.Errorf("%+v", md)
	}
	ks, err := c.ListKeys(context.Background(), &kms.ListKeysInput{})
	if err != nil || len(ks.Keys) != 4 || ks.Truncated { // "hidden" has no kmsjson and is not listed
		t.Errorf("%+v %v", ks, err)
	}
	as, err := c.ListAliases(context.Background(), &kms.ListAliasesInput{})
	if err != nil || len(as.Aliases) != 4 {
		t.Errorf("%+v %v", as, err)
	}
}

func TestErrorsAreTheOnesSDKsKnow(t *testing.T) {
	c := client(secret)
	_, der := func() (*ecdsa.PrivateKey, []byte) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		d, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
		return k, d
	}()
	derive := func(c *kms.Client, key string, mutate func(*kms.DeriveSharedSecretInput)) error {
		in := &kms.DeriveSharedSecretInput{KeyId: aws.String(key), KeyAgreementAlgorithm: types.KeyAgreementAlgorithmSpecEcdh, PublicKey: der}
		if mutate != nil {
			mutate(in)
		}
		_, err := c.DeriveSharedSecret(context.Background(), in)
		return err
	}
	for name, tc := range map[string]struct {
		err  error
		code string
	}{
		"a key that is not enabled for the face": {derive(c, "hidden", nil), "AccessDeniedException"},
		"a key that does not exist":              {derive(c, "nope", nil), "AccessDeniedException"},
		"dry run":                                {derive(c, "etcd", func(in *kms.DeriveSharedSecretInput) { in.DryRun = aws.Bool(true) }), "DryRunOperationException"},
		"junk instead of a key":                  {derive(c, "etcd", func(in *kms.DeriveSharedSecretInput) { in.PublicKey = []byte("junk") }), "ValidationException"},
		"a wrong signing secret":                 {derive(client("this-is-not-the-secret-0123456789"), "etcd", nil), "InvalidSignatureException"},
	} {
		if got := code(tc.err); got != tc.code {
			t.Errorf("%s: %s, want %s (%v)", name, got, tc.code, tc.err)
		}
	}
	// an unknown access key
	bad := kms.New(kms.Options{Region: "local", BaseEndpoint: aws.String(endpoint), HTTPClient: httpc, RetryMaxAttempts: 1,
		Credentials: credentials.NewStaticCredentialsProvider("AKIDNOBODYNOBODYNOBODY", secret, "")})
	if got := code(derive(bad, "etcd", nil)); got != "UnrecognizedClientException" {
		t.Errorf("an unknown access key: %s", got)
	}
	// an operation the face does not have is said so
	_, err := c.ScheduleKeyDeletion(context.Background(), &kms.ScheduleKeyDeletionInput{KeyId: aws.String("etcd")})
	if got := code(err); got != "UnsupportedOperationException" {
		t.Errorf("an unsupported operation: %s (%v)", got, err)
	}
}

// Sealing by the service: the calls that services written for the cloud service make (Encrypt, Decrypt without a KeyId, GenerateDataKey, ReEncrypt, GenerateRandom).
func TestEncryptDecryptAndDataKeys(t *testing.T) {
	c := client(secret)
	ctx := context.Background()
	d, err := c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String("seal")})
	if err != nil || d.KeyMetadata.KeyUsage != types.KeyUsageTypeEncryptDecrypt || d.KeyMetadata.KeySpec != types.KeySpecSymmetricDefault {
		t.Fatalf("DescribeKey: %+v %v", d, err)
	}
	enc, err := c.Encrypt(ctx, &kms.EncryptInput{KeyId: aws.String("alias/seal"), Plaintext: []byte("hello")})
	if err != nil || enc.EncryptionAlgorithm != types.EncryptionAlgorithmSpecSymmetricDefault {
		t.Fatalf("Encrypt: %+v %v", enc, err)
	}
	dec, err := c.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: enc.CiphertextBlob})
	if err != nil || string(dec.Plaintext) != "hello" || aws.ToString(dec.KeyId) != aws.ToString(enc.KeyId) {
		t.Fatalf("Decrypt: %+v %v", dec, err)
	}
	dk, err := c.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{KeyId: aws.String("seal"), KeySpec: types.DataKeySpecAes256})
	if err != nil || len(dk.Plaintext) != 32 {
		t.Fatalf("GenerateDataKey: %+v %v", dk, err)
	}
	back, err := c.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: dk.CiphertextBlob, KeyId: aws.String("seal")})
	if err != nil || !bytes.Equal(back.Plaintext, dk.Plaintext) {
		t.Fatalf("the data key: %v", err)
	}
	if _, err := c.GenerateDataKeyWithoutPlaintext(ctx, &kms.GenerateDataKeyWithoutPlaintextInput{KeyId: aws.String("seal"), NumberOfBytes: aws.Int32(24)}); err != nil {
		t.Errorf("GenerateDataKeyWithoutPlaintext: %v", err)
	}
	re, err := c.ReEncrypt(ctx, &kms.ReEncryptInput{CiphertextBlob: enc.CiphertextBlob, DestinationKeyId: aws.String("seal")})
	if err != nil {
		t.Fatalf("ReEncrypt: %v", err)
	}
	if again, err := c.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: re.CiphertextBlob}); err != nil || string(again.Plaintext) != "hello" {
		t.Errorf("after ReEncrypt: %v", err)
	}
	r, err := c.GenerateRandom(ctx, &kms.GenerateRandomInput{NumberOfBytes: aws.Int32(40)})
	if err != nil || len(r.Plaintext) != 40 {
		t.Errorf("GenerateRandom: %v", err)
	}
	bad := append([]byte{}, enc.CiphertextBlob...)
	bad[len(bad)-2] ^= 1
	_, err = c.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: bad})
	if got := code(err); got != "InvalidCiphertextException" {
		t.Errorf("a damaged blob: %s", got)
	}
	// a key for key agreement is not for sealing
	_, err = c.Encrypt(ctx, &kms.EncryptInput{KeyId: aws.String("etcd"), Plaintext: []byte("x")})
	if got := code(err); got != "InvalidKeyUsageException" {
		t.Errorf("Encrypt on an ECDH key: %s", got)
	}
}

func TestSignAndVerify(t *testing.T) {
	c := client(secret)
	ctx := context.Background()
	msg := []byte("release v1.0.0")
	pk, err := c.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String("sig")})
	if err != nil || pk.KeyUsage != types.KeyUsageTypeSignVerify || len(pk.SigningAlgorithms) != 1 || pk.SigningAlgorithms[0] != types.SigningAlgorithmSpecEcdsaSha256 {
		t.Fatalf("GetPublicKey: %+v %v", pk, err)
	}
	pub, err := x509.ParsePKIXPublicKey(pk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sg, err := c.Sign(ctx, &kms.SignInput{KeyId: aws.String("alias/sig"), Message: msg, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256})
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), d[:], sg.Signature) {
		t.Fatal("the signature does not verify with the public key")
	}
	v, err := c.Verify(ctx, &kms.VerifyInput{KeyId: aws.String("sig"), Message: msg, Signature: sg.Signature, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256})
	if err != nil || !v.SignatureValid {
		t.Errorf("Verify: %+v %v", v, err)
	}
	// a digest of a large message, signed as a DIGEST
	if _, err := c.Sign(ctx, &kms.SignInput{KeyId: aws.String("sig"), Message: d[:], MessageType: types.MessageTypeDigest, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256}); err != nil {
		t.Errorf("Sign a digest: %v", err)
	}
	_, err = c.Verify(ctx, &kms.VerifyInput{KeyId: aws.String("sig"), Message: []byte("other"), Signature: sg.Signature, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256})
	if got := code(err); got != "KMSInvalidSignatureException" {
		t.Errorf("a signature of another message: %s", got)
	}
}

func TestGenerateAndVerifyMac(t *testing.T) {
	c := client(secret)
	ctx := context.Background()
	msg := []byte("message to authenticate")
	d, err := c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String("mac")})
	if err != nil || d.KeyMetadata.KeyUsage != types.KeyUsageTypeGenerateVerifyMac || d.KeyMetadata.KeySpec != types.KeySpecHmac256 || len(d.KeyMetadata.MacAlgorithms) != 1 {
		t.Fatalf("DescribeKey: %+v %v", d, err)
	}
	g, err := c.GenerateMac(ctx, &kms.GenerateMacInput{KeyId: aws.String("alias/mac"), Message: msg, MacAlgorithm: types.MacAlgorithmSpecHmacSha256})
	if err != nil || len(g.Mac) != 32 || g.MacAlgorithm != types.MacAlgorithmSpecHmacSha256 {
		t.Fatalf("GenerateMac: %+v %v", g, err)
	}
	v, err := c.VerifyMac(ctx, &kms.VerifyMacInput{KeyId: aws.String("mac"), Message: msg, Mac: g.Mac, MacAlgorithm: types.MacAlgorithmSpecHmacSha256})
	if err != nil || !v.MacValid {
		t.Errorf("VerifyMac: %+v %v", v, err)
	}
	_, err = c.VerifyMac(ctx, &kms.VerifyMacInput{KeyId: aws.String("mac"), Message: []byte("other"), Mac: g.Mac, MacAlgorithm: types.MacAlgorithmSpecHmacSha256})
	if got := code(err); got != "KMSInvalidMacException" {
		t.Errorf("a MAC of another message: %s", got)
	}
	_, err = c.GenerateMac(ctx, &kms.GenerateMacInput{KeyId: aws.String("mac"), Message: msg, MacAlgorithm: types.MacAlgorithmSpecHmacSha512})
	if got := code(err); got != "InvalidKeyUsageException" {
		t.Errorf("HMAC_SHA_512: %s", got)
	}
}
