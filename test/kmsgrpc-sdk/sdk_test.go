// A black-box test of the gRPC face with the official Go client library of the cloud key service whose API the face imitates: the real hsmgate binary is built and started, with the
// service account of a client, and the library calls it as it calls the service (a token from the token endpoint of the service account file, then unary gRPC calls over TLS). It is a
// module of its own, so that the library does not become a dependency of the service.
package kmsgrpcsdk

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const ring = "projects/hsmgate/locations/global/keyRings/main/cryptoKeys/"

var (
	addr    string
	saFile  string
	crcTab  = crc32.MakeTable(crc32.Castagnoli)
	workdir string
)

func crc(b []byte) *wrapperspb.Int64Value { return wrapperspb.Int64(int64(crc32.Checksum(b, crcTab))) }

func TestMain(m *testing.M) { os.Exit(run(m)) }

func run(m *testing.M) int {
	var err error
	workdir, err = os.MkdirTemp("", "kmsgrpc-sdk")
	if err != nil {
		fmt.Println(err)
		return 1
	}
	defer os.RemoveAll(workdir)
	f := func(n string) string { return filepath.Join(workdir, n) }
	bin := f("hsmgate")
	build := exec.Command("go", "build", "-o", bin, "./cmd/hsmgate")
	build.Dir = "../.." // the main module; this one is separate
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Println("build:", err)
		return 1
	}
	// a CA-less setup: the server certificate is its own trust anchor, found by the client through SSL_CERT_FILE
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "hsmgate"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &sk.PublicKey, sk)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, _ := x509.MarshalECPrivateKey(sk)
	os.WriteFile(f("srv.pem"), certPEM, 0o600)
	os.WriteFile(f("srv.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	os.WriteFile(f("ca.pem"), certPEM, 0o600) // the client CA: nobody has a certificate, the service account is the credential
	os.Setenv("SSL_CERT_FILE", f("srv.pem"))

	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubDER, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	os.WriteFile(f("sa.pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644)
	privDER, _ := x509.MarshalPKCS8PrivateKey(rk)
	for i, n := range []string{"k1", "k2", "k3", "k4"} {
		os.WriteFile(f(n+".hex"), bytes.Repeat([]byte{"0a0b0c0d"[2*i], "0a0b0c0d"[2*i+1]}, 32), 0o600)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr = l.Addr().String()
	l.Close()
	sa, _ := json.Marshal(map[string]string{"type": "service_account", "project_id": "hsmgate", "private_key_id": "k1", "client_email": "sdk@example.test",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})), "token_uri": "https://" + addr + "/oauth2/token"})
	saFile = f("sa.json")
	os.WriteFile(saFile, sa, 0o600)
	os.WriteFile(f("hsmgate.yaml"), []byte(fmt.Sprintf(`listen: %s
tls: {cert: %s, key: %s, client_ca: %s}
kmsgrpc: {enabled: true}
tokens: [{name: soft, type: soft, keys: {m1: %s, m2: %s, m3: %s, m4: %s}}]
keys:
  seal: {kmsgrpc: true, kmsjson_usage: encrypt_decrypt, versions: [{token: soft, label: m1}], aad: {mode: fixed}}
  sig:  {kmsgrpc: true, kmsjson_usage: sign_verify, versions: [{token: soft, label: m2}], aad: {mode: fixed}}
  mac:  {kmsgrpc: true, kmsjson_usage: generate_verify_mac, versions: [{token: soft, label: m3}], aad: {mode: fixed}}
  hidden: {versions: [{token: soft, label: m4}], aad: {mode: fixed}}
clients:
  - name: sdk
    jwt: {issuer: sdk@example.test, public_key_file: %s, no_cert: true, allow_from: ["127.0.0.1"]}
    keys: {seal: {ops: [encrypt, decrypt]}, sig: {ops: [sign]}, mac: {ops: [generate_mac, verify_mac]}}
`, addr, f("srv.pem"), f("srv.key"), f("ca.pem"), f("k1.hex"), f("k2.hex"), f("k3.hex"), f("k4.hex"), f("sa.pub"))), 0o600)
	cmd := exec.Command(bin, "serve", "-config", f("hsmgate.yaml"))
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Println(err)
		return 1
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return m.Run()
}

func client(t *testing.T) *kms.KeyManagementClient {
	c, err := kms.NewKeyManagementClient(context.Background(), option.WithEndpoint(addr), option.WithCredentialsFile(saFile))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func code(err error) codes.Code { return status.Code(err) }

func TestEncryptDecrypt(t *testing.T) {
	c, ctx := client(t), context.Background()
	pt := []byte("a secret of the test")
	enc, err := c.Encrypt(ctx, &kmspb.EncryptRequest{Name: ring + "seal", Plaintext: pt, PlaintextCrc32C: crc(pt)})
	if err != nil {
		t.Fatal(err)
	}
	if !enc.VerifiedPlaintextCrc32C || enc.Name != ring+"seal/cryptoKeyVersions/1" || enc.CiphertextCrc32C.GetValue() != crc(enc.Ciphertext).GetValue() {
		t.Errorf("%+v", enc)
	}
	dec, err := c.Decrypt(ctx, &kmspb.DecryptRequest{Name: ring + "seal", Ciphertext: enc.Ciphertext, CiphertextCrc32C: crc(enc.Ciphertext)})
	if err != nil || !bytes.Equal(dec.Plaintext, pt) || !dec.UsedPrimary || dec.PlaintextCrc32C.GetValue() != crc(pt).GetValue() {
		t.Fatalf("%+v %v", dec, err)
	}
	if _, err := c.Decrypt(ctx, &kmspb.DecryptRequest{Name: ring + "seal", Ciphertext: enc.Ciphertext[:len(enc.Ciphertext)-3]}); code(err) != codes.InvalidArgument {
		t.Errorf("a damaged ciphertext: %v", err)
	}
}

func TestSignWithThePublicKey(t *testing.T) {
	c, ctx := client(t), context.Background()
	name := ring + "sig/cryptoKeyVersions/1"
	pub, err := c.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	if pub.Algorithm != kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256 || pub.Name != name || pub.PemCrc32C.GetValue() != crc([]byte(pub.Pem)).GetValue() {
		t.Errorf("%+v", pub)
	}
	blk, _ := pem.Decode([]byte(pub.Pem))
	pk, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256([]byte("to be signed"))
	sig, err := c.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{Name: name, Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: d[:]}}, DigestCrc32C: crc(d[:])})
	if err != nil {
		t.Fatal(err)
	}
	if !sig.VerifiedDigestCrc32C || !ecdsa.VerifyASN1(pk.(*ecdsa.PublicKey), d[:], sig.Signature) {
		t.Errorf("the signature does not verify")
	}
	if _, err := c.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{Name: name, Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha384{Sha384: make([]byte, 48)}}}); code(err) != codes.InvalidArgument {
		t.Errorf("a SHA-384 digest: %v", err)
	}
}

func TestMac(t *testing.T) {
	c, ctx := client(t), context.Background()
	name := ring + "mac/cryptoKeyVersions/1"
	m, err := c.MacSign(ctx, &kmspb.MacSignRequest{Name: name, Data: []byte("data"), DataCrc32C: crc([]byte("data"))})
	if err != nil || len(m.Mac) != 32 || !m.VerifiedDataCrc32C {
		t.Fatalf("%+v %v", m, err)
	}
	v, err := c.MacVerify(ctx, &kmspb.MacVerifyRequest{Name: name, Data: []byte("data"), Mac: m.Mac})
	if err != nil || !v.Success {
		t.Errorf("%+v %v", v, err)
	}
	v, err = c.MacVerify(ctx, &kmspb.MacVerifyRequest{Name: name, Data: []byte("other"), Mac: m.Mac})
	if err != nil || v.Success {
		t.Errorf("%+v %v", v, err)
	}
}

func TestMetadataAndRefusals(t *testing.T) {
	c, ctx := client(t), context.Background()
	k, err := c.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: ring + "seal"})
	if err != nil || k.Purpose != kmspb.CryptoKey_ENCRYPT_DECRYPT || k.Primary == nil || k.Primary.State != kmspb.CryptoKeyVersion_ENABLED || k.Primary.ProtectionLevel != kmspb.ProtectionLevel_HSM {
		t.Errorf("%+v %v", k, err)
	}
	n := 0
	it := c.ListCryptoKeys(ctx, &kmspb.ListCryptoKeysRequest{Parent: "projects/hsmgate/locations/global/keyRings/main"})
	for {
		k, err := it.Next()
		if err != nil {
			break
		}
		n++
		if strings.HasSuffix(k.Name, "hidden") {
			t.Error("a key that is not on the face is listed")
		}
	}
	if n != 3 {
		t.Errorf("listed %d keys", n)
	}
	r, err := c.GenerateRandomBytes(ctx, &kmspb.GenerateRandomBytesRequest{Location: "projects/hsmgate/locations/global", LengthBytes: 32})
	if err != nil || len(r.Data) != 32 {
		t.Errorf("%v", err)
	}
	for name, err := range map[string]error{
		"hidden": func() error {
			_, e := c.Encrypt(ctx, &kmspb.EncryptRequest{Name: ring + "hidden", Plaintext: []byte("x")})
			return e
		}(),
		"no such": func() error {
			_, e := c.Encrypt(ctx, &kmspb.EncryptRequest{Name: ring + "nope", Plaintext: []byte("x")})
			return e
		}(),
		"no right": func() error {
			_, e := c.Decrypt(ctx, &kmspb.DecryptRequest{Name: ring + "sig", Ciphertext: []byte("x")})
			return e
		}(),
		"destroy": func() error {
			_, e := c.DestroyCryptoKeyVersion(ctx, &kmspb.DestroyCryptoKeyVersionRequest{Name: ring + "seal/cryptoKeyVersions/1"})
			return e
		}(),
	} {
		if code(err) == codes.OK {
			t.Errorf("%s was not refused", name)
		}
	}
}
