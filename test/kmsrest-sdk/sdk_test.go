// A black-box test of the REST face with the official Go client library of the cloud key vault whose API the face imitates: the real hsmgate binary is built and started, with the
// credential of a client, and the library calls it as it calls the service (a token from the authority, a challenge, then JSON over HTTPS). It is a module of its own, so that the
// library does not become a dependency of the service.
package kmsrestsdk

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

const (
	tenant       = "hsmgate"
	clientID     = "sdk-client"
	certClientID = "sdk-cert-client"
	secret       = "a-client-secret-of-the-test-0123456789"
)

var (
	addr          string
	httpc         *http.Client
	certClientPEM []byte
	certClientKey *rsa.PrivateKey
)

func TestMain(m *testing.M) { os.Exit(run(m)) }

func run(m *testing.M) int {
	workdir, err := os.MkdirTemp("", "kmsrest-sdk")
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
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "hsmgate"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &sk.PublicKey, sk)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, _ := x509.MarshalECPrivateKey(sk)
	os.WriteFile(f("srv.pem"), certPEM, 0o600)
	os.WriteFile(f("srv.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	os.WriteFile(f("secret"), []byte(secret+"\n"), 0o600)
	// the credential of a second client: a certificate with an RSA key, which the client proves by a signed assertion (the library signs it with PS256 and writes "nbf" and no "iat";
	// the service checks its subject and its audience)
	ck, _ := rsa.GenerateKey(rand.Reader, 2048)
	ctpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: certClientID}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	cder, _ := x509.CreateCertificate(rand.Reader, ctpl, ctpl, &ck.PublicKey, ck)
	certClientPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cder})
	certClientKey = ck
	os.WriteFile(f("client.pem"), certClientPEM, 0o600)
	for i, n := range []string{"k1", "k2", "k3", "k4"} {
		os.WriteFile(f(n+".hex"), bytes.Repeat([]byte{"0a0b0c0d"[2*i], "0a0b0c0d"[2*i+1]}, 32), 0o600)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr = l.Addr().String()
	l.Close()
	os.WriteFile(f("hsmgate.yaml"), []byte(fmt.Sprintf(`listen: %s
tls: {cert: %s, key: %s, client_ca: %s}
kmsrest: {enabled: true, tenant: %s, audiences: ["https://%s/%s/oauth2/v2.0/token"]}
tokens: [{name: soft, type: soft, keys: {m1: %s, m2: %s, m3: %s, m4: %s}}]
keys:
  seal: {kmsrest: true, kmsjson_usage: encrypt_decrypt, versions: [{token: soft, label: m1}], aad: {mode: fixed}}
  sig:  {kmsrest: true, kmsjson_usage: sign_verify, versions: [{token: soft, label: m2}], aad: {mode: fixed}}
  mac:  {kmsrest: true, kmsjson_usage: generate_verify_mac, versions: [{token: soft, label: m3}], aad: {mode: fixed}}
  hidden: {versions: [{token: soft, label: m4}], aad: {mode: fixed}}
clients:
  - name: sdk
    oauth: {client_id: %s, secret_file: %s, no_cert: true, allow_from: ["127.0.0.1"]}
    keys: {seal: {ops: [encrypt, decrypt]}, sig: {ops: [sign, verify]}, mac: {ops: [generate_mac, verify_mac]}}
  - name: sdkcert
    oauth: {client_id: %s, public_key_file: %s, no_cert: true, allow_from: ["127.0.0.1"]}
    keys: {sig: {ops: [sign, verify]}}
`, addr, f("srv.pem"), f("srv.key"), f("srv.pem"), tenant, addr, tenant, f("k1.hex"), f("k2.hex"), f("k3.hex"), f("k4.hex"), clientID, f("secret"), certClientID, f("client.pem"))), 0o600)
	cmd := exec.Command(bin, "serve", "-config", f("hsmgate.yaml"))
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Println(err)
		return 1
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	httpc = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: true}, Timeout: 20 * time.Second}
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return m.Run()
}

func client(t *testing.T, sec string) *azkeys.Client {
	co := azcore.ClientOptions{Transport: httpc, Cloud: cloud.Configuration{ActiveDirectoryAuthorityHost: "https://" + addr}}
	cred, err := azidentity.NewClientSecretCredential(tenant, clientID, sec, &azidentity.ClientSecretCredentialOptions{ClientOptions: co, DisableInstanceDiscovery: true})
	if err != nil {
		t.Fatal(err)
	}
	c, err := azkeys.NewClient("https://"+addr, cred, &azkeys.ClientOptions{ClientOptions: azcore.ClientOptions{Transport: httpc, Retry: azcore.ClientOptions{}.Retry}, DisableChallengeResourceVerification: true})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSignAndGetKey(t *testing.T) {
	c, ctx := client(t, secret), context.Background()
	k, err := c.GetKey(ctx, "sig", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if k.Key == nil || *k.Key.Kty != azkeys.KeyTypeECHSM || *k.Key.Crv != azkeys.CurveNameP256 {
		t.Fatalf("%+v", k.Key)
	}
	pub := ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(k.Key.X), Y: new(big.Int).SetBytes(k.Key.Y)}
	d := sha256.Sum256([]byte("to be signed"))
	alg := azkeys.SignatureAlgorithmES256
	s, err := c.Sign(ctx, "sig", k.Key.KID.Version(), azkeys.SignParameters{Algorithm: &alg, Value: d[:]}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Result) != 64 || !ecdsa.Verify(&pub, d[:], new(big.Int).SetBytes(s.Result[:32]), new(big.Int).SetBytes(s.Result[32:])) {
		t.Fatal("the signature does not verify")
	}
	v, err := c.Verify(ctx, "sig", "", azkeys.VerifyParameters{Algorithm: &alg, Digest: d[:], Signature: s.Result}, nil)
	if err != nil || v.Value == nil || !*v.Value {
		t.Errorf("verify: %v %v", v, err)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	c, ctx := client(t, secret), context.Background()
	alg := azkeys.EncryptionAlgorithmA256GCM
	e, err := c.Encrypt(ctx, "seal", "", azkeys.KeyOperationParameters{Algorithm: &alg, Value: []byte("hello")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	d, err := c.Decrypt(ctx, "seal", "", azkeys.KeyOperationParameters{Algorithm: &alg, Value: e.Result}, nil)
	if err != nil || string(d.Result) != "hello" {
		t.Fatalf("%v %v", d, err)
	}
}

func TestMacListAndRefusals(t *testing.T) {
	c, ctx := client(t, secret), context.Background()
	alg := azkeys.SignatureAlgorithmHS256
	m, err := c.Sign(ctx, "mac", "", azkeys.SignParameters{Algorithm: &alg, Value: []byte("data")}, nil)
	if err != nil || len(m.Result) != 32 {
		t.Fatalf("%v", err)
	}
	n := 0
	p := c.NewListKeyPropertiesPager(nil)
	for p.More() {
		page, err := p.NextPage(ctx)
		if err != nil {
			t.Fatal(err)
		}
		n += len(page.Value)
	}
	if n != 3 {
		t.Errorf("listed %d keys", n)
	}
	ea := azkeys.EncryptionAlgorithmA256GCM
	if _, err := c.Encrypt(ctx, "hidden", "", azkeys.KeyOperationParameters{Algorithm: &ea, Value: []byte("x")}, nil); err == nil {
		t.Error("a key that is not on the face was used")
	}
	if _, err := client(t, secret+"x").GetKey(ctx, "sig", "", nil); err == nil {
		t.Error("a wrong secret was accepted")
	}
}

// A client that proves itself with a certificate sends a signed assertion. The official library signs it with PS256 and writes "nbf" and no "iat"; the service takes it only with the
// client as its subject and its own token endpoint as its audience (RFC 7523 section 3), and answers.
func TestCertificateAssertion(t *testing.T) {
	blk, _ := pem.Decode(certClientPEM)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	co := azcore.ClientOptions{Transport: httpc, Cloud: cloud.Configuration{ActiveDirectoryAuthorityHost: "https://" + addr}}
	cred, err := azidentity.NewClientCertificateCredential(tenant, certClientID, []*x509.Certificate{cert}, certClientKey, &azidentity.ClientCertificateCredentialOptions{ClientOptions: co, DisableInstanceDiscovery: true})
	if err != nil {
		t.Fatal(err)
	}
	c, err := azkeys.NewClient("https://"+addr, cred, &azkeys.ClientOptions{ClientOptions: azcore.ClientOptions{Transport: httpc}, DisableChallengeResourceVerification: true})
	if err != nil {
		t.Fatal(err)
	}
	if k, err := c.GetKey(context.Background(), "sig", "", nil); err != nil || k.Key == nil {
		t.Fatalf("%v", err)
	}
}
