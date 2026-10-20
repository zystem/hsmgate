package authn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/zystem/hsmgate/internal/config"
)

type cert struct {
	c *x509.Certificate
	k *ecdsa.PrivateKey
}

func issue(t *testing.T, ca *cert, cn string, uri string, eku []x509.ExtKeyUsage, notAfter time.Time) cert {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: eku}
	if ca == nil { // a CA, self-signed
		tpl.IsCA, tpl.BasicConstraintsValid, tpl.KeyUsage = true, true, x509.KeyUsageCertSign
		tpl.ExtKeyUsage = nil
	}
	if uri != "" {
		u, _ := url.Parse(uri)
		tpl.URIs = []*url.URL{u}
	}
	parent, pk := tpl, k
	if ca != nil {
		parent, pk = ca.c, ca.k
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &k.PublicKey, pk)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return cert{c, k}
}

func state(cs ...*x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{PeerCertificates: cs}
}

func TestIdentify(t *testing.T) {
	ca := issue(t, nil, "ca", "", nil, time.Now().Add(time.Hour))
	other := issue(t, nil, "other ca", "", nil, time.Now().Add(time.Hour))
	pool := x509.NewCertPool()
	pool.AddCert(ca.c)
	client := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	byCN := issue(t, &ca, "app", "", client, time.Now().Add(time.Hour))
	byURI := issue(t, &ca, "whatever", "spiffe://example.org/ns/shop/sa/core", client, time.Now().Add(time.Hour))
	byPin := issue(t, &ca, "pinned", "", client, time.Now().Add(time.Hour))
	pin := sha256.Sum256(byPin.c.Raw)
	noName := issue(t, &ca, "", "", client, time.Now().Add(time.Hour))

	clients := []config.Client{
		{Name: "by-cn", Identity: config.Identity{CN: "app"}},
		{Name: "by-uri", Identity: config.Identity{URI: "spiffe://example.org/ns/shop/sa/core"}},
		{Name: "by-pin", Identity: config.Identity{SHA256: hex.EncodeToString(pin[:])}},
		{Name: "no-cert-client"}, // a client with no identity (it signs its requests and shows no certificate) is nobody's certificate
	}
	a := New(clients, pool)
	for name, tc := range map[string]struct {
		cs   *tls.ConnectionState
		want string
	}{
		"CN":                       {state(byCN.c), "by-cn"},
		"URI SAN, any CN":          {state(byURI.c), "by-uri"},
		"pinned certificate":       {state(byPin.c), "by-pin"},
		"a certificate with no CN": {state(noName.c), ""},
		"no state":                 {nil, ""},
		"no certificate":           {state(), ""},
	} {
		if got, ok := a.Identify(tc.cs); got != tc.want || ok != (tc.want != "") {
			t.Errorf("%s: %q %v, want %q", name, got, ok, tc.want)
		}
	}
	// the chain is judged: a certificate of another CA with the right name, an expired one, one made for servers only
	forged := issue(t, &other, "app", "", client, time.Now().Add(time.Hour))
	expired := issue(t, &ca, "app", "", client, time.Now().Add(time.Hour))
	serverOnly := issue(t, &ca, "app", "", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, time.Now().Add(time.Hour))
	for name, c := range map[string]*x509.Certificate{"another CA": forged.c, "server-only usage": serverOnly.c} {
		if got, ok := a.Identify(state(c)); ok {
			t.Errorf("%s was accepted as %q", name, got)
		}
	}
	a.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	if got, ok := a.Identify(state(expired.c)); ok {
		t.Errorf("an expired certificate was accepted as %q", got)
	}
	// a certificate that is shown with an intermediate that the peer sends is judged with it
	// and a pin does not need the chain only when no CA is given (tests): with a CA, a pinned certificate of another CA is still refused
	a2 := New(clients, pool)
	foreignPin := issue(t, &other, "pinned", "", client, time.Now().Add(time.Hour))
	pin2 := sha256.Sum256(foreignPin.c.Raw)
	a3 := New([]config.Client{{Name: "pinned-foreign", Identity: config.Identity{SHA256: hex.EncodeToString(pin2[:])}}}, pool)
	if got, ok := a3.Identify(state(foreignPin.c)); ok {
		t.Errorf("a certificate of another CA was accepted by its pin as %q", got)
	}
	_ = a2
}
