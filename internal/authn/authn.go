// Package authn maps a verified TLS client certificate to a client of the policy. Nothing in a header is believed.
// The chain is checked again at every request against the CA of the current generation, so that replacing the CA or a certificate that has expired
// ends access on connections that are already open, not only on new ones.
package authn

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"time"

	"github.com/zystem/hsmgate/internal/config"
)

type Authenticator struct {
	clients []config.Client
	roots   *x509.CertPool
	now     func() time.Time
}

// New: roots is the client CA of this generation (nil: the chain is not checked again, which is for tests that have no CA).
func New(clients []config.Client, roots *x509.CertPool) *Authenticator {
	return &Authenticator{clients: clients, roots: roots, now: time.Now}
}

// Identify returns the client's name for the leaf certificate of the connection.
func (a *Authenticator) Identify(cs *tls.ConnectionState) (string, bool) {
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return "", false
	}
	leaf := cs.PeerCertificates[0]
	if a.roots != nil {
		inter := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: a.roots, Intermediates: inter, CurrentTime: a.now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			return "", false
		}
	}
	sum := sha256.Sum256(leaf.Raw)
	pin := hex.EncodeToString(sum[:])
	for _, c := range a.clients {
		id := c.Identity
		if id.SHA256 != "" && strings.EqualFold(id.SHA256, pin) {
			return c.Name, true
		}
		if id.URI != "" {
			for _, u := range leaf.URIs {
				if u.String() == id.URI {
					return c.Name, true
				}
			}
		}
		if id.CN != "" && id.CN == leaf.Subject.CommonName {
			return c.Name, true
		}
	}
	return "", false
}
