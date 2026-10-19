// Package authn maps a verified TLS client certificate to a client of the policy. Nothing in a header is believed.
package authn

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"

	"github.com/zystem/hsmgate/internal/config"
)

type Authenticator struct{ clients []config.Client }

func New(clients []config.Client) *Authenticator { return &Authenticator{clients} }

// Identify returns the client's name for the leaf certificate of a handshake the server has already verified.
func (a *Authenticator) Identify(cs *tls.ConnectionState) (string, bool) {
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return "", false
	}
	leaf := cs.PeerCertificates[0]
	sum := sha256.Sum256(leaf.Raw)
	pin := hex.EncodeToString(sum[:])
	for _, c := range a.clients {
		id := c.Identity
		if id.SHA256 != "" && id.SHA256 == pin {
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
