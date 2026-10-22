package kmsgrpc

// Authentication of the gRPC face. A client holds a service account: the private key of an RSA pair, which the service knows by its public half. Like the client libraries of the
// service do, it can (1) send a token that it signed itself (a JWT, RS256) as the bearer, or (2) trade a signed assertion for an opaque access token at the token endpoint of this
// service (the grant "urn:ietf:params:oauth:grant-type:jwt-bearer") and send that. Either way the bearer is bound to the client of the credential; the address, the client certificate
// (if one is shown it must be the client's) and the rule about calls without a certificate are judged on every request, so that a removed credential or a changed list of addresses
// ends access at once.

import (
	"crypto/rsa"
	"fmt"
	"net/netip"

	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/oauth"
)

// Cred is a service account of a client.
type Cred struct {
	Client string
	Issuer string
	Key    *rsa.PublicKey
	NoCert bool
	From   []netip.Prefix
}

// LoadCreds reads the public keys of the service accounts of the clients that have a jwt credential, by issuer.
func LoadCreds(cfg *config.Config) (map[string]Cred, error) {
	creds := map[string]Cred{}
	for _, c := range cfg.Clients {
		if c.JWT == nil {
			continue
		}
		pub, err := oauth.ReadRSAPublic(c.JWT.PublicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("client %s: jwt.public_key_file: %w", c.Name, err)
		}
		from, err := (config.SigV4{AllowFrom: c.JWT.AllowFrom}).Prefixes()
		if err != nil {
			return nil, fmt.Errorf("client %s: %w", c.Name, err)
		}
		creds[c.JWT.Issuer] = Cred{Client: c.Name, Issuer: c.JWT.Issuer, Key: pub, NoCert: c.JWT.NoCert, From: from}
	}
	return creds, nil
}
