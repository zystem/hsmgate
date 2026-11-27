package kmsrest

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/zystem/hsmgate/internal/policy"
)

// A token given under one list of audiences is not good under another; a token for a client secret has no "aud" behind it and stays (the review of 2026-11-22, finding 2).
func TestTokenDiesWithTheAudienceList(t *testing.T) {
	r := newRig(t)
	reload := func(audiences ...string) {
		r.cfg.KMSRest.Audiences = audiences
		creds, err := LoadCreds(r.cfg)
		if err != nil {
			t.Fatal(err)
		}
		r.f.Reload(r.cfg, nil, policy.New(r.cfg, nil), func(*http.Request) (string, bool) { return "", true }, creds)
	}
	_, app := r.token(url.Values{"grant_type": {"client_credentials"}, "client_id": {"app-client"}, "client_secret": {secret}})
	code, cert := r.token(url.Values{"grant_type": {"client_credentials"}, "client_id": {"cert-client"}, "client_assertion_type": {assertionTy}, "client_assertion": {r.assertion("cert-client", r.rsaKey)}})
	status := func(tok string) int { st, _, _ := r.do("GET", "/keys", tok, nil); return st }
	if code != 200 || status(app) != 200 || status(cert) != 200 {
		t.Fatal("both tokens are good before")
	}
	r.log.Reset()
	reload("https://another.example.test/token")
	if st := status(cert); st != 401 || !strings.Contains(r.log.String(), `"result":"credential_changed"`) {
		t.Errorf("the token given under the former list: %d %s", st, r.log.String())
	}
	if status(app) != 200 {
		t.Error("the token for a client secret was ended")
	}
}
