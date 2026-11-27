package kmsgrpc

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zystem/hsmgate/internal/policy"
)

// An access token given under one list of token audiences is not good under another (the review of 2026-11-22, finding 2).
func TestTokenDiesWithTheAudienceList(t *testing.T) {
	r := newRig(t)
	reload := func(audiences ...string) {
		r.cfg.KMSGRPC.TokenAudiences = audiences
		r.f.Reload(r.cfg, nil, policy.New(r.cfg, nil), func(*http.Request) (string, bool) { return "", true }, mustCreds(t, r.cfg))
	}
	resp, err := r.client.PostForm(r.srv.URL+r.f.TokenPath, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {r.jwt("app@example.test", r.rsaKey, time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var tk struct {
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(resp.Body).Decode(&tk)
	call := func() int {
		code, _, _ := r.rpc("GenerateRandomBytes", tk.AccessToken, (&writer{}).str(1, "projects/hsmgate/locations/global").u64(2, 8))
		return code
	}
	if resp.StatusCode != 200 || call() != 0 {
		t.Fatalf("the token is good before: %d", resp.StatusCode)
	}
	r.log.Reset()
	reload("https://another.example.test/token")
	if c := call(); c != cUnauth || !strings.Contains(r.log.String(), `"result":"credential_changed"`) {
		t.Errorf("the token given under the former list: %d %s", c, r.log.String())
	}
}
