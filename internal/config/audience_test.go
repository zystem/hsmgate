package config

import (
	"strings"
	"testing"
)

// A face with a client that signs JWTs needs its audiences: without them a JWT made for another service that trusts the same key is taken.
func TestAudiencesAreRequiredForClientsThatSignJWTs(t *testing.T) {
	grpc := &Config{}
	grpc.Clients = []Client{{Name: "app", JWT: &JWT{}}}
	if got := strings.Join(grpc.UncheckedAudiences(), " "); got != "kmsgrpc.token_audiences kmsgrpc.bearer_audiences" {
		t.Errorf("gRPC: %q", got)
	}
	secret := &Config{}
	secret.Clients = []Client{{Name: "app", OAuth: &OAuth{SecretFile: "s"}}}
	if got := secret.UncheckedAudiences(); len(got) != 0 {
		t.Errorf("a client secret has no audience: %v", got)
	}
	key := &Config{}
	key.Clients = []Client{{Name: "app", OAuth: &OAuth{PublicKeyFile: "k"}}}
	if got := strings.Join(key.UncheckedAudiences(), " "); got != "kmsrest.audiences" {
		t.Errorf("REST: %q", got)
	}
	key.KMSRest.Audiences = []string{"https://kms.example.org/t"}
	if got := key.UncheckedAudiences(); len(got) != 0 {
		t.Errorf("with the list: %v", got)
	}
}
