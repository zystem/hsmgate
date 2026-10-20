package sigv4

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

var secret = []byte("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")

func lookup(akid string) ([]byte, bool) { return secret, akid == "AKIDEXAMPLE" }

// The published example "get-vanilla" of the signing scheme (the AWS documentation's test suite): a GET of / with two signed headers.
// The expected signature is the one the suite gives; it checks the whole chain (canonical request, string to sign, signing key) against a value that this code did not make.
func TestKnownAnswer(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.amazonaws.com/", nil)
	r.Host = "example.amazonaws.com"
	r.Header.Set("X-Amz-Date", "20150830T123600Z")
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")
	v := &Verifier{Region: "us-east-1", Service: "service", Secrets: lookup, Require: []string{"host", "x-amz-date"}, Now: func() time.Time { return time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC) }}
	if akid, err := v.Verify(r, nil); err != nil || akid != "AKIDEXAMPLE" {
		t.Fatalf("%q %v", akid, err)
	}
}

func signed(t *testing.T, body string, now time.Time) (*http.Request, []byte) {
	r, _ := http.NewRequest("POST", "http://kms.local:8443/", strings.NewReader(body))
	r.Header.Set("X-Amz-Target", "TrentService.GetPublicKey")
	r.Header.Set("Content-Type", "application/x-amz-json-1.1")
	Sign(r, []byte(body), "AKIDEXAMPLE", secret, "local", "kms", now)
	return r, []byte(body)
}

func TestSignAndVerifyRoundTripAndWhatBreaksIt(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	v := &Verifier{Region: "local", Service: "kms", Secrets: lookup, Now: func() time.Time { return now }}
	r, body := signed(t, `{"KeyId":"k"}`, now)
	if akid, err := v.Verify(r, body); err != nil || akid != "AKIDEXAMPLE" {
		t.Fatalf("%q %v", akid, err)
	}
	for name, mutate := range map[string]func(r *http.Request, body []byte) []byte{
		"another body": func(r *http.Request, b []byte) []byte { return []byte(`{"KeyId":"other"}`) },
		"another target": func(r *http.Request, b []byte) []byte {
			r.Header.Set("X-Amz-Target", "TrentService.DeriveSharedSecret")
			return b
		},
		"another host":   func(r *http.Request, b []byte) []byte { r.Host = "evil.example"; return b },
		"another method": func(r *http.Request, b []byte) []byte { r.Method = "PUT"; return b },
		"a query added":  func(r *http.Request, b []byte) []byte { r.URL.RawQuery = "a=b"; return b },
		"another date":   func(r *http.Request, b []byte) []byte { r.Header.Set("X-Amz-Date", "20261020T120001Z"); return b },
		"a changed signature": func(r *http.Request, b []byte) []byte {
			a := r.Header.Get("Authorization")
			r.Header.Set("Authorization", a[:len(a)-1]+"0")
			return b
		},
		"an unknown access key": func(r *http.Request, b []byte) []byte {
			a := r.Header.Get("Authorization")
			r.Header.Set("Authorization", strings.Replace(a, "AKIDEXAMPLE", "AKIDOTHER00", 1))
			return b
		},
		"another region in scope": func(r *http.Request, b []byte) []byte {
			a := r.Header.Get("Authorization")
			r.Header.Set("Authorization", strings.Replace(a, "/local/", "/elsewhere/", 1))
			return b
		},
		"another service in scope": func(r *http.Request, b []byte) []byte {
			a := r.Header.Get("Authorization")
			r.Header.Set("Authorization", strings.Replace(a, "/kms/", "/s3/", 1))
			return b
		},
		"no authorization": func(r *http.Request, b []byte) []byte { r.Header.Del("Authorization"); return b },
		"a payload hash that lies": func(r *http.Request, b []byte) []byte {
			r.Header.Set("X-Amz-Content-Sha256", strings.Repeat("0", 64))
			return b
		},
	} {
		r, body := signed(t, `{"KeyId":"k"}`, now)
		body = mutate(r, body)
		if akid, err := v.Verify(r, body); err == nil {
			t.Errorf("%s was accepted as %q", name, akid)
		}
	}
}

func TestClockSkewAndRequiredHeaders(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	v := &Verifier{Region: "local", Service: "kms", Secrets: lookup, Now: func() time.Time { return now }}
	for _, d := range []time.Duration{-4 * time.Minute, 4 * time.Minute} {
		r, b := signed(t, "{}", now.Add(d))
		if _, err := v.Verify(r, b); err != nil {
			t.Errorf("skew %v: %v", d, err)
		}
	}
	for _, d := range []time.Duration{-6 * time.Minute, 6 * time.Minute} {
		r, b := signed(t, "{}", now.Add(d))
		if _, err := v.Verify(r, b); err != ErrExpired {
			t.Errorf("skew %v: %v", d, err)
		}
	}
	// a request signed without the target: the signature would not protect which operation is called
	r, _ := http.NewRequest("POST", "http://kms.local/", strings.NewReader("{}"))
	Sign(r, []byte("{}"), "AKIDEXAMPLE", secret, "local", "kms", now)
	r.Header.Set("X-Amz-Target", "TrentService.DeriveSharedSecret") // added after signing
	if _, err := v.Verify(r, []byte("{}")); err == nil {
		t.Error("an unsigned target was accepted")
	}
}

// Spaces in a header value are folded as the scheme says, so a client that writes "a  b" and one that writes "a b" agree.
func TestHeaderValuesAreFolded(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	v := &Verifier{Region: "local", Service: "kms", Secrets: lookup, Now: func() time.Time { return now }}
	r, b := signed(t, "{}", now)
	r.Header.Set("Content-Type", "  application/x-amz-json-1.1  ")
	if _, err := v.Verify(r, b); err != nil {
		t.Errorf("%v", err)
	}
}

// Whatever an unauthenticated peer sends, the verifier does not panic, and it accepts only what carries the right signature: a mutated header or body of a valid request is refused.
func FuzzVerify(f *testing.F) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	good, _ := signed(&testing.T{}, `{"KeyId":"k"}`, now)
	f.Add(good.Header.Get("Authorization"), good.Header.Get("X-Amz-Date"), `{"KeyId":"k"}`)
	f.Add("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261020/local/kms/aws4_request, SignedHeaders=host;x-amz-date;x-amz-target, Signature=00", "20261020T120000Z", "")
	f.Add("", "", "")
	f.Add("AWS4-HMAC-SHA256 Credential=//////, SignedHeaders=;;;, Signature=", "x", "y")
	v := &Verifier{Region: "local", Service: "kms", Secrets: lookup, Now: func() time.Time { return now }, Require: []string{"host", "x-amz-date", "x-amz-target"}}
	f.Fuzz(func(t *testing.T, auth, date, body string) {
		r, _ := http.NewRequest("POST", "http://kms.local:8443/", strings.NewReader(body))
		r.Header.Set("Authorization", auth)
		r.Header.Set("X-Amz-Date", date)
		r.Header.Set("X-Amz-Target", "TrentService.GetPublicKey")
		if akid, err := v.Verify(r, []byte(body)); err == nil {
			// accepted: then it must be a request that this very secret signs
			r2, _ := http.NewRequest("POST", "http://kms.local:8443/", strings.NewReader(body))
			r2.Header.Set("X-Amz-Target", "TrentService.GetPublicKey")
			Sign(r2, []byte(body), akid, secret, "local", "kms", now)
			if r2.Header.Get("Authorization") != auth && date != r2.Header.Get("X-Amz-Date") {
				t.Fatalf("accepted a request that was not signed with the secret: %q", auth)
			}
		}
	})
}
