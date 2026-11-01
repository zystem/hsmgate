package sigv4

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func BenchmarkSignAndVerify(b *testing.B) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	v := &Verifier{Region: "local", Service: "kms", Secrets: lookup, Now: func() time.Time { return now }}
	body := `{"KeyId":"k","Plaintext":"AAAA"}`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r, _ := http.NewRequest("POST", "http://kms.local:8443/", strings.NewReader(body))
		r.Header.Set("X-Amz-Target", "TrentService.Encrypt")
		Sign(r, []byte(body), "AKIDEXAMPLE", secret, "local", "kms", now)
		if _, err := v.Verify(r, []byte(body)); err != nil {
			b.Fatal(err)
		}
	}
}
