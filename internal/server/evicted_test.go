package server

import (
	"bytes"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zystem/hsmgate/internal/config"
)

// /metrics names the count of evicted access tokens for each face that gives them.
func TestMetricsCountEvictedTokens(t *testing.T) {
	dir := t.TempDir()
	ca := mk(t, "ca", nil, true, false)
	srvCert := mk(t, "hsmgate", &ca, false, true)
	cfg := baseConfig(t, dir, ca, srvCert)
	cfg.AdminSocket = filepath.Join(dir, "admin.sock")
	cfg.Metrics.Enabled, cfg.Metrics.Detail = true, "basic"
	cfg.KMSRest.Enabled, cfg.KMSRest.Tenant = true, "t"
	cfg.KMSGRPC.Enabled, cfg.KMSGRPC.TokenPath = true, "/token"
	cfg.Keys["bao-seal"] = config.Key{KMSRest: true, KMSGRPC: true, KMSJSONUsage: "encrypt_decrypt", AAD: config.AAD{Mode: "fixed"}, Versions: cfg.Keys["bao-seal"].Versions}
	s, err := New(cfg, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.metricsHandler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	body := w.Body.String()
	for _, face := range []string{"kmsrest", "kmsgrpc"} {
		for _, reason := range []string{"client_limit", "table_full"} {
			if line := `hsmgate_tokens_evicted_total{face="` + face + `",reason="` + reason + `"} 0`; !strings.Contains(body, line) {
				t.Errorf("no line %s", line)
			}
		}
	}
	if !strings.Contains(body, "# TYPE hsmgate_tokens_evicted_total counter") {
		t.Error("the type of the metric is not counter")
	}
}
