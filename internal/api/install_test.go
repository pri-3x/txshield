package api

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pri-3x/txshield/internal/config"
)

func installServer(t *testing.T, store *memStore, mutate func(*config.Config)) *Server {
	t.Helper()
	return engineServer(t, store, func(c *config.Config, _ *Engine) {
		c.API.InstallTokens = true
		if mutate != nil {
			mutate(c)
		}
	})
}

func issueToken(t *testing.T, s *Server, ip string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/v1/install", nil)
	req.RemoteAddr = ip + ":1234"
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	var out InstallResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out.Token
}

func authed(t *testing.T, s *Server, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	return do(t, s, method, path, &buf, map[string]string{"Content-Type": "application/json", "Authorization": "Bearer " + token})
}

func TestInstallTokensDisabledByDefault(t *testing.T) {
	s := engineServer(t, nil, nil)
	if rr, _ := issueToken(t, s, "203.0.113.1"); rr.Code != 422 {
		t.Fatalf("install must be off unless enabled: %d %s", rr.Code, rr.Body)
	}
}

func TestInstallTokenIsNeverStored(t *testing.T) {
	store := &memStore{}
	s := installServer(t, store, nil)
	rr, tok := issueToken(t, s, "203.0.113.1")
	if rr.Code != 201 || !strings.HasPrefix(tok, installPrefix) || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("issue: %d %s", rr.Code, rr.Body)
	}
	// persist:true is ignored for install-token requests.
	tx := map[string]any{"chainId": 1, "from": sender, "to": usdc, "data": approveMax, "persist": true}
	rr = authed(t, s, "POST", "/api/v1/analyze", tok, tx)
	if rr.Code != 200 {
		t.Fatalf("analyze: %d %s", rr.Code, rr.Body)
	}
	if len(store.reports) != 0 {
		t.Fatalf("install-token analysis was stored (%d rows)", len(store.reports))
	}
	// Control: the same request without the token is stored.
	if rr = post(t, s, "/api/v1/analyze", tx); rr.Code != 200 || len(store.reports) != 1 {
		t.Fatalf("control request: %d stored=%d", rr.Code, len(store.reports))
	}
}

func TestInstallTokenScope(t *testing.T) {
	s := installServer(t, &memStore{}, nil)
	_, tok := issueToken(t, s, "203.0.113.1")
	for _, p := range []string{"/api/v1/analyses", "/api/v1/stats", "/api/v1/address/" + sender + "?chainId=1"} {
		if rr := authed(t, s, "GET", p, tok, nil); rr.Code != 403 {
			t.Errorf("GET %s with install token -> %d, want 403", p, rr.Code)
		}
	}
	if rr := authed(t, s, "GET", "/api/v1/info", tok, nil); rr.Code != 200 {
		t.Errorf("info -> %d", rr.Code)
	}
}

func TestInstallTokenWithAPIKeys(t *testing.T) {
	key := strings.Repeat("k", 32)
	s := installServer(t, &memStore{}, func(c *config.Config) { c.API.APIKeys = []string{key} })
	_, tok := issueToken(t, s, "203.0.113.1")
	if tok == "" {
		t.Fatal("issuance must not need an API key")
	}
	tx := map[string]any{"chainId": 1, "from": sender, "to": usdc, "data": approveMax}
	if rr := authed(t, s, "POST", "/api/v1/analyze", tok, tx); rr.Code != 200 {
		t.Fatalf("install token with keys configured: %d %s", rr.Code, rr.Body)
	}
	if rr := post(t, s, "/api/v1/analyze", tx); rr.Code != 401 {
		t.Fatalf("no credentials: %d", rr.Code)
	}
	// History still needs the API key.
	if rr := authed(t, s, "GET", "/api/v1/analyses", key, nil); rr.Code != 200 {
		t.Fatalf("API key on history: %d %s", rr.Code, rr.Body)
	}
}

func TestInstallTokenRejectsForgery(t *testing.T) {
	s := installServer(t, &memStore{}, nil)
	_, tok := issueToken(t, s, "203.0.113.1")
	other := installServer(t, &memStore{}, nil) // different random secret
	tx := map[string]any{"chainId": 1, "from": sender, "to": usdc, "data": approveMax}
	if rr := authed(t, other, "POST", "/api/v1/analyze", tok, tx); rr.Code != 401 || errBody(t, rr).Code != "invalid_install_token" {
		t.Fatalf("token from another server: %d %s", rr.Code, rr.Body)
	}
	b := []byte(tok)
	b[len(b)-1] ^= 1
	if rr := authed(t, s, "POST", "/api/v1/analyze", string(b), tx); rr.Code != 401 {
		t.Fatalf("tampered token: %d", rr.Code)
	}
	if rr := authed(t, s, "POST", "/api/v1/analyze", installPrefix+"AAAA", tx); rr.Code != 401 {
		t.Fatalf("short token: %d", rr.Code)
	}
}

func TestInstallTokenSharedSecretSurvivesRestart(t *testing.T) {
	secret := strings.Repeat("s", 40)
	mut := func(c *config.Config) { c.API.InstallTokenSecret = secret }
	_, tok := issueToken(t, installServer(t, &memStore{}, mut), "203.0.113.1")
	tx := map[string]any{"chainId": 1, "from": sender, "to": usdc, "data": approveMax}
	if rr := authed(t, installServer(t, &memStore{}, mut), "POST", "/api/v1/analyze", tok, tx); rr.Code != 200 {
		t.Fatalf("same secret, new process: %d %s", rr.Code, rr.Body)
	}
}

func TestInstallRateLimits(t *testing.T) {
	s := installServer(t, &memStore{}, func(c *config.Config) { c.API.InstallRateRPS, c.API.InstallRateBurst = 0.001, 2 })
	_, tok := issueToken(t, s, "203.0.113.1")
	tx := map[string]any{"chainId": 1, "from": sender, "to": usdc, "data": approveMax}
	for i := range 2 {
		if rr := authed(t, s, "POST", "/api/v1/analyze", tok, tx); rr.Code != 200 {
			t.Fatalf("request %d: %d", i, rr.Code)
		}
	}
	if rr := authed(t, s, "POST", "/api/v1/analyze", tok, tx); rr.Code != 429 || rr.Header().Get("Retry-After") == "" {
		t.Fatalf("per-token limit: %d", rr.Code)
	}
	// A fresh token is not affected by the first one's bucket.
	_, tok2 := issueToken(t, s, "203.0.113.1")
	if rr := authed(t, s, "POST", "/api/v1/analyze", tok2, tx); rr.Code != 200 {
		t.Fatalf("second token: %d", rr.Code)
	}

	// Issuance is limited per IP.
	s = installServer(t, &memStore{}, nil)
	for i := range installIssueBurst {
		if rr, _ := issueToken(t, s, "198.51.100.7"); rr.Code != 201 {
			t.Fatalf("issue %d: %d", i, rr.Code)
		}
	}
	if rr, _ := issueToken(t, s, "198.51.100.7"); rr.Code != 429 {
		t.Fatalf("issuance limit: %d", rr.Code)
	}
	if rr, _ := issueToken(t, s, "198.51.100.8"); rr.Code != 201 {
		t.Fatalf("other IP: %d", rr.Code)
	}
}

func TestAnalyzeReportsServerTiming(t *testing.T) {
	s := engineServer(t, nil, nil)
	rr := post(t, s, "/api/v1/analyze", map[string]any{"chainId": 1, "from": sender, "to": usdc, "data": approveMax})
	st := rr.Header().Get("Server-Timing")
	for _, stage := range []string{"decode;dur=", "simulate;dur=", "context;dur=", "rules;dur=", "total;dur="} {
		if !strings.Contains(st, stage) {
			t.Fatalf("Server-Timing %q missing %s", st, stage)
		}
	}
	mr := do(t, s, "GET", "/metrics", nil, nil)
	if !strings.Contains(mr.Body.String(), `txshield_analysis_stage_duration_seconds_count{stage="rules"} 1`) {
		t.Fatal("stage histogram not recorded")
	}
}
