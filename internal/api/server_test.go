package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pri-3x/txshield/internal/config"
	"github.com/pri-3x/txshield/internal/metrics"
	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/txerrors"
)

type fakeCheck struct {
	name     string
	critical bool
	err      error
}

func (f fakeCheck) Name() string                { return f.name }
func (f fakeCheck) Critical() bool              { return f.critical }
func (f fakeCheck) Check(context.Context) error { return f.err }

func newTestServer(t *testing.T, mutate func(*config.Config), checks ...interfaces.HealthChecker) *Server {
	t.Helper()
	cfg := config.Defaults()
	cfg.Chains.RPCURLs = map[uint64]string{11155111: "https://rpc.example/v2/SECRET", 1: "https://eth.example"}
	if mutate != nil {
		mutate(&cfg)
	}
	return New(Deps{
		Config:  cfg,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Metrics: metrics.New("test", "abc"),
		Checks:  checks,
	})
}

func do(t *testing.T, h http.Handler, method, path string, body io.Reader, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, body)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestHealthStatuses(t *testing.T) {
	cases := []struct {
		name       string
		checks     []interfaces.HealthChecker
		wantCode   int
		wantStatus string
	}{
		{"no deps", nil, 200, "ok"},
		{"all ok", []interfaces.HealthChecker{fakeCheck{name: "postgres", critical: true}}, 200, "ok"},
		{"non-critical down", []interfaces.HealthChecker{
			fakeCheck{name: "postgres", critical: true},
			fakeCheck{name: "redis", err: errors.New("dial redis://secret-host:6379")},
		}, 200, "degraded"},
		{"critical down", []interfaces.HealthChecker{
			fakeCheck{name: "postgres", critical: true, err: errors.New("password authentication failed")},
		}, 503, "unhealthy"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newTestServer(t, nil, c.checks...)
			rr := do(t, s, "GET", "/health", nil, nil)
			if rr.Code != c.wantCode {
				t.Fatalf("code = %d, want %d", rr.Code, c.wantCode)
			}
			var hr HealthResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &hr); err != nil {
				t.Fatal(err)
			}
			if hr.Status != c.wantStatus || len(hr.Checks) != len(c.checks) {
				t.Fatalf("health = %+v", hr)
			}
			if strings.Contains(rr.Body.String(), "secret-host") || strings.Contains(rr.Body.String(), "password") {
				t.Fatalf("health response leaks dependency error details: %s", rr.Body)
			}
		})
	}
}

type countingCheck struct{ n *atomic.Int64 }

func (c countingCheck) Name() string   { return "rpc:1" }
func (c countingCheck) Critical() bool { return false }
func (c countingCheck) Check(ctx context.Context) error {
	c.n.Add(1)
	time.Sleep(20 * time.Millisecond)
	return ctx.Err()
}

// /health is unauthenticated, so a flood of probes must not turn into a
// flood of upstream RPC calls.
func TestHealthChecksAreCached(t *testing.T) {
	var n atomic.Int64
	s := newTestServer(t, nil, countingCheck{&n})
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rr := do(t, s, "GET", "/health", nil, nil); rr.Code != 200 {
				t.Errorf("code %d", rr.Code)
			}
		}()
	}
	wg.Wait()
	if got := n.Load(); got != 1 {
		t.Fatalf("50 concurrent probes ran the checks %d times, want 1", got)
	}
	s.health.mu.Lock()
	s.health.at = time.Now().Add(-healthCacheTTL)
	s.health.mu.Unlock()
	do(t, s, "GET", "/health", nil, nil)
	if got := n.Load(); got != 2 {
		t.Fatalf("expired cache not refreshed: %d runs", got)
	}
}

func TestLivez(t *testing.T) {
	s := newTestServer(t, nil, fakeCheck{name: "postgres", critical: true, err: errors.New("down")})
	if rr := do(t, s, "GET", "/livez", nil, nil); rr.Code != 200 {
		t.Fatalf("livez must not depend on dependencies; got %d", rr.Code)
	}
}

func TestRequestIDPropagation(t *testing.T) {
	s := newTestServer(t, nil)
	rr := do(t, s, "GET", "/livez", nil, map[string]string{RequestIDHeader: "client-id_123"})
	if got := rr.Header().Get(RequestIDHeader); got != "client-id_123" {
		t.Fatalf("valid incoming request ID not preserved: %q", got)
	}
	rr = do(t, s, "GET", "/livez", nil, map[string]string{RequestIDHeader: "bad id\nwith newline"})
	got := rr.Header().Get(RequestIDHeader)
	if got == "" || strings.ContainsAny(got, " \n") {
		t.Fatalf("invalid incoming request ID must be replaced; got %q", got)
	}
}

func TestStructuredNotFoundAndMethodNotAllowed(t *testing.T) {
	s := newTestServer(t, nil)

	rr := do(t, s, "GET", "/nope", nil, nil)
	var eb ErrorBody
	if rr.Code != 404 || json.Unmarshal(rr.Body.Bytes(), &eb) != nil || eb.Error.Code != "route_not_found" || eb.Error.RequestID == "" {
		t.Fatalf("404: code=%d body=%s", rr.Code, rr.Body)
	}

	rr = do(t, s, "POST", "/health", nil, nil)
	if rr.Code != 405 || json.Unmarshal(rr.Body.Bytes(), &eb) != nil || eb.Error.Code != "method_not_allowed" {
		t.Fatalf("405: code=%d body=%s", rr.Code, rr.Body)
	}
}

func TestInfoDoesNotLeakRPCURLs(t *testing.T) {
	s := newTestServer(t, nil)
	rr := do(t, s, "GET", "/api/v1/info", nil, nil)
	if rr.Code != 200 {
		t.Fatalf("code = %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "SECRET") || strings.Contains(rr.Body.String(), "rpc.example") {
		t.Fatalf("info leaks RPC URL: %s", rr.Body)
	}
	var info InfoResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if len(info.Chains) != 2 || info.Chains[0].ChainID != 1 || info.Chains[1].Name != "sepolia" {
		t.Fatalf("chains = %+v", info.Chains)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	s := newTestServer(t, nil)
	do(t, s, "GET", "/livez", nil, nil)
	do(t, s, "GET", "/does-not-exist-1", nil, nil)
	do(t, s, "GET", "/does-not-exist-2", nil, nil)
	rr := do(t, s, "GET", "/metrics", nil, nil)
	body := rr.Body.String()
	if rr.Code != 200 {
		t.Fatalf("code = %d", rr.Code)
	}
	for _, want := range []string{
		`txshield_http_requests_total{code="200",method="GET",route="GET /livez"} 1`,
		`txshield_build_info{commit="abc",version="test"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	// Unknown paths must collapse into one route label, not one per path.
	if strings.Contains(body, "does-not-exist") {
		t.Error("raw paths leaked into metric labels (cardinality risk)")
	}
}

func TestPanicRecovery(t *testing.T) {
	s := newTestServer(t, nil)
	// Wrap a panicking handler with the same outer middleware the server uses.
	h := requestID(s.log)(recoverer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})))
	rr := do(t, h, "GET", "/", nil, nil)
	var eb ErrorBody
	if rr.Code != 500 || json.Unmarshal(rr.Body.Bytes(), &eb) != nil || eb.Error.Code != "internal_error" {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body)
	}
	if strings.Contains(rr.Body.String(), "boom") {
		t.Fatal("panic value leaked to client")
	}
}

func TestSecurityHeaders(t *testing.T) {
	s := newTestServer(t, nil)
	rr := do(t, s, "GET", "/livez", nil, nil)
	if rr.Header().Get("X-Content-Type-Options") != "nosniff" || rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("missing security headers: %v", rr.Header())
	}
}

type sample struct {
	ChainID uint64 `json:"chainId"`
	From    string `json:"from"`
}

func decodeReq(body string, ct string, limit int64) error {
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/x", strings.NewReader(body))
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	req.Body = http.MaxBytesReader(httptest.NewRecorder(), req.Body, limit)
	var s sample
	return decodeJSON(req, &s)
}

func TestDecodeJSON(t *testing.T) {
	if err := decodeReq(`{"chainId":1,"from":"0x"}`, "application/json; charset=utf-8", 1024); err != nil {
		t.Fatalf("valid body rejected: %v", err)
	}
	cases := map[string]struct {
		body, ct string
		limit    int64
		kind     txerrors.Kind
	}{
		"unknown field":  {`{"chainId":1,"maxFeePerGass":"1"}`, "", 1024, txerrors.KindInvalidInput},
		"trailing data":  {`{"chainId":1}{"chainId":2}`, "", 1024, txerrors.KindInvalidInput},
		"syntax":         {`{"chainId":`, "", 1024, txerrors.KindInvalidInput},
		"wrong type":     {`{"chainId":"one"}`, "", 1024, txerrors.KindInvalidInput},
		"empty":          {``, "", 1024, txerrors.KindInvalidInput},
		"bad media type": {`{}`, "text/plain", 1024, txerrors.KindInvalidInput},
		"too large":      {`{"from":"` + strings.Repeat("a", 200) + `"}`, "", 64, txerrors.KindPayloadTooLarge},
	}
	for name, c := range cases {
		err := decodeReq(c.body, c.ct, c.limit)
		if txerrors.KindOf(err) != c.kind {
			t.Errorf("%s: kind = %s (err %v), want %s", name, txerrors.KindOf(err), err, c.kind)
		}
	}
}

func TestBodyLimitByContentLength(t *testing.T) {
	s := newTestServer(t, func(c *config.Config) { c.Limits.MaxBodyBytes = 16 })
	rr := do(t, s, "POST", "/health", strings.NewReader(strings.Repeat("x", 100)), nil)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("code = %d, want 413", rr.Code)
	}
}
