package api

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/txshield/txshield/internal/config"
)

func TestRateLimiterBucket(t *testing.T) {
	l := newRateLimiter(1, 3)
	now := time.Unix(0, 0)
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if ok, _ := l.allow("a"); !ok {
			t.Fatalf("burst request %d denied", i)
		}
	}
	ok, wait := l.allow("a")
	if ok || wait <= 0 || wait > time.Second {
		t.Fatalf("4th request: ok=%v wait=%s", ok, wait)
	}
	if ok, _ := l.allow("b"); !ok {
		t.Fatal("other clients have their own bucket")
	}
	now = now.Add(1100 * time.Millisecond)
	if ok, _ := l.allow("a"); !ok {
		t.Fatal("token must refill")
	}
}

func TestRateLimiterBoundedKeys(t *testing.T) {
	l := newRateLimiter(1, 1)
	l.maxKeys = 10
	for i := 0; i < 1000; i++ {
		l.allow("k" + strconv.Itoa(i))
	}
	if n := len(l.buckets); n > 10 {
		t.Fatalf("tracked %d keys; table must stay bounded", n)
	}
	// A new client arriving while the table is full of other sources gets
	// its own full bucket, not a shared one drained by the flood.
	if ok, _ := l.allow("newcomer"); !ok {
		t.Fatal("new client denied while the table is full")
	}
}

func TestRateKeyGroupsIPv6Subnets(t *testing.T) {
	cases := map[string]string{
		"203.0.113.9":                  "203.0.113.9",
		"::ffff:203.0.113.9":           "203.0.113.9",
		"2001:db8:1:2:aaaa::1":         "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff:ffff:0:abc": "2001:db8:1:2::/64",
		"2001:db8:1:3::1":              "2001:db8:1:3::/64",
		"not-an-ip":                    "not-an-ip",
	}
	for in, want := range cases {
		if got := rateKey(in); got != want {
			t.Errorf("rateKey(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.9:4444"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 198.51.100.7")
	if got := clientIP(r, false); got != "203.0.113.9" {
		t.Fatalf("untrusted proxy headers must be ignored: %s", got)
	}
	if got := clientIP(r, true); got != "198.51.100.7" {
		t.Fatalf("trusted proxy: want last hop, got %s", got)
	}
	r.Header.Set("X-Forwarded-For", "garbage")
	if got := clientIP(r, true); got != "203.0.113.9" {
		t.Fatalf("invalid XFF must fall back: %s", got)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	s := newTestServer(t, func(c *config.Config) { c.API.RateLimitRPS = 0.001; c.API.RateLimitBurst = 2 })
	codes := []int{}
	for i := 0; i < 3; i++ {
		codes = append(codes, do(t, s, "GET", "/api/v1/info", nil, nil).Code)
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != http.StatusTooManyRequests {
		t.Fatalf("codes = %v", codes)
	}
	rr := do(t, s, "GET", "/api/v1/info", nil, nil)
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("429 must carry Retry-After")
	}
	if do(t, s, "GET", "/health", nil, nil).Code != 200 {
		t.Fatal("health must not be rate limited")
	}
}

func TestCORS(t *testing.T) {
	s := newTestServer(t, func(c *config.Config) { c.API.CORSOrigins = []string{"http://localhost:3000"} })
	rr := do(t, s, "OPTIONS", "/api/v1/analyze", nil, map[string]string{"Origin": "http://localhost:3000", "Access-Control-Request-Method": "POST"})
	if rr.Code != 204 || rr.Header().Get("Access-Control-Allow-Origin") != "http://localhost:3000" || rr.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Fatalf("preflight: %d %v", rr.Code, rr.Header())
	}
	rr = do(t, s, "OPTIONS", "/api/v1/analyze", nil, map[string]string{"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
	if rr.Code != 403 || rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("foreign preflight: %d %v", rr.Code, rr.Header())
	}
	rr = do(t, s, "GET", "/api/v1/info", nil, map[string]string{"Origin": "https://evil.example"})
	if rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("foreign origin must not get CORS headers")
	}
}

func TestAPIKeyAuth(t *testing.T) {
	key := "k_0123456789abcdefghijklmnop"
	s := newTestServer(t, func(c *config.Config) { c.API.APIKeys = []string{key, "another-key-0123456789abcd"} })
	if rr := do(t, s, "GET", "/api/v1/info", nil, nil); rr.Code != 401 || rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("no key: %d", rr.Code)
	}
	if rr := do(t, s, "GET", "/api/v1/info", nil, map[string]string{"Authorization": "Bearer wrong"}); rr.Code != 401 {
		t.Fatalf("wrong key: %d", rr.Code)
	}
	if rr := do(t, s, "GET", "/api/v1/info", nil, map[string]string{"Authorization": "Bearer " + key}); rr.Code != 200 {
		t.Fatalf("valid key: %d", rr.Code)
	}
	for _, p := range []string{"/health", "/livez", "/metrics", "/api/v1/openapi.json"} {
		if rr := do(t, s, "GET", p, nil, nil); rr.Code != 200 {
			t.Errorf("%s must not require a key: %d", p, rr.Code)
		}
	}
}

// Requests with a missing or wrong API key are rate limited too, so
// unauthenticated floods cannot bypass the limiter.
func TestRateLimitAppliesBeforeAuth(t *testing.T) {
	s := newTestServer(t, func(c *config.Config) {
		c.API.RateLimitRPS = 0.001
		c.API.RateLimitBurst = 2
		c.API.APIKeys = []string{"k-0123456789abcdef0123456789"}
	})
	bad := map[string]string{"Authorization": "Bearer wrong-key-0123456789abcdef"}
	codes := []int{}
	for i := 0; i < 3; i++ {
		codes = append(codes, do(t, s, "GET", "/api/v1/info", nil, bad).Code)
	}
	if codes[0] != http.StatusUnauthorized || codes[1] != http.StatusUnauthorized || codes[2] != http.StatusTooManyRequests {
		t.Fatalf("codes = %v", codes)
	}
}
