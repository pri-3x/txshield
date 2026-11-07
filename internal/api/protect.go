package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"math"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pri-3x/txshield/internal/metrics"
	"github.com/pri-3x/txshield/pkg/txerrors"
)

// clientIP returns the caller's IP. X-Forwarded-For is honored only when the
// operator states that a trusted reverse proxy sets it; then its last entry
// (appended by that proxy) is used, since earlier entries are client-supplied.
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
				return ip.Unmap().String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rateKey groups addresses that one client typically controls: IPv6 clients
// usually get a whole /64, so per-address keys would let one subscriber
// rotate through 2^64 buckets.
func rateKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is4() {
		return a.String()
	}
	p, err := a.Prefix(64)
	if err != nil {
		return ip
	}
	return p.String()
}

// rateLimiter is a per-key token bucket with idle-entry eviction and a cap
// on tracked keys (so a flood of spoofed sources cannot exhaust memory).
type rateLimiter struct {
	rate    float64 // tokens per second
	burst   float64
	maxKeys int
	now     func() time.Time

	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(rps float64, burst int) *rateLimiter {
	return &rateLimiter{rate: rps, burst: float64(burst), maxKeys: 100_000, now: time.Now, buckets: map[string]*bucket{}}
}

// allow consumes a token for key; when denied it returns the wait until the
// next token.
func (l *rateLimiter) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Sub(l.lastSweep) > time.Minute || len(l.buckets) >= l.maxKeys {
		l.sweep(now)
	}
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			// Table full of active clients: evict an arbitrary entry (Go map
			// iteration order is randomized) instead of growing, or putting
			// new clients into one shared bucket that a flood of sources
			// keeps drained. In a flood, the evicted entry is most likely
			// one of the flooding sources.
			for k := range l.buckets {
				delete(l.buckets, k)
				break
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
}

// sweep drops buckets that have refilled completely (idle clients).
func (l *rateLimiter) sweep(now time.Time) {
	full := time.Duration(l.burst / l.rate * float64(time.Second))
	for k, b := range l.buckets {
		if now.Sub(b.last) > full {
			delete(l.buckets, k)
		}
	}
	l.lastSweep = now
}

// rateLimit applies the limiter to /api/ routes only; health and metrics
// stay reachable for orchestrators and scrapers.
func rateLimit(l *rateLimiter, trustProxy bool, m *metrics.Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if l == nil || !strings.HasPrefix(r.URL.Path, "/api/") || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			ok, wait := l.allow(rateKey(clientIP(r, trustProxy)))
			if !ok {
				m.RateLimited.Inc()
				w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
				writeError(w, r, txerrors.New(txerrors.KindRateLimited, "rate_limited", "too many requests; retry later"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// apiKeyAuth requires a bearer key on /api/ routes when keys are configured.
// Only SHA-256 digests are kept in memory, and every candidate is compared
// in constant time so timing does not reveal which key nearly matched.
func apiKeyAuth(keys []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if len(keys) == 0 {
			return next
		}
		digests := make([][32]byte, len(keys))
		for i, k := range keys {
			digests[i] = sha256.Sum256([]byte(k))
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, "/api/") || r.Method == http.MethodOptions || r.URL.Path == "/api/v1/openapi.json" {
				next.ServeHTTP(w, r)
				return
			}
			token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			got := sha256.Sum256([]byte(strings.TrimSpace(token)))
			match := 0
			for _, d := range digests {
				match |= subtle.ConstantTimeCompare(got[:], d[:])
			}
			if !ok || match != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="txshield"`)
				writeJSON(w, http.StatusUnauthorized, ErrorBody{Error: ErrorDetail{
					Kind: txerrors.KindInvalidInput, Code: "unauthorized", Message: "a valid API key is required", RequestID: RequestIDFrom(r.Context()),
				}})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// cors allows only explicitly configured origins. Requests from other
// origins get no CORS headers, so browsers block them.
func cors(origins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if len(origins) == 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			allowed := origin != "" && slices.Contains(origins, origin)
			if allowed {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				h.Add("Vary", "Origin")
				h.Set("Access-Control-Expose-Headers", "X-Request-ID, Retry-After")
			}
			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				if !allowed {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				h := w.Header()
				h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Content-Type, X-Request-ID, Authorization")
				h.Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
