package api

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/pri-3x/txshield/internal/version"
)

// CheckResult is the outcome of one dependency check.
type CheckResult struct {
	Status    string `json:"status"` // "ok" or "fail"
	Critical  bool   `json:"critical"`
	LatencyMs int64  `json:"latencyMs"`
	Error     string `json:"error,omitempty"`
}

// HealthResponse is the body of GET /health.
type HealthResponse struct {
	Status  string                 `json:"status"` // ok, degraded, unhealthy
	Version string                 `json:"version"`
	Commit  string                 `json:"commit"`
	Checks  map[string]CheckResult `json:"checks"`
}

const (
	healthCheckTimeout = 3 * time.Second
	// healthCacheTTL bounds how often dependency checks run. /health is
	// unauthenticated and not rate limited (probes must work without keys),
	// and each check may call a paid upstream RPC endpoint.
	healthCacheTTL = 5 * time.Second
)

// healthCache holds the latest result; concurrent requests during a
// refresh wait for it instead of starting their own checks.
type healthCache struct {
	mu     sync.Mutex
	at     time.Time
	resp   HealthResponse
	status int
}

// handleHealth serves the cached dependency status, refreshing it at most
// once per healthCacheTTL. It returns 503 only when a critical dependency
// fails; non-critical failures (e.g. cache) yield 200 with status "degraded".
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.health.mu.Lock()
	if s.health.at.IsZero() || time.Since(s.health.at) >= healthCacheTTL {
		s.health.resp, s.health.status = s.runHealthChecks()
		s.health.at = time.Now()
	}
	resp, status := s.health.resp, s.health.status
	s.health.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, resp)
}

// runHealthChecks runs all dependency checks concurrently. It does not use
// the request context: the result is shared, so one client disconnecting
// must not record a failure for everyone.
func (s *Server) runHealthChecks() (HealthResponse, int) {
	ctx, cancel := context.WithTimeout(context.Background(), healthCheckTimeout)
	defer cancel()

	resp := HealthResponse{
		Status:  "ok",
		Version: version.Version,
		Commit:  version.Commit,
		Checks:  make(map[string]CheckResult, len(s.checks)),
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, c := range s.checks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			err := c.Check(ctx)
			res := CheckResult{Status: "ok", Critical: c.Critical(), LatencyMs: time.Since(start).Milliseconds()}
			up := 1.0
			if err != nil {
				// Dependency errors can include hostnames or DSNs; expose only
				// a generic message and keep details in logs.
				res.Status, res.Error, up = "fail", "check failed", 0
				s.log.Warn("health check failed", "dependency", c.Name(), "err", err)
			}
			s.metrics.HealthStatus.WithLabelValues(c.Name()).Set(up)
			mu.Lock()
			resp.Checks[c.Name()] = res
			mu.Unlock()
		}()
	}
	wg.Wait()

	status := http.StatusOK
	for _, res := range resp.Checks {
		if res.Status == "ok" {
			continue
		}
		if res.Critical {
			resp.Status = "unhealthy"
			status = http.StatusServiceUnavailable
			break
		}
		resp.Status = "degraded"
	}
	return resp, status
}

// handleLive is a liveness probe: it succeeds whenever the process can serve
// HTTP, independent of dependencies.
func (s *Server) handleLive(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
