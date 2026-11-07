// Package api implements the TxShield HTTP API gateway: routing, middleware
// (request IDs, recovery, logging, limits, timeouts, metrics), and handlers.
// Business logic lives in the engine; handlers only translate HTTP <-> engine.
package api

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/txshield/txshield/internal/config"
	"github.com/txshield/txshield/internal/evm"
	"github.com/txshield/txshield/internal/metrics"
	"github.com/txshield/txshield/internal/version"
	"github.com/txshield/txshield/pkg/interfaces"
	"github.com/txshield/txshield/pkg/txerrors"
)

// Deps are the server's injected dependencies.
type Deps struct {
	Config  config.Config
	Logger  *slog.Logger
	Metrics *metrics.Metrics
	Checks  []interfaces.HealthChecker
	// Engine provides analysis; nil leaves analysis endpoints returning 503.
	Engine *Engine
}

// Server is the HTTP API.
type Server struct {
	cfg     config.Config
	log     *slog.Logger
	metrics *metrics.Metrics
	checks  []interfaces.HealthChecker
	engine  *Engine
	routes  map[string]bool // registered paths, for 404 vs 405
	prefix  []string        // registered parameterized path prefixes
	handler http.Handler
	health  healthCache
}

// New builds the server and its handler chain.
func New(d Deps) *Server {
	s := &Server{
		cfg:     d.Config,
		log:     d.Logger,
		metrics: d.Metrics,
		checks:  d.Checks,
		engine:  d.Engine,
		routes:  map[string]bool{},
	}
	mux := http.NewServeMux()
	s.handle(mux, "GET", "/livez", s.handleLive)
	s.handle(mux, "GET", "/health", s.handleHealth)
	s.handle(mux, "GET", "/api/v1/info", s.handleInfo)
	s.handle(mux, "GET", "/api/v1/openapi.json", s.handleOpenAPI)
	s.handle(mux, "POST", "/api/v1/analyze", s.handleAnalyze)
	s.handle(mux, "POST", "/api/v1/simulate", s.handleSimulate)
	s.handle(mux, "POST", "/api/v1/approvals/analyze", s.handleApprovals)
	s.handle(mux, "GET", "/api/v1/analyses", s.handleListAnalyses)
	s.handle(mux, "GET", "/api/v1/analyses/{id}", s.handleGetAnalysis)
	s.handle(mux, "GET", "/api/v1/address/{address}", s.handleAddress)
	s.handle(mux, "GET", "/api/v1/stats", s.handleStats)
	s.handle(mux, "POST", "/api/v1/decode", s.handleDecode)
	s.handle(mux, "GET", "/api/v1/transactions/{hash}", s.handleTransaction)
	mux.Handle("GET "+d.Config.MetricsPath, promhttp.HandlerFor(d.Metrics.Registry, promhttp.HandlerOpts{}))
	s.routes[d.Config.MetricsPath] = true
	mux.HandleFunc("/", s.handleFallback)

	// Outermost first. instrument must wrap the mux directly (see its doc).
	h := instrument(d.Metrics, mux)
	h = bodyLimit(d.Config.Limits.MaxBodyBytes)(h)
	h = timeout(d.Config.HTTP.RequestTimeout)(h)
	var limiter *rateLimiter
	if d.Config.API.RateLimitRPS > 0 {
		limiter = newRateLimiter(d.Config.API.RateLimitRPS, d.Config.API.RateLimitBurst)
	}
	// Rate limiting wraps authentication so floods of requests with bad or
	// missing keys are throttled too.
	h = apiKeyAuth(d.Config.API.APIKeys)(h)
	h = rateLimit(limiter, d.Config.API.TrustProxyHeaders, d.Metrics)(h)
	h = cors(d.Config.API.CORSOrigins)(h)
	h = accessLog(h)
	h = recoverer(h)
	h = requestID(d.Logger)(h)
	h = securityHeaders(h)
	s.handler = h
	return s
}

func (s *Server) handle(mux *http.ServeMux, method, path string, h http.HandlerFunc) {
	mux.HandleFunc(method+" "+path, h)
	if i := strings.Index(path, "{"); i >= 0 {
		s.prefix = append(s.prefix, path[:i])
		return
	}
	s.routes[path] = true
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

// handleFallback returns structured 404/405 errors instead of the mux's
// plain-text defaults.
func (s *Server) handleFallback(w http.ResponseWriter, r *http.Request) {
	known := s.routes[r.URL.Path]
	for _, p := range s.prefix {
		known = known || (strings.HasPrefix(r.URL.Path, p) && len(r.URL.Path) > len(p) && !strings.Contains(r.URL.Path[len(p):], "/"))
	}
	if known {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorBody{Error: ErrorDetail{
			Kind: txerrors.KindInvalidInput, Code: "method_not_allowed",
			Message: "method not allowed", RequestID: RequestIDFrom(r.Context()),
		}})
		return
	}
	writeError(w, r, txerrors.New(txerrors.KindNotFound, "route_not_found", "route not found"))
}

// InfoResponse describes the running engine. Chain IDs are listed but RPC
// URLs are never exposed (they commonly embed API keys).
type InfoResponse struct {
	Version      string      `json:"version"`
	Commit       string      `json:"commit"`
	Chains       []ChainInfo `json:"chains"`
	Persistence  bool        `json:"persistence"`
	AllowUserRPC bool        `json:"allowUserRpc"`
	Simulator    string      `json:"simulator"`
	Rules        int         `json:"rules"`
	Reputation   []string    `json:"reputationSources"`
}

// ChainInfo is a configured chain.
type ChainInfo struct {
	ChainID uint64 `json:"chainId"`
	Name    string `json:"name,omitempty"`
}

func (s *Server) handleInfo(w http.ResponseWriter, _ *http.Request) {
	resp := InfoResponse{
		Version:      version.Version,
		Commit:       version.Commit,
		Chains:       []ChainInfo{},
		Persistence:  s.cfg.Storage.DatabaseURL != "",
		AllowUserRPC: s.cfg.Chains.AllowUserRPC,
		Simulator:    "none",
		Reputation:   []string{},
	}
	if s.engine != nil {
		resp.Persistence = s.engine.Store != nil
		if s.engine.Simulator != nil {
			resp.Simulator = s.engine.Simulator.Name()
		}
		if s.engine.Analyzer != nil {
			resp.Rules = len(s.engine.Analyzer.Rules())
			if agg := s.engine.Analyzer.Reputation(); agg != nil {
				resp.Reputation = agg.Sources()
			}
		}
	}
	for _, id := range s.cfg.Chains.ConfiguredChains() {
		ci := ChainInfo{ChainID: id}
		if c, ok := evm.ChainByID(id); ok {
			ci.Name = c.Name
		}
		resp.Chains = append(resp.Chains, ci)
	}
	writeJSON(w, http.StatusOK, resp)
}

// securityHeaders sets conservative headers appropriate for a JSON API.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
