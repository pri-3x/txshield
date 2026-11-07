// Package config loads and validates TxShield configuration from environment
// variables. All variables use the TXSHIELD_ prefix. See .env.example.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Config is the full runtime configuration.
type Config struct {
	HTTP        HTTPConfig
	Log         LogConfig
	Limits      LimitsConfig
	Chains      ChainsConfig
	Storage     StorageConfig
	Redis       RedisConfig
	Simulation  SimulationConfig
	Security    SecurityConfig
	API         APIConfig
	MetricsPath string
}

// SecurityConfig configures the analysis engine.
type SecurityConfig struct {
	ReputationFiles   []string // JSON allow/block lists
	ScoringConfigPath string   // optional scoring weight overrides
}

// APIConfig configures API-level protections.
type APIConfig struct {
	// RateLimitRPS and RateLimitBurst bound requests per client IP on
	// /api/ routes. RPS 0 disables rate limiting.
	RateLimitRPS   float64
	RateLimitBurst int
	// CORSOrigins lists browser origins allowed to call the API (e.g. the
	// dashboard). Empty disables CORS.
	CORSOrigins []string
	// TrustProxyHeaders uses the last X-Forwarded-For entry as the client
	// IP. Enable only behind a reverse proxy that sets it.
	TrustProxyHeaders bool
	// APIKeys, when non-empty, are required as "Authorization: Bearer <key>"
	// on /api/ routes. Secrets: never logged.
	APIKeys []string
}

type HTTPConfig struct {
	Addr              string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	RequestTimeout    time.Duration // per-request context deadline
}

type LogConfig struct {
	Level  string // debug, info, warn, error
	Format string // json, text
}

type LimitsConfig struct {
	MaxBodyBytes     int64
	MaxCalldataBytes int
}

type ChainsConfig struct {
	// RPCURLs maps chain ID to operator-configured RPC endpoint. Treated as
	// secrets (may embed API keys): never logged or returned to clients.
	RPCURLs map[uint64]string
	// AllowUserRPC permits API clients to supply their own RPC URL. Off by
	// default because it creates SSRF and abuse risk.
	AllowUserRPC bool
}

type StorageConfig struct {
	DatabaseURL   string // empty disables persistence
	StoreSender   bool   // persist the `from` address
	StoreCalldata bool   // persist raw calldata (otherwise only hash + selector)
	RetentionDays int    // 0 = keep forever
	MaxConns      int32
}

type RedisConfig struct {
	URL string // empty disables Redis
}

type SimulationConfig struct {
	Backend       string // anvil, rpc-trace, none
	AnvilPath     string
	Timeout       time.Duration
	MaxConcurrent int
}

// maxDBConns bounds the Postgres pool size.
const maxDBConns = 1000

// Defaults returns the default configuration.
func Defaults() Config {
	return Config{
		HTTP: HTTPConfig{
			Addr:              "127.0.0.1:8080", // loopback unless deliberately exposed
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
			ShutdownTimeout:   20 * time.Second,
			RequestTimeout:    45 * time.Second,
		},
		Log:    LogConfig{Level: "info", Format: "json"},
		Limits: LimitsConfig{MaxBodyBytes: 1 << 20, MaxCalldataBytes: 128 << 10},
		Chains: ChainsConfig{RPCURLs: map[uint64]string{}},
		Storage: StorageConfig{
			RetentionDays: 30,
			MaxConns:      10,
		},
		Simulation: SimulationConfig{
			Backend:       "anvil",
			AnvilPath:     "anvil",
			Timeout:       30 * time.Second,
			MaxConcurrent: 4,
		},
		API:         APIConfig{RateLimitRPS: 5, RateLimitBurst: 20},
		MetricsPath: "/metrics",
	}
}

// Load reads configuration from the process environment.
func Load() (Config, error) { return LoadFrom(os.LookupEnv) }

// LoadFrom reads configuration using lookup (injectable for tests). It
// returns every problem found, joined.
func LoadFrom(lookup func(string) (string, bool)) (Config, error) {
	c := Defaults()
	var errs []error
	get := func(key string) (string, bool) {
		v, ok := lookup("TXSHIELD_" + key)
		v = strings.TrimSpace(v)
		return v, ok && v != ""
	}
	str := func(key string, dst *string) {
		if v, ok := get(key); ok {
			*dst = v
		}
	}
	dur := func(key string, dst *time.Duration) {
		if v, ok := get(key); ok {
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 {
				errs = append(errs, fmt.Errorf("TXSHIELD_%s: must be a positive duration like 30s", key))
				return
			}
			*dst = d
		}
	}
	integer := func(key string, min int64, set func(int64)) {
		if v, ok := get(key); ok {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < min {
				errs = append(errs, fmt.Errorf("TXSHIELD_%s: must be an integer >= %d", key, min))
				return
			}
			set(n)
		}
	}
	boolean := func(key string, dst *bool) {
		if v, ok := get(key); ok {
			b, err := strconv.ParseBool(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("TXSHIELD_%s: must be true or false", key))
				return
			}
			*dst = b
		}
	}

	str("HTTP_ADDR", &c.HTTP.Addr)
	dur("HTTP_READ_HEADER_TIMEOUT", &c.HTTP.ReadHeaderTimeout)
	dur("HTTP_READ_TIMEOUT", &c.HTTP.ReadTimeout)
	dur("HTTP_WRITE_TIMEOUT", &c.HTTP.WriteTimeout)
	dur("HTTP_IDLE_TIMEOUT", &c.HTTP.IdleTimeout)
	dur("SHUTDOWN_TIMEOUT", &c.HTTP.ShutdownTimeout)
	dur("REQUEST_TIMEOUT", &c.HTTP.RequestTimeout)

	str("LOG_LEVEL", &c.Log.Level)
	str("LOG_FORMAT", &c.Log.Format)

	integer("MAX_BODY_BYTES", 1024, func(n int64) { c.Limits.MaxBodyBytes = n })
	integer("MAX_CALLDATA_BYTES", 4, func(n int64) { c.Limits.MaxCalldataBytes = int(n) })

	if v, ok := get("RPC_URLS"); ok {
		m, err := parseRPCURLs(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("TXSHIELD_RPC_URLS: %w", err))
		} else {
			c.Chains.RPCURLs = m
		}
	}
	boolean("ALLOW_USER_RPC", &c.Chains.AllowUserRPC)

	str("DATABASE_URL", &c.Storage.DatabaseURL)
	boolean("STORE_SENDER", &c.Storage.StoreSender)
	boolean("STORE_CALLDATA", &c.Storage.StoreCalldata)
	integer("RETENTION_DAYS", 0, func(n int64) { c.Storage.RetentionDays = int(n) })
	integer("DB_MAX_CONNS", 1, func(n int64) {
		if n > maxDBConns {
			errs = append(errs, fmt.Errorf("TXSHIELD_DB_MAX_CONNS: must be <= %d", maxDBConns))
			return
		}
		c.Storage.MaxConns = int32(n) //nolint:gosec // bounded to [1, maxDBConns] above
	})

	str("REDIS_URL", &c.Redis.URL)

	str("SIMULATOR", &c.Simulation.Backend)
	str("ANVIL_PATH", &c.Simulation.AnvilPath)
	dur("SIMULATION_TIMEOUT", &c.Simulation.Timeout)
	integer("SIMULATION_MAX_CONCURRENT", 1, func(n int64) { c.Simulation.MaxConcurrent = int(n) })

	str("METRICS_PATH", &c.MetricsPath)

	list := func(key string, dst *[]string) {
		if v, ok := get(key); ok {
			for _, part := range strings.Split(v, ",") {
				if part = strings.TrimSpace(part); part != "" {
					*dst = append(*dst, part)
				}
			}
		}
	}
	list("REPUTATION_FILES", &c.Security.ReputationFiles)
	str("SCORING_CONFIG", &c.Security.ScoringConfigPath)
	list("CORS_ORIGINS", &c.API.CORSOrigins)
	boolean("TRUST_PROXY_HEADERS", &c.API.TrustProxyHeaders)
	list("API_KEYS", &c.API.APIKeys)
	integer("RATE_LIMIT_BURST", 1, func(n int64) { c.API.RateLimitBurst = int(n) })
	if v, ok := get("RATE_LIMIT_RPS"); ok {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || f < 0 || f > 10000 {
			errs = append(errs, fmt.Errorf("TXSHIELD_RATE_LIMIT_RPS: must be a number between 0 and 10000"))
		} else {
			c.API.RateLimitRPS = f
		}
	}

	if err := c.validate(); err != nil {
		errs = append(errs, err)
	}
	return c, errors.Join(errs...)
}

func (c *Config) validate() error {
	var errs []error
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("TXSHIELD_LOG_LEVEL: must be debug, info, warn, or error"))
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		errs = append(errs, fmt.Errorf("TXSHIELD_LOG_FORMAT: must be json or text"))
	}
	if c.HTTP.RequestTimeout >= c.HTTP.WriteTimeout {
		errs = append(errs, fmt.Errorf("TXSHIELD_REQUEST_TIMEOUT (%s) must be less than TXSHIELD_HTTP_WRITE_TIMEOUT (%s)", c.HTTP.RequestTimeout, c.HTTP.WriteTimeout))
	}
	switch c.Simulation.Backend {
	case "anvil", "rpc-trace", "none":
	default:
		errs = append(errs, fmt.Errorf("TXSHIELD_SIMULATOR: must be anvil, rpc-trace, or none"))
	}
	for _, k := range c.API.APIKeys {
		if len(k) < 24 {
			errs = append(errs, fmt.Errorf("TXSHIELD_API_KEYS: every key must be at least 24 characters"))
			break
		}
	}
	for _, o := range c.API.CORSOrigins {
		u, err := url.Parse(o)
		if o == "*" || err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Path != "" {
			errs = append(errs, fmt.Errorf("TXSHIELD_CORS_ORIGINS: %q must be an explicit origin like https://dashboard.example (no wildcards)", o))
		}
	}
	if !strings.HasPrefix(c.MetricsPath, "/") {
		errs = append(errs, fmt.Errorf("TXSHIELD_METRICS_PATH: must start with /"))
	}
	if c.Storage.DatabaseURL != "" {
		if u, err := url.Parse(c.Storage.DatabaseURL); err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
			errs = append(errs, fmt.Errorf("TXSHIELD_DATABASE_URL: must be a postgres:// URL"))
		}
	}
	if c.Redis.URL != "" {
		if u, err := url.Parse(c.Redis.URL); err != nil || (u.Scheme != "redis" && u.Scheme != "rediss") {
			errs = append(errs, fmt.Errorf("TXSHIELD_REDIS_URL: must be a redis:// or rediss:// URL"))
		}
	}
	return errors.Join(errs...)
}

// parseRPCURLs parses "1=https://a,11155111=https://b".
func parseRPCURLs(s string) (map[uint64]string, error) {
	out := map[uint64]string{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, raw, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("entry %q: expected <chainId>=<url>", redactEntry(part))
		}
		chainID, err := strconv.ParseUint(strings.TrimSpace(id), 10, 64)
		if err != nil || chainID == 0 {
			// Do not echo id: a malformed entry may contain a URL with a key.
			return nil, fmt.Errorf("entry %q: invalid chain ID", redactEntry(part))
		}
		raw = strings.TrimSpace(raw)
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("chain %d: invalid URL", chainID)
		}
		switch u.Scheme {
		case "http", "https":
		default:
			return nil, fmt.Errorf("chain %d: URL scheme must be http or https", chainID)
		}
		if _, dup := out[chainID]; dup {
			return nil, fmt.Errorf("chain %d: configured more than once", chainID)
		}
		out[chainID] = raw
	}
	return out, nil
}

// redactEntry avoids echoing a possible API key back in error messages.
func redactEntry(s string) string {
	if len(s) > 12 {
		return s[:12] + "..."
	}
	return s
}

// ConfiguredChains returns configured chain IDs in ascending order.
func (c ChainsConfig) ConfiguredChains() []uint64 {
	ids := make([]uint64, 0, len(c.RPCURLs))
	for id := range c.RPCURLs {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// RedactURL removes credentials, path, and query from a URL for safe logging.
// RPC providers commonly embed API keys in the path (e.g. /v2/<key>).
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "<invalid-url>"
	}
	return u.Scheme + "://" + u.Host + "/<redacted>"
}
