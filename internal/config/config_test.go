package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestDefaultsAreValid(t *testing.T) {
	c, err := LoadFrom(env(nil))
	if err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
	if c.HTTP.Addr != "127.0.0.1:8080" || c.Storage.DatabaseURL != "" || c.Chains.AllowUserRPC {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestLoadOverrides(t *testing.T) {
	c, err := LoadFrom(env(map[string]string{
		"TXSHIELD_HTTP_ADDR":       ":9090",
		"TXSHIELD_REQUEST_TIMEOUT": "10s",
		"TXSHIELD_RPC_URLS":        "1=https://eth.example/v2/KEY, 11155111=http://localhost:8545",
		"TXSHIELD_DATABASE_URL":    "postgres://u:p@localhost:5432/txshield",
		"TXSHIELD_STORE_SENDER":    "true",
		"TXSHIELD_RETENTION_DAYS":  "0",
		"TXSHIELD_LOG_FORMAT":      "text",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTP.Addr != ":9090" || c.HTTP.RequestTimeout != 10*time.Second {
		t.Fatalf("http overrides not applied: %+v", c.HTTP)
	}
	if got := c.Chains.ConfiguredChains(); len(got) != 2 || got[0] != 1 || got[1] != 11155111 {
		t.Fatalf("chains = %v", got)
	}
	if !c.Storage.StoreSender || c.Storage.RetentionDays != 0 {
		t.Fatalf("storage overrides not applied: %+v", c.Storage)
	}
}

func TestLoadReportsAllErrors(t *testing.T) {
	_, err := LoadFrom(env(map[string]string{
		"TXSHIELD_LOG_LEVEL":       "loud",
		"TXSHIELD_REQUEST_TIMEOUT": "forever",
		"TXSHIELD_MAX_BODY_BYTES":  "10",
		"TXSHIELD_DATABASE_URL":    "mysql://x",
		"TXSHIELD_RPC_URLS":        "1=ftp://x",
	}))
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"LOG_LEVEL", "REQUEST_TIMEOUT", "MAX_BODY_BYTES", "DATABASE_URL", "RPC_URLS"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %s: %v", want, err)
		}
	}
}

func TestRequestTimeoutMustBeBelowWriteTimeout(t *testing.T) {
	_, err := LoadFrom(env(map[string]string{
		"TXSHIELD_REQUEST_TIMEOUT":    "60s",
		"TXSHIELD_HTTP_WRITE_TIMEOUT": "30s",
	}))
	if err == nil || !strings.Contains(err.Error(), "REQUEST_TIMEOUT") {
		t.Fatalf("expected timeout ordering error, got %v", err)
	}
}

func TestParseRPCURLs(t *testing.T) {
	bad := []string{
		"1",                       // no '='
		"0=https://x",             // zero chain
		"abc=https://x",           // non-numeric
		"1=https://a,1=https://b", // duplicate
		"1=/relative",             // no host
	}
	for _, in := range bad {
		if _, err := parseRPCURLs(in); err == nil {
			t.Errorf("parseRPCURLs(%q) expected error", in)
		}
	}
}

func TestErrorsDoNotLeakRPCSecrets(t *testing.T) {
	_, err := LoadFrom(env(map[string]string{"TXSHIELD_RPC_URLS": "https://eth.example/v2/SUPERSECRETKEY"}))
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "SUPERSECRETKEY") {
		t.Fatalf("error leaks secret: %v", err)
	}
}

func TestRedactURL(t *testing.T) {
	got := RedactURL("https://user:pw@eth.example/v2/KEY?apikey=X")
	if got != "https://eth.example/<redacted>" {
		t.Fatalf("RedactURL = %q", got)
	}
	if RedactURL("::::") != "<invalid-url>" {
		t.Fatal("invalid URL not handled")
	}
}

func TestPhase5Settings(t *testing.T) {
	c, err := LoadFrom(env(map[string]string{
		"TXSHIELD_SIMULATOR":        "rpc-trace",
		"TXSHIELD_REPUTATION_FILES": "a.json, b.json",
		"TXSHIELD_CORS_ORIGINS":     "http://localhost:3000,https://dash.example",
		"TXSHIELD_RATE_LIMIT_RPS":   "2.5",
		"TXSHIELD_RATE_LIMIT_BURST": "7",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Simulation.Backend != "rpc-trace" || len(c.Security.ReputationFiles) != 2 || c.Security.ReputationFiles[1] != "b.json" ||
		len(c.API.CORSOrigins) != 2 || c.API.RateLimitRPS != 2.5 || c.API.RateLimitBurst != 7 {
		t.Fatalf("%+v %+v %+v", c.Simulation, c.Security, c.API)
	}
	for k, v := range map[string]string{
		"TXSHIELD_SIMULATOR":      "tenderly",
		"TXSHIELD_CORS_ORIGINS":   "*",
		"TXSHIELD_RATE_LIMIT_RPS": "-1",
	} {
		if _, err := LoadFrom(env(map[string]string{k: v})); err == nil {
			t.Errorf("%s=%s accepted", k, v)
		}
	}
	if _, err := LoadFrom(env(map[string]string{"TXSHIELD_CORS_ORIGINS": "https://x.example/path"})); err == nil {
		t.Error("origin with path accepted")
	}
}

func TestAPIKeysMinimumLength(t *testing.T) {
	if _, err := LoadFrom(env(map[string]string{"TXSHIELD_API_KEYS": "short"})); err == nil || strings.Contains(err.Error(), "short") {
		t.Fatalf("short key must be rejected without echoing it: %v", err)
	}
}
