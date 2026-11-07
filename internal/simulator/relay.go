package simulator

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// forkRelay is a loopback JSON-RPC relay between Anvil and the upstream fork
// endpoint.
//
// Anvil only accepts its fork endpoint as a command-line argument (no
// environment variable), and process arguments are visible to every local
// user (ps, /proc/*/cmdline, container tooling). Provider URLs usually embed
// an API key, so Anvil is given http://127.0.0.1:<port>/fork/<token>
// instead, where the token is random per upstream URL and the real URL
// stays in TxShield's memory.
//
// Anyone who learns a token can still send read requests through the relay
// (using the operator's RPC quota) while TxShield runs, but cannot learn the
// key, and methods that send transactions or change node state are refused.
type forkRelay struct {
	maxResponse int64
	client      *http.Client

	mu      sync.Mutex
	srv     *http.Server
	base    string            // http://127.0.0.1:<port>
	byURL   map[string]string // upstream URL -> token
	byToken map[string]string // token -> upstream URL
}

const relayMaxRequest = 1 << 20

func newForkRelay(maxResponse int64) *forkRelay {
	if maxResponse <= 0 {
		maxResponse = 64 << 20
	}
	return &forkRelay{
		maxResponse: maxResponse,
		client: &http.Client{
			// Anvil fetches fork state with many concurrent requests; a
			// small idle pool would open and close a connection per request
			// and exhaust ephemeral ports under load.
			Transport: &http.Transport{
				Proxy:                 nil,
				DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
				MaxIdleConns:          256,
				MaxIdleConnsPerHost:   128,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   5 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
				ForceAttemptHTTP2:     true,
			},
			Timeout: 60 * time.Second,
			// The upstream is operator-configured; still, never follow it elsewhere.
			CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are not followed") },
		},
		byURL:   map[string]string{},
		byToken: map[string]string{},
	}
}

// url returns the relay URL to give Anvil for upstream, starting the relay
// on first use.
func (r *forkRelay) url(upstream string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.srv == nil {
		l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			return "", err
		}
		r.srv = &http.Server{Handler: r, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 120 * time.Second}
		r.base = "http://" + l.Addr().String()
		go func() { _ = r.srv.Serve(l) }()
	}
	tok, ok := r.byURL[upstream]
	if !ok {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		tok = hex.EncodeToString(b)
		r.byURL[upstream], r.byToken[tok] = tok, upstream
	}
	return r.base + "/fork/" + tok, nil
}

func (r *forkRelay) close() {
	r.mu.Lock()
	srv := r.srv
	r.srv = nil
	r.mu.Unlock()
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

// relayDenied lists method prefixes the relay never forwards. Forking only
// needs reads; anything that sends a transaction or changes node state is
// refused even if a token leaks.
var relayDenied = []string{
	"eth_sendRawTransaction", "eth_sendTransaction", "eth_sign", "eth_signTransaction", "eth_signTypedData",
	"personal_", "admin_", "miner_", "debug_set", "engine_", "anvil_", "hardhat_", "evm_",
}

func relayAllowed(method string) bool {
	if method == "" {
		return false
	}
	for _, p := range relayDenied {
		if strings.HasPrefix(method, p) {
			return false
		}
	}
	return true
}

// requestMethods returns the JSON-RPC methods in a single or batch request.
func requestMethods(body []byte) ([]string, bool) {
	type call struct {
		Method string `json:"method"`
	}
	body = bytes.TrimSpace(body)
	if len(body) > 0 && body[0] == '[' {
		var calls []call
		if json.Unmarshal(body, &calls) != nil || len(calls) == 0 {
			return nil, false
		}
		out := make([]string, len(calls))
		for i, c := range calls {
			out[i] = c.Method
		}
		return out, true
	}
	var c call
	if json.Unmarshal(body, &c) != nil {
		return nil, false
	}
	return []string{c.Method}, true
}

func (r *forkRelay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	tok, ok := strings.CutPrefix(req.URL.Path, "/fork/")
	r.mu.Lock()
	upstream := r.byToken[tok]
	r.mu.Unlock()
	if !ok || upstream == "" || req.Method != http.MethodPost {
		http.NotFound(w, req)
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, relayMaxRequest+1))
	if err != nil || len(body) > relayMaxRequest {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	methods, ok := requestMethods(body)
	if !ok {
		http.Error(w, "invalid JSON-RPC request", http.StatusBadRequest)
		return
	}
	for _, m := range methods {
		if !relayAllowed(m) {
			http.Error(w, "method not allowed through the fork relay", http.StatusForbidden)
			return
		}
	}
	out, err := http.NewRequestWithContext(req.Context(), http.MethodPost, upstream, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "bad upstream", http.StatusBadGateway)
		return
	}
	out.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(out)
	if err != nil {
		// Never echo the error: it contains the upstream URL.
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, r.maxResponse))
}
