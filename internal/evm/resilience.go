package evm

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"

	"github.com/pri-3x/txshield/internal/netguard"
)

// RetryPolicy controls retries of transient RPC failures. Only idempotent
// read methods are ever retried (the upstream client is read-only).
type RetryPolicy struct {
	MaxAttempts int           // total attempts including the first; default 3
	BaseDelay   time.Duration // default 200ms
	MaxDelay    time.Duration // default 2s
}

func (p RetryPolicy) withDefaults() RetryPolicy {
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = 3
	}
	if p.BaseDelay <= 0 {
		p.BaseDelay = 200 * time.Millisecond
	}
	if p.MaxDelay <= 0 {
		p.MaxDelay = 2 * time.Second
	}
	return p
}

// backoff returns the delay before retry attempt n (1-based) using
// exponential backoff with full jitter: uniform in [0, min(max, base*2^(n-1))].
func (p RetryPolicy) backoff(n int) time.Duration {
	ceil := p.BaseDelay << (n - 1)
	if ceil > p.MaxDelay || ceil <= 0 {
		ceil = p.MaxDelay
	}
	return time.Duration(rand.Int64N(int64(ceil) + 1)) //nolint:gosec // jitter does not need a CSPRNG
}

// isTransient classifies errors that may succeed on retry: network failures,
// HTTP 429/5xx, and JSON-RPC "limit exceeded". JSON-RPC execution errors
// (e.g. reverts) are deterministic answers and never retried.
func isTransient(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode == http.StatusTooManyRequests || httpErr.StatusCode >= 500
	}
	var rpcErr *RPCError
	if errors.As(err, &rpcErr) {
		return rpcErr.Code == -32005 // limit exceeded / rate limited
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET)
}

// ErrCircuitOpen is returned while an endpoint's breaker is open.
var ErrCircuitOpen = errors.New("rpc endpoint temporarily disabled after repeated failures")

// Breaker is a consecutive-failure circuit breaker. After Threshold
// infrastructure failures it opens for Cooldown; then one trial request is
// let through (half-open), and its outcome closes or re-opens the circuit.
type Breaker struct {
	Threshold int
	Cooldown  time.Duration
	now       func() time.Time

	mu        sync.Mutex
	failures  int
	openUntil time.Time
	trial     bool
}

// NewBreaker returns a breaker with defaults (5 failures, 30s cooldown).
func NewBreaker(threshold int, cooldown time.Duration) *Breaker {
	if threshold <= 0 {
		threshold = 5
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	return &Breaker{Threshold: threshold, Cooldown: cooldown, now: time.Now}
}

// Allow reports whether a request may proceed.
func (b *Breaker) Allow() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failures < b.Threshold {
		return nil
	}
	if b.now().Before(b.openUntil) || b.trial {
		return ErrCircuitOpen
	}
	b.trial = true // half-open: admit exactly one trial
	return nil
}

// Record reports the outcome of an admitted request.
func (b *Breaker) Record(infraFailure bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.trial = false
	if !infraFailure {
		b.failures = 0
		return
	}
	b.failures++
	if b.failures >= b.Threshold {
		b.openUntil = b.now().Add(b.Cooldown)
	}
}

// State is "closed", "open", or "half-open" (for metrics and tests).
func (b *Breaker) State() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case b.failures < b.Threshold:
		return "closed"
	case b.now().Before(b.openUntil):
		return "open"
	default:
		return "half-open"
	}
}

// limitedBody caps response bodies; a hostile or broken endpoint must not
// be able to exhaust memory with an unbounded response.
type limitedBody struct {
	io.ReadCloser
	remaining int64
}

var errResponseTooLarge = errors.New("rpc response exceeds size limit")

func (l *limitedBody) Read(p []byte) (int, error) {
	if l.remaining <= 0 {
		return 0, errResponseTooLarge
	}
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.ReadCloser.Read(p)
	l.remaining -= int64(n)
	return n, err
}

type limitTransport struct {
	base  http.RoundTripper
	limit int64
}

func (t limitTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	resp.Body = &limitedBody{ReadCloser: resp.Body, remaining: t.limit}
	return resp, nil
}

// guardedTransport is used for user-supplied endpoints: every connection's
// destination IP is checked at dial time (defeats DNS rebinding).
var guardedTransport = &http.Transport{
	Proxy:                 nil,
	DialContext:           (&net.Dialer{Timeout: 5 * time.Second, Control: netguard.DialControl}).DialContext,
	MaxIdleConnsPerHost:   4,
	IdleConnTimeout:       30 * time.Second,
	TLSHandshakeTimeout:   5 * time.Second,
	ResponseHeaderTimeout: 20 * time.Second,
	ForceAttemptHTTP2:     true,
}

// sharedTransport pools connections across all RPC clients.
var sharedTransport = &http.Transport{
	Proxy:                 nil, // never route RPC through environment proxies implicitly
	DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	MaxIdleConns:          128,
	MaxIdleConnsPerHost:   16,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   5 * time.Second,
	ResponseHeaderTimeout: 30 * time.Second,
	ForceAttemptHTTP2:     true,
}
