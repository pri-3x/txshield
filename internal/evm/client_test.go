package evm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/pri-3x/txshield/pkg/models"
	"github.com/pri-3x/txshield/pkg/txerrors"
)

// fakeNode is a scriptable JSON-RPC server that records every method called.
type fakeNode struct {
	mu      sync.Mutex
	methods []string
	handle  func(method string, params []json.RawMessage) (status int, result any, rpcErr *RPCError)
}

func (f *fakeNode) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     uint64            `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	f.mu.Lock()
	f.methods = append(f.methods, req.Method)
	f.mu.Unlock()
	status, result, rpcErr := f.handle(req.Method, req.Params)
	if status != 0 && status != 200 {
		w.WriteHeader(status)
		return
	}
	resp := map[string]any{"jsonrpc": "2.0", "id": req.ID}
	if rpcErr != nil {
		resp["error"] = rpcErr
	} else {
		resp["result"] = result
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (f *fakeNode) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.methods...)
}

func fastOpts() Options {
	return Options{Retry: RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond}, BreakerThreshold: 3, BreakerCooldown: 50 * time.Millisecond}
}

func newNode(t *testing.T, h func(string, []json.RawMessage) (int, any, *RPCError)) (*fakeNode, *Client) {
	t.Helper()
	n := &fakeNode{handle: h}
	srv := httptest.NewServer(n)
	t.Cleanup(srv.Close)
	c, err := DialUpstream(context.Background(), srv.URL+"/v2/SECRETKEY", fastOpts())
	if err != nil {
		t.Fatal(err)
	}
	return n, c
}

func TestReadsAndTypes(t *testing.T) {
	_, c := newNode(t, func(m string, p []json.RawMessage) (int, any, *RPCError) {
		switch m {
		case "eth_chainId":
			return 0, "0x1", nil
		case "eth_blockNumber":
			return 0, "0x10", nil
		case "eth_getCode":
			return 0, "0x6080", nil
		case "eth_getBalance":
			return 0, "0xde0b6b3a7640000", nil
		case "eth_call":
			return 0, "0x0000000000000000000000000000000000000000000000000000000000000012", nil
		case "eth_getBlockByNumber":
			return 0, map[string]any{"number": "0x10", "hash": "0x" + strings.Repeat("ab", 32), "timestamp": "0x64", "baseFeePerGas": "0x3b9aca00", "gasLimit": "0x1c9c380"}, nil
		}
		return 0, nil, &RPCError{Code: -32601, Message: "method not found"}
	})
	ctx := context.Background()
	if id, err := c.ChainID(ctx); err != nil || id.Int64() != 1 {
		t.Fatal(id, err)
	}
	if n, err := c.BlockNumber(ctx); err != nil || n != 16 {
		t.Fatal(n, err)
	}
	if code, err := c.CodeAt(ctx, common.Address{}, big.NewInt(5)); err != nil || len(code) != 2 {
		t.Fatal(code, err)
	}
	if b, err := c.BalanceAt(ctx, common.Address{}, nil); err != nil || b.String() != "1000000000000000000" {
		t.Fatal(b, err)
	}
	to := common.Address{1}
	if out, err := c.CallContract(ctx, &models.Transaction{To: &to}, nil); err != nil || out[31] != 0x12 {
		t.Fatal(out, err)
	}
	info, err := c.ResolveBlock(ctx, models.BlockRef{Tag: models.BlockLatest})
	if err != nil || info.Number != 16 || info.Timestamp != 100 || info.BaseFee != "1000000000" || info.GasLimit != 30000000 {
		t.Fatalf("%+v %v", info, err)
	}
}

func TestUpstreamRefusesSendAndMutatingMethods(t *testing.T) {
	n, c := newNode(t, func(string, []json.RawMessage) (int, any, *RPCError) { return 0, "0x", nil })
	for _, m := range []string{"eth_sendRawTransaction", "eth_sendTransaction", "eth_sign", "eth_signTypedData_v4", "personal_sign", "anvil_setBalance", "hardhat_impersonateAccount", "evm_mine", "admin_addPeer", "debug_setHead"} {
		err := c.Call(context.Background(), nil, m)
		if !errors.Is(err, ErrMethodNotAllowed) {
			t.Errorf("%s: err = %v", m, err)
		}
	}
	if got := n.called(); len(got) != 0 {
		t.Fatalf("denied methods reached the network: %v", got)
	}
}

func TestRetryOnTransientThenSuccess(t *testing.T) {
	var calls atomic.Int32
	_, c := newNode(t, func(string, []json.RawMessage) (int, any, *RPCError) {
		if calls.Add(1) < 3 {
			return http.StatusServiceUnavailable, nil, nil
		}
		return 0, "0x5", nil
	})
	n, err := c.BlockNumber(context.Background())
	if err != nil || n != 5 || calls.Load() != 3 {
		t.Fatalf("n=%d err=%v calls=%d", n, err, calls.Load())
	}
	if c.Breaker().State() != "closed" {
		t.Fatal("success must reset the breaker")
	}
}

func TestNoRetryOnExecutionError(t *testing.T) {
	var calls atomic.Int32
	_, c := newNode(t, func(string, []json.RawMessage) (int, any, *RPCError) {
		calls.Add(1)
		return 0, nil, &RPCError{Code: 3, Message: "execution reverted", Data: json.RawMessage(`"0x08c379a0"`)}
	})
	to := common.Address{1}
	_, err := c.CallContract(context.Background(), &models.Transaction{To: &to}, nil)
	if !IsExecutionError(err) || calls.Load() != 1 {
		t.Fatalf("err=%v calls=%d", err, calls.Load())
	}
	if c.Breaker().State() != "closed" {
		t.Fatal("reverts must not trip the breaker")
	}
}

func TestCircuitBreaker(t *testing.T) {
	var calls atomic.Int32
	var healthy atomic.Bool
	_, c := newNode(t, func(string, []json.RawMessage) (int, any, *RPCError) {
		calls.Add(1)
		if healthy.Load() {
			return 0, "0x1", nil
		}
		return http.StatusBadGateway, nil, nil
	})
	ctx := context.Background()
	_, err := c.BlockNumber(ctx) // 3 attempts -> 3 failures -> open
	if txerrors.KindOf(err) != txerrors.KindUnavailable {
		t.Fatalf("err = %v", err)
	}
	before := calls.Load()
	_, err = c.BlockNumber(ctx)
	if !errors.Is(err, ErrCircuitOpen) || calls.Load() != before {
		t.Fatalf("open circuit must fail fast without network: %v (calls %d->%d)", err, before, calls.Load())
	}
	time.Sleep(60 * time.Millisecond)
	healthy.Store(true)
	if _, err := c.BlockNumber(ctx); err != nil || c.Breaker().State() != "closed" {
		t.Fatalf("half-open trial should close the circuit: %v %s", err, c.Breaker().State())
	}
}

func TestErrorsNeverLeakURL(t *testing.T) {
	c, err := DialUpstream(context.Background(), "http://127.0.0.1:1/v2/SECRETKEY", fastOpts())
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.BlockNumber(context.Background())
	if txerrors.KindOf(err) != txerrors.KindUnavailable {
		t.Fatalf("err = %v", err)
	}
	var full strings.Builder
	for e := err; e != nil; e = errors.Unwrap(e) {
		full.WriteString(e.Error())
	}
	if strings.Contains(full.String(), "SECRETKEY") {
		t.Fatalf("error chain leaks API key: %s", full.String())
	}
	if c.Endpoint() != "http://127.0.0.1:1/<redacted>" {
		t.Fatal(c.Endpoint())
	}
}

// Every failure path (not only connection errors) must keep the endpoint
// URL, which usually holds an API key, out of the error chain: errors on
// 5xx responses are logged by the API server.
func TestNoFailurePathLeaksURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/slow"):
			time.Sleep(300 * time.Millisecond)
		case strings.HasSuffix(r.URL.Path, "/500"):
			w.WriteHeader(http.StatusBadGateway)
		case strings.HasSuffix(r.URL.Path, "/400"):
			w.WriteHeader(http.StatusForbidden)
		default:
			_, _ = io.WriteString(w, "not json")
		}
	}))
	defer srv.Close()
	chain := func(err error) string {
		var b strings.Builder
		for e := err; e != nil; e = errors.Unwrap(e) {
			b.WriteString(e.Error() + " | ")
		}
		return b.String()
	}
	cases := []struct {
		path string
		ctx  func() (context.Context, context.CancelFunc)
		kind txerrors.Kind
	}{
		{"/v2/SECRETKEY/slow", func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 30*time.Millisecond)
		}, txerrors.KindTimeout},
		{"/v2/SECRETKEY/slow", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(30*time.Millisecond, cancel)
			return ctx, cancel
		}, txerrors.KindTimeout},
		{"/v2/SECRETKEY/500", nil, txerrors.KindUnavailable},
		{"/v2/SECRETKEY/400", nil, txerrors.KindUnavailable},
		{"/v2/SECRETKEY/garbage", nil, txerrors.KindUnavailable},
	}
	for _, tc := range cases {
		c, err := DialUpstream(context.Background(), srv.URL+tc.path+"?apikey=SECRETQUERY", fastOpts())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.Background(), context.CancelFunc(func() {})
		if tc.ctx != nil {
			ctx, cancel = tc.ctx()
		}
		_, err = c.BlockNumber(ctx)
		cancel()
		if txerrors.KindOf(err) != tc.kind {
			t.Errorf("%s: kind %v, err %v", tc.path, txerrors.KindOf(err), err)
		}
		if s := chain(err); strings.Contains(s, "SECRET") {
			t.Errorf("%s: error chain leaks the URL: %s", tc.path, s)
		}
	}
}

func TestResponseSizeLimitAndRedirects(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"0x`+strings.Repeat("00", 4096)+`"}`)
	}))
	defer big.Close()
	o := fastOpts()
	o.MaxResponseBytes = 1024
	c, _ := DialUpstream(context.Background(), big.URL, o)
	if _, err := c.CodeAt(context.Background(), common.Address{}, nil); txerrors.KindOf(err) != txerrors.KindUnavailable || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("err = %v", err)
	}

	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	c, _ = DialUpstream(context.Background(), redirect.URL, fastOpts())
	if _, err := c.BlockNumber(context.Background()); err == nil {
		t.Fatal("redirect must not be followed")
	}
}

func TestDialValidation(t *testing.T) {
	for _, u := range []string{"ftp://x", "ws://x", "notaurl", "http://"} {
		if _, err := DialUpstream(context.Background(), u, Options{}); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
	for _, u := range []string{"http://example.com:8545", "http://10.0.0.1:8545", "http://localhost:8545"} {
		if _, err := DialLocal(context.Background(), u, Options{}); err == nil {
			t.Errorf("DialLocal accepted non-loopback-IP %s", u)
		}
	}
	if _, err := DialLocal(context.Background(), "http://127.0.0.1:8545", Options{}); err != nil {
		t.Fatal(err)
	}
}

func TestContextCancellation(t *testing.T) {
	_, c := newNode(t, func(string, []json.RawMessage) (int, any, *RPCError) {
		time.Sleep(200 * time.Millisecond)
		return 0, "0x1", nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.BlockNumber(ctx); txerrors.KindOf(err) != txerrors.KindTimeout {
		t.Fatalf("err = %v", err)
	}
}

func TestRegistryChainVerification(t *testing.T) {
	n := &fakeNode{handle: func(m string, _ []json.RawMessage) (int, any, *RPCError) { return 0, "0x5", nil }}
	srv := httptest.NewServer(n)
	defer srv.Close()
	r := NewRegistry(map[uint64]string{1: srv.URL, 5: srv.URL}, fastOpts())
	if _, err := r.Reader(1); txerrors.KindOf(err) != txerrors.KindUnsupported || !strings.Contains(err.Error(), "reports chain 5") {
		t.Fatalf("mismatch not detected: %v", err)
	}
	if _, err := r.Reader(5); err != nil {
		t.Fatal(err)
	}
	before := len(n.called())
	if _, err := r.Reader(5); err != nil || len(n.called()) != before {
		t.Fatal("verification must be cached")
	}
	if _, err := r.Reader(999); txerrors.KindOf(err) != txerrors.KindUnsupported {
		t.Fatal("unknown chain")
	}
	if got := r.Chains(); len(got) != 2 || got[0] != 1 {
		t.Fatal(got)
	}
}

func TestBackoffBounds(t *testing.T) {
	p := RetryPolicy{BaseDelay: 100 * time.Millisecond, MaxDelay: 300 * time.Millisecond}.withDefaults()
	for n := 1; n < 70; n++ {
		if d := p.backoff(n); d < 0 || d > 300*time.Millisecond {
			t.Fatalf("attempt %d: %s", n, d)
		}
	}
}

func TestPublicOnlyRefusesLoopback(t *testing.T) {
	n := &fakeNode{handle: func(string, []json.RawMessage) (int, any, *RPCError) { return 0, "0x1", nil }}
	srv := httptest.NewServer(n)
	defer srv.Close()
	o := fastOpts()
	o.PublicOnly = true
	guarded, err := DialUpstream(context.Background(), srv.URL, o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guarded.BlockNumber(context.Background()); err == nil || len(n.called()) != 0 {
		t.Fatalf("guarded client reached a loopback server: err=%v calls=%v", err, n.called())
	}
}
