package evm

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/txshield/txshield/internal/config"
	"github.com/txshield/txshield/pkg/interfaces"
	"github.com/txshield/txshield/pkg/models"
	"github.com/txshield/txshield/pkg/txerrors"
)

// upstreamMethods is the complete set of JSON-RPC methods TxShield may call
// on an operator's (real network) endpoint. Everything else, in particular
// eth_sendRawTransaction, eth_sendTransaction, eth_sign*, personal_*, and
// node-mutating anvil_/hardhat_/evm_ methods, is refused before any network
// I/O. This is the enforcement point for "TxShield never broadcasts".
var upstreamMethods = map[string]bool{
	"eth_chainId": true, "net_version": true, "eth_blockNumber": true,
	"eth_getBlockByNumber": true, "eth_getBlockByHash": true,
	"eth_getCode": true, "eth_getBalance": true, "eth_getStorageAt": true, "eth_getTransactionCount": true,
	"eth_call": true, "eth_estimateGas": true, "eth_gasPrice": true, "eth_maxPriorityFeePerGas": true, "eth_feeHistory": true,
	"eth_getTransactionByHash": true, "eth_getTransactionReceipt": true, "eth_getLogs": true,
	"debug_traceCall": true, "debug_traceTransaction": true,
}

// ErrMethodNotAllowed is returned for methods outside the upstream allowlist.
var ErrMethodNotAllowed = errors.New("rpc method not allowed on upstream endpoint")

// Options configures a Client.
type Options struct {
	Retry            RetryPolicy
	BreakerThreshold int
	BreakerCooldown  time.Duration
	MaxResponseBytes int64 // default 32 MiB
	// PublicOnly refuses connections to non-public IPs at dial time (SSRF
	// protection for user-supplied endpoints).
	PublicOnly bool
}

// Client is a JSON-RPC client with retries, a circuit breaker, a response
// size cap, and (for upstream endpoints) a read-only method allowlist.
type Client struct {
	rpc      *httpRPC
	redacted string
	local    bool
	retry    RetryPolicy
	breaker  *Breaker
}

var _ interfaces.ChainReader = (*Client)(nil)

// DialUpstream connects to an operator-configured network endpoint
// (read-only). Only http(s) URLs are accepted.
func DialUpstream(ctx context.Context, rawURL string, o Options) (*Client, error) {
	return dial(ctx, rawURL, o, false)
}

// DialLocal connects to a loopback endpoint owned by TxShield (an Anvil
// fork). Any method is allowed, including transaction sending, because the
// node is private and discarded. Non-loopback URLs are rejected.
func DialLocal(ctx context.Context, rawURL string, o Options) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid local RPC URL")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("local RPC endpoint must be a loopback IP address")
	}
	return dial(ctx, rawURL, o, true)
}

func dial(_ context.Context, rawURL string, o Options, local bool) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid RPC URL")
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("RPC URL scheme must be http or https")
	}
	limit := o.MaxResponseBytes
	if limit <= 0 {
		limit = 32 << 20
	}
	base := http.RoundTripper(sharedTransport)
	if o.PublicOnly {
		base = guardedTransport
	}
	httpClient := &http.Client{
		Transport: limitTransport{base: base, limit: limit},
		// Redirects could point a trusted endpoint at an internal address.
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are not followed") },
	}
	return &Client{
		rpc: &httpRPC{url: rawURL, client: httpClient}, redacted: config.RedactURL(rawURL), local: local,
		retry: o.Retry.withDefaults(), breaker: NewBreaker(o.BreakerThreshold, o.BreakerCooldown),
	}, nil
}

// Close releases idle connections. Connections are pooled process-wide.
func (c *Client) Close() {}

// Endpoint returns the redacted endpoint for logs.
func (c *Client) Endpoint() string { return c.redacted }

// Breaker exposes the circuit breaker state.
func (c *Client) Breaker() *Breaker { return c.breaker }

// Call performs a JSON-RPC call with policy enforcement, retries, and the
// circuit breaker. Infrastructure failures are returned as *txerrors.Error
// (Unavailable/Timeout); JSON-RPC error responses are returned unchanged so
// callers can distinguish e.g. execution reverts.
func (c *Client) Call(ctx context.Context, result any, method string, args ...any) error {
	if !c.local && !upstreamMethods[method] {
		return txerrors.Wrap(ErrMethodNotAllowed, txerrors.KindInternal, "rpc_method_denied", "internal error: refused to call "+method+" upstream")
	}
	var lastErr error
	for attempt := 1; attempt <= c.retry.MaxAttempts; attempt++ {
		if err := c.breaker.Allow(); err != nil {
			return txerrors.Wrap(err, txerrors.KindUnavailable, "rpc_circuit_open", "RPC endpoint temporarily unavailable")
		}
		err := c.rpc.call(ctx, result, method, args...)
		transient := isTransient(err)
		c.breaker.Record(transient)
		if err == nil {
			return nil
		}
		lastErr = err
		if !transient || attempt == c.retry.MaxAttempts {
			break
		}
		select {
		case <-time.After(c.retry.backoff(attempt)):
		case <-ctx.Done():
			lastErr = ctx.Err()
		}
		if ctx.Err() != nil {
			break
		}
	}
	return c.classify(lastErr)
}

// classify maps a transport failure to a *txerrors.Error. Every wrapped
// error is redacted first: net/http errors embed the request URL, and RPC
// provider URLs usually carry an API key in the path or query.
func (c *Client) classify(err error) error {
	var rpcErr *RPCError
	if errors.As(err, &rpcErr) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return err // JSON-RPC error response: a deterministic answer
	}
	red := redactErr(err, c.rpc.url)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return txerrors.Wrap(red, txerrors.KindTimeout, "rpc_timeout", "RPC request timed out")
	case errors.Is(err, context.Canceled):
		return txerrors.Wrap(red, txerrors.KindTimeout, "rpc_cancelled", "RPC request cancelled")
	case errors.Is(err, errResponseTooLarge):
		return txerrors.Wrap(red, txerrors.KindUnavailable, "rpc_response_too_large", "RPC response exceeded the size limit")
	case isTransient(err):
		return txerrors.Wrap(red, txerrors.KindUnavailable, "rpc_unavailable", "RPC endpoint unavailable")
	}
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return txerrors.Wrap(red, txerrors.KindUnavailable, "rpc_http_error", fmt.Sprintf("RPC endpoint returned HTTP %d", httpErr.StatusCode))
	}
	return txerrors.Wrap(red, txerrors.KindUnavailable, "rpc_bad_response", "RPC endpoint returned an invalid response")
}

// redactErr strips URLs (which may embed API keys) from transport errors.
func redactErr(err error, rawURL string) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s %s: %w", ue.Op, config.RedactURL(ue.URL), ue.Err)
	}
	if rawURL != "" && strings.Contains(err.Error(), rawURL) {
		return errors.New(strings.ReplaceAll(err.Error(), rawURL, config.RedactURL(rawURL)))
	}
	return err
}

// IsExecutionError reports whether err is a JSON-RPC error response (e.g.
// "execution reverted") rather than an infrastructure failure.
func IsExecutionError(err error) bool {
	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) {
		return false
	}
	_, isTx := txerrors.As(err)
	return !isTx
}

// ---------------------------------------------------------------------------
// interfaces.ChainReader

func blockArg(block *big.Int) string {
	if block == nil {
		return "latest"
	}
	return hexutil.EncodeBig(block)
}

// ChainID returns eth_chainId.
func (c *Client) ChainID(ctx context.Context) (*big.Int, error) {
	var r hexutil.Big
	if err := c.Call(ctx, &r, "eth_chainId"); err != nil {
		return nil, err
	}
	return (*big.Int)(&r), nil
}

// BlockNumber returns eth_blockNumber.
func (c *Client) BlockNumber(ctx context.Context) (uint64, error) {
	var r hexutil.Uint64
	err := c.Call(ctx, &r, "eth_blockNumber")
	return uint64(r), err
}

// CodeAt returns eth_getCode.
func (c *Client) CodeAt(ctx context.Context, addr common.Address, block *big.Int) ([]byte, error) {
	var r hexutil.Bytes
	err := c.Call(ctx, &r, "eth_getCode", addr, blockArg(block))
	return r, err
}

// BalanceAt returns eth_getBalance.
func (c *Client) BalanceAt(ctx context.Context, addr common.Address, block *big.Int) (*big.Int, error) {
	var r hexutil.Big
	if err := c.Call(ctx, &r, "eth_getBalance", addr, blockArg(block)); err != nil {
		return nil, err
	}
	return (*big.Int)(&r), nil
}

// StorageAt returns eth_getStorageAt.
func (c *Client) StorageAt(ctx context.Context, addr common.Address, slot common.Hash, block *big.Int) ([]byte, error) {
	var r hexutil.Bytes
	err := c.Call(ctx, &r, "eth_getStorageAt", addr, slot, blockArg(block))
	return r, err
}

// CallArgs is the JSON shape of a call object. Fee fields are omitted on
// purpose: reads should not depend on the caller's fee settings.
type CallArgs struct {
	From  *common.Address `json:"from,omitempty"`
	To    *common.Address `json:"to,omitempty"`
	Gas   *hexutil.Uint64 `json:"gas,omitempty"`
	Value *hexutil.Big    `json:"value,omitempty"`
	Data  hexutil.Bytes   `json:"data,omitempty"`
}

// ArgsFor converts a transaction into call arguments.
func ArgsFor(tx *models.Transaction) CallArgs {
	a := CallArgs{To: tx.To, Data: tx.Data}
	if tx.From != (common.Address{}) {
		from := tx.From
		a.From = &from
	}
	if tx.Value != nil && tx.Value.Sign() > 0 {
		a.Value = (*hexutil.Big)(tx.Value)
	}
	if tx.Gas != nil {
		g := hexutil.Uint64(*tx.Gas)
		a.Gas = &g
	}
	return a
}

// CallContract performs eth_call. A successful call is not evidence of safety.
func (c *Client) CallContract(ctx context.Context, tx *models.Transaction, block *big.Int) ([]byte, error) {
	var r hexutil.Bytes
	err := c.Call(ctx, &r, "eth_call", ArgsFor(tx), blockArg(block))
	return r, err
}

// EstimateGas performs eth_estimateGas.
func (c *Client) EstimateGas(ctx context.Context, tx *models.Transaction) (uint64, error) {
	var r hexutil.Uint64
	err := c.Call(ctx, &r, "eth_estimateGas", ArgsFor(tx))
	return uint64(r), err
}

type rpcHeader struct {
	Number    hexutil.Uint64 `json:"number"`
	Hash      common.Hash    `json:"hash"`
	Timestamp hexutil.Uint64 `json:"timestamp"`
	BaseFee   *hexutil.Big   `json:"baseFeePerGas"`
	GasLimit  hexutil.Uint64 `json:"gasLimit"`
}

// ResolveBlock resolves a tag, number, or hash to a concrete block.
func (c *Client) ResolveBlock(ctx context.Context, ref models.BlockRef) (models.BlockInfo, error) {
	var h *rpcHeader
	var err error
	if ref.Hash != nil {
		err = c.Call(ctx, &h, "eth_getBlockByHash", *ref.Hash, false)
	} else {
		err = c.Call(ctx, &h, "eth_getBlockByNumber", ref.String(), false)
	}
	if err != nil {
		return models.BlockInfo{}, err
	}
	if h == nil {
		return models.BlockInfo{}, txerrors.New(txerrors.KindNotFound, "block_not_found", "block "+ref.String()+" not found")
	}
	info := models.BlockInfo{Number: uint64(h.Number), Hash: h.Hash.Hex(), Timestamp: uint64(h.Timestamp), GasLimit: uint64(h.GasLimit)}
	if h.BaseFee != nil {
		info.BaseFee = (*big.Int)(h.BaseFee).String()
	}
	return info, nil
}
