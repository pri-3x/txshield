package evm

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/txerrors"
)

// Registry maps chain IDs to operator-configured RPC endpoints. Clients are
// dialed lazily, and each endpoint's eth_chainId is verified once against
// the configured chain ID: analyzing a mainnet transaction against a testnet
// endpoint would silently produce wrong results.
type Registry struct {
	urls map[uint64]string
	opts Options

	mu       sync.Mutex
	clients  map[uint64]*Client
	verified map[uint64]bool
}

var _ interfaces.ChainRegistry = (*Registry)(nil)

// NewRegistry builds a registry from chainID -> URL.
func NewRegistry(urls map[uint64]string, opts Options) *Registry {
	cp := make(map[uint64]string, len(urls))
	for k, v := range urls {
		cp[k] = v
	}
	return &Registry{urls: cp, opts: opts, clients: map[uint64]*Client{}, verified: map[uint64]bool{}}
}

// Chains returns configured chain IDs, ascending.
func (r *Registry) Chains() []uint64 {
	out := make([]uint64, 0, len(r.urls))
	for id := range r.urls {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// RPCURL returns the raw (secret-bearing) URL for fork simulators.
func (r *Registry) RPCURL(chainID uint64) (string, error) {
	u, ok := r.urls[chainID]
	if !ok {
		return "", unsupportedChain(chainID)
	}
	return u, nil
}

// Reader returns a verified read-only client for chainID.
func (r *Registry) Reader(chainID uint64) (interfaces.ChainReader, error) {
	return r.Client(context.Background(), chainID)
}

// Client returns the concrete client, verifying the chain ID on first use.
func (r *Registry) Client(ctx context.Context, chainID uint64) (*Client, error) {
	raw, ok := r.urls[chainID]
	if !ok {
		return nil, unsupportedChain(chainID)
	}
	r.mu.Lock()
	c := r.clients[chainID]
	verified := r.verified[chainID]
	r.mu.Unlock()

	if c == nil {
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		nc, err := DialUpstream(dctx, raw, r.opts)
		if err != nil {
			return nil, txerrors.Wrap(err, txerrors.KindUnavailable, "rpc_dial_failed", "could not connect to the RPC endpoint")
		}
		r.mu.Lock()
		if existing := r.clients[chainID]; existing != nil {
			nc.Close()
			c = existing
		} else {
			r.clients[chainID] = nc
			c = nc
		}
		r.mu.Unlock()
	}
	if verified {
		return c, nil
	}
	vctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	got, err := c.ChainID(vctx)
	if err != nil {
		return nil, err // transient; verification retried next time
	}
	if !got.IsUint64() || got.Uint64() != chainID {
		return nil, txerrors.New(txerrors.KindUnsupported, "rpc_chain_mismatch",
			fmt.Sprintf("the RPC endpoint configured for chain %d reports chain %s", chainID, got))
	}
	r.mu.Lock()
	r.verified[chainID] = true
	r.mu.Unlock()
	return c, nil
}

// Close closes all dialed clients.
func (r *Registry) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, c := range r.clients {
		c.Close()
		delete(r.clients, id)
	}
}

func unsupportedChain(id uint64) error {
	return txerrors.New(txerrors.KindUnsupported, "chain_not_configured", fmt.Sprintf("no RPC endpoint is configured for chain %d", id))
}
