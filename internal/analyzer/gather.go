package analyzer

import (
	"context"
	"fmt"
	"math/big"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/pri-3x/txshield/internal/evm"
	"github.com/pri-3x/txshield/internal/security/core"
	"github.com/pri-3x/txshield/pkg/models"
)

// gathered is the chain context (contract facts and reputation) for a set of
// addresses.
type gathered struct {
	contracts       map[common.Address]*models.ContractInfo
	reputation      map[common.Address][]models.ReputationRecord
	repWarnings     []string
	inspectFailures int
}

// gather looks up reputation and contract facts for addrs in parallel.
func (a *Analyzer) gather(ctx context.Context, chainID uint64, addrs []common.Address, block uint64) gathered {
	g := gathered{contracts: map[common.Address]*models.ContractInfo{}, reputation: map[common.Address][]models.ReputationRecord{}}
	var wg sync.WaitGroup
	if a.d.Reputation != nil && len(addrs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.reputation, g.repWarnings = a.d.Reputation.LookupAll(ctx, chainID, addrs)
		}()
	}
	if a.d.Inspector != nil && len(addrs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.contracts, g.inspectFailures = a.inspect(ctx, chainID, addrs, block)
		}()
	}
	wg.Wait()
	if g.reputation == nil {
		g.reputation = map[common.Address][]models.ReputationRecord{}
	}
	return g
}

func (g *gathered) merge(o gathered) {
	for k, v := range o.contracts {
		g.contracts[k] = v
	}
	for k, v := range o.reputation {
		g.reputation[k] = v
	}
	for _, w := range o.repWarnings {
		if !slices.Contains(g.repWarnings, w) {
			g.repWarnings = append(g.repWarnings, w)
		}
	}
	g.inspectFailures += o.inspectFailures
}

func (g *gathered) warnings() []string {
	out := append([]string{}, g.repWarnings...)
	if g.inspectFailures > 0 {
		out = append(out, fmt.Sprintf("contract facts unavailable for %d address(es); rules that need them were skipped", g.inspectFailures))
	}
	return out
}

// limitAddresses returns the addresses in a stable order, bounded by
// MaxAddresses (adversarial calldata can reference thousands).
func (a *Analyzer) limitAddresses(roles core.AddressRoles) []common.Address {
	addrs := make([]common.Address, 0, len(roles))
	for addr := range roles {
		addrs = append(addrs, addr)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Hex() < addrs[j].Hex() })
	if len(addrs) > a.d.MaxAddresses {
		addrs = addrs[:a.d.MaxAddresses]
	}
	return addrs
}

// missing returns the addresses in all that are not in have.
func missing(all, have []common.Address) []common.Address {
	set := make(map[common.Address]bool, len(have))
	for _, h := range have {
		set[h] = true
	}
	var out []common.Address
	for _, x := range all {
		if !set[x] {
			out = append(out, x)
		}
	}
	return out
}

// Token metadata limits: display hints are not worth slowing a report down.
const (
	maxTokenMetadata     = 16
	tokenMetadataTimeout = 3 * time.Second
	tokenMetaConcurrency = 8
)

type tokenMeta struct {
	symbol   string
	decimals *uint8
}

// tokenCache keeps token symbols/decimals per (chain, token). They are
// display hints only (never read by rules), so caching them across blocks is
// acceptable.
type tokenCache struct {
	mu  sync.Mutex
	max int
	m   map[string]tokenMeta
}

func newTokenCache(maxEntries int) *tokenCache {
	return &tokenCache{max: maxEntries, m: map[string]tokenMeta{}}
}

func tokenKey(chainID uint64, addr common.Address) string {
	return fmt.Sprintf("%d/%s", chainID, addr.Hex())
}

func (c *tokenCache) get(chainID uint64, addr common.Address) (tokenMeta, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[tokenKey(chainID, addr)]
	return v, ok
}

func (c *tokenCache) put(chainID uint64, addr common.Address, v tokenMeta) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.max {
		for k := range c.m { // random eviction (map order is randomized)
			delete(c.m, k)
			break
		}
	}
	c.m[tokenKey(chainID, addr)] = v
}

// fetchTokenMeta reads symbol and decimals of simulated token assets from
// the token contracts themselves, in parallel and cached. These are
// self-reported, can be spoofed, and are only display hints (the API schema
// and UI label them unverified); rules never read them. Failures leave the
// fields empty. It only reads sim, so it may run while rules evaluate.
func (a *Analyzer) fetchTokenMeta(ctx context.Context, chainID uint64, sim *models.SimulationResult) map[common.Address]tokenMeta {
	if a.d.Chains == nil || sim == nil || (len(sim.AssetTransfers) == 0 && len(sim.BalanceChanges) == 0) {
		return nil
	}
	var order []common.Address
	seen := map[common.Address]bool{}
	collect := func(ref models.AssetRef) {
		if ref.Kind == models.AssetNative || !common.IsHexAddress(ref.Address) || len(order) >= maxTokenMetadata {
			return
		}
		addr := common.HexToAddress(ref.Address)
		if !seen[addr] {
			seen[addr] = true
			order = append(order, addr)
		}
	}
	for _, t := range sim.AssetTransfers {
		collect(t.Asset)
	}
	for _, b := range sim.BalanceChanges {
		collect(b.Asset)
	}
	if len(order) == 0 {
		return nil
	}
	out := make(map[common.Address]tokenMeta, len(order))
	var todo []common.Address
	for _, addr := range order {
		if m, ok := a.tokens.get(chainID, addr); ok {
			out[addr] = m
		} else {
			todo = append(todo, addr)
		}
	}
	if len(todo) == 0 {
		return out
	}
	reader, err := a.d.Chains.Reader(chainID)
	if err != nil {
		return out
	}
	var blk *big.Int
	if sim.BlockNumber > 0 {
		blk = new(big.Int).SetUint64(sim.BlockNumber)
	}
	mctx, cancel := context.WithTimeout(ctx, tokenMetadataTimeout)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, tokenMetaConcurrency)
	for _, addr := range todo {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-mctx.Done():
				return
			}
			symbol, decimals, err := evm.TokenMetadata(mctx, reader, addr, blk)
			if err != nil {
				return
			}
			m := tokenMeta{symbol, decimals}
			a.tokens.put(chainID, addr, m)
			mu.Lock()
			out[addr] = m
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

// applyTokenMeta fills Symbol and Decimals on simulated token assets.
func applyTokenMeta(sim *models.SimulationResult, meta map[common.Address]tokenMeta) {
	if len(meta) == 0 {
		return
	}
	apply := func(ref *models.AssetRef) {
		if ref.Kind == models.AssetNative || !common.IsHexAddress(ref.Address) {
			return
		}
		m, ok := meta[common.HexToAddress(ref.Address)]
		if !ok {
			return
		}
		ref.Symbol = m.symbol
		// Decimals only make sense for fungible tokens.
		if ref.Kind == models.AssetERC20 {
			ref.Decimals = m.decimals
		}
	}
	for i := range sim.AssetTransfers {
		apply(&sim.AssetTransfers[i].Asset)
	}
	for i := range sim.BalanceChanges {
		apply(&sim.BalanceChanges[i].Asset)
	}
}
