package evm

import (
	"bytes"
	"container/list"
	"context"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
)

// Well-known proxy storage slots.
var (
	slotEIP1967Impl   = common.HexToHash("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
	slotEIP1967Beacon = common.HexToHash("0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50")
	slotEIP1822       = common.HexToHash("0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7")
	slotOZLegacy      = common.HexToHash("0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3")
)

// EIP-1167 minimal proxy runtime code: prefix | implementation | suffix.
var (
	minimalProxyPrefix = common.FromHex("363d3d373d3d3d363d73")
	minimalProxySuffix = common.FromHex("5af43d82803e903d91602b57fd5bf3")
	eip7702Prefix      = common.FromHex("ef0100")
)

// Selectors used for standard detection.
var (
	selSupportsInterface = common.FromHex("01ffc9a7")
	selImplementation    = common.FromHex("5c60da1b")
	selTotalSupply       = common.FromHex("18160ddd")
	selBalanceOf         = common.FromHex("70a08231")
	selDecimals          = common.FromHex("313ce567")
)

const inspectCallGas = 100_000

// Inspector implements interfaces.ContractInspector using a ChainRegistry.
//
// Facts it reports: code presence, code hash/size, EIP-7702 delegation,
// proxy implementation (EIP-1167, EIP-1967 implementation/beacon, EIP-1822,
// legacy OpenZeppelin slot). Token standards: ERC-721/ERC-1155 via ERC-165
// (strong signal); ERC-20 via a heuristic (totalSupply, balanceOf, decimals
// all answer). Contract names and verification status are not fetched.
type Inspector struct {
	reg   interfaces.ChainRegistry
	cache *lru
	// std caches token standards by (chain, address, code hash,
	// implementation) across blocks: they follow from the code that runs, so
	// a new block only needs the code and proxy slots re-read (in parallel),
	// not the ERC-165/ERC-20 probe chain.
	std *lru
}

var _ interfaces.ContractInspector = (*Inspector)(nil)

// NewInspector returns an inspector with an LRU cache of cacheSize entries
// (results at pinned blocks are immutable and safe to cache).
func NewInspector(reg interfaces.ChainRegistry, cacheSize int) *Inspector {
	if cacheSize <= 0 {
		cacheSize = 4096
	}
	return &Inspector{reg: reg, cache: newLRU(cacheSize), std: newLRU(cacheSize)}
}

// Inspect reads facts about addr at block (0 = latest, not cached).
func (in *Inspector) Inspect(ctx context.Context, chainID uint64, addr common.Address, block uint64) (*models.ContractInfo, error) {
	key := fmt.Sprintf("%d|%s|%d", chainID, addr.Hex(), block)
	if block > 0 {
		if v, ok := in.cache.get(key); ok {
			info := *v
			return &info, nil
		}
	}
	r, err := in.reg.Reader(chainID)
	if err != nil {
		return nil, err
	}
	var blk *big.Int
	if block > 0 {
		blk = new(big.Int).SetUint64(block)
	}
	info, err := inspectWith(ctx, r, chainID, addr, blk, in.std)
	if err != nil {
		return nil, err
	}
	info.AtBlock = block
	if block > 0 {
		cp := *info
		in.cache.put(key, &cp)
	}
	return info, nil
}

func inspect(ctx context.Context, r interfaces.ChainReader, chainID uint64, addr common.Address, blk *big.Int) (*models.ContractInfo, error) {
	return inspectWith(ctx, r, chainID, addr, blk, nil)
}

func inspectWith(ctx context.Context, r interfaces.ChainReader, chainID uint64, addr common.Address, blk *big.Int, stdCache *lru) (*models.ContractInfo, error) {
	info := &models.ContractInfo{ChainID: chainID, Address: addr.Hex()}
	code, err := r.CodeAt(ctx, addr, blk)
	if err != nil {
		return nil, err
	}
	info.CodeSize = len(code)
	if len(code) == 0 {
		return info, nil
	}
	info.CodeHash = crypto.Keccak256Hash(code).Hex()

	// EIP-7702: an EOA delegating to contract code. It is still a user
	// account (has a private key), so it is not reported as a contract.
	if len(code) == 23 && bytes.HasPrefix(code, eip7702Prefix) {
		info.Standards = []string{"eip7702-delegated"}
		info.Implementation = common.BytesToAddress(code[3:]).Hex()
		return info, nil
	}
	info.IsContract = true

	if impl, ok := minimalProxyTarget(code); ok {
		info.IsProxy, info.Implementation = true, impl.Hex()
	} else if impl, err := slotProxyTarget(ctx, r, addr, blk); err != nil {
		return nil, err
	} else if impl != (common.Address{}) {
		info.IsProxy, info.Implementation = true, impl.Hex()
	}

	stdKey := fmt.Sprintf("%d|%s|%s|%s", chainID, addr.Hex(), info.CodeHash, info.Implementation)
	if stdCache != nil {
		if v, ok := stdCache.get(stdKey); ok {
			info.Standards = append([]string(nil), v.Standards...)
			return info, nil
		}
	}
	std, err := detectStandards(ctx, r, addr, blk)
	if err != nil {
		return nil, err
	}
	info.Standards = std
	if stdCache != nil {
		stdCache.put(stdKey, &models.ContractInfo{Standards: append([]string(nil), std...)})
	}
	return info, nil
}

func minimalProxyTarget(code []byte) (common.Address, bool) {
	n := len(minimalProxyPrefix) + 20 + len(minimalProxySuffix)
	if len(code) != n || !bytes.HasPrefix(code, minimalProxyPrefix) || !bytes.HasSuffix(code, minimalProxySuffix) {
		return common.Address{}, false
	}
	return common.BytesToAddress(code[len(minimalProxyPrefix) : len(minimalProxyPrefix)+20]), true
}

func slotAddress(ctx context.Context, r interfaces.ChainReader, addr common.Address, slot common.Hash, blk *big.Int) (common.Address, error) {
	v, err := r.StorageAt(ctx, addr, slot, blk)
	if err != nil {
		return common.Address{}, err
	}
	return common.BytesToAddress(v), nil
}

func slotProxyTarget(ctx context.Context, r interfaces.ChainReader, addr common.Address, blk *big.Int) (common.Address, error) {
	// All four slots are read at once; precedence is applied afterwards.
	slots := []common.Hash{slotEIP1967Impl, slotEIP1822, slotOZLegacy, slotEIP1967Beacon}
	vals := make([]common.Address, len(slots))
	errs := make([]error, len(slots))
	var wg sync.WaitGroup
	for i, slot := range slots {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vals[i], errs[i] = slotAddress(ctx, r, addr, slot, blk)
		}()
	}
	wg.Wait()
	for i := range slots[:3] {
		if errs[i] != nil {
			return common.Address{}, errs[i]
		}
		if vals[i] != (common.Address{}) {
			return vals[i], nil
		}
	}
	beacon, err := vals[3], errs[3]
	if err != nil || beacon == (common.Address{}) {
		return common.Address{}, err
	}
	out, ok, err := staticCall(ctx, r, beacon, selImplementation, blk)
	if err != nil || !ok || len(out) < 32 {
		return common.Address{}, err
	}
	return common.BytesToAddress(out[12:32]), nil
}

// staticCall returns (output, true) on success, (nil, false) when the call
// reverted, and an error only for infrastructure failures.
func staticCall(ctx context.Context, r interfaces.ChainReader, to common.Address, data []byte, blk *big.Int) ([]byte, bool, error) {
	gas := uint64(inspectCallGas)
	out, err := r.CallContract(ctx, &models.Transaction{To: &to, Data: data, Gas: &gas, Value: new(big.Int)}, blk)
	if err != nil {
		if IsExecutionError(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return out, true, nil
}

func supportsInterface(ctx context.Context, r interfaces.ChainReader, addr common.Address, id string, blk *big.Int) (bool, error) {
	data := append(append([]byte{}, selSupportsInterface...), common.RightPadBytes(common.FromHex(id), 32)...)
	out, ok, err := staticCall(ctx, r, addr, data, blk)
	if err != nil || !ok || len(out) != 32 {
		return false, err
	}
	return new(big.Int).SetBytes(out).Cmp(big.NewInt(1)) == 0, nil
}

func detectStandards(ctx context.Context, r interfaces.ChainReader, addr common.Address, blk *big.Int) ([]string, error) {
	// ERC-165 compliance requires true for 0x01ffc9a7 and false for 0xffffffff.
	is165, err := supportsInterface(ctx, r, addr, "01ffc9a7", blk)
	if err != nil {
		return nil, err
	}
	if is165 {
		bogus, err := supportsInterface(ctx, r, addr, "ffffffff", blk)
		if err != nil {
			return nil, err
		}
		if !bogus {
			var std []string
			for id, name := range map[string]string{"80ac58cd": "erc721", "d9b67a26": "erc1155"} {
				ok, err := supportsInterface(ctx, r, addr, id, blk)
				if err != nil {
					return nil, err
				}
				if ok {
					std = append(std, name)
				}
			}
			if len(std) > 0 {
				if len(std) == 2 && std[0] > std[1] {
					std[0], std[1] = std[1], std[0]
				}
				return std, nil
			}
		}
	}
	// ERC-20 heuristic (ERC-20 has no ERC-165 identifier). The three probes
	// are independent and run at once.
	probes := [][]byte{selTotalSupply, append(append([]byte{}, selBalanceOf...), make([]byte, 32)...), selDecimals}
	outs := make([][]byte, 3)
	oks := make([]bool, 3)
	errs := make([]error, 3)
	var wg sync.WaitGroup
	for i, data := range probes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outs[i], oks[i], errs[i] = staticCall(ctx, r, addr, data, blk)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	ts, bal, dec := outs[0], outs[1], outs[2]
	ok1, ok2, ok3 := oks[0], oks[1], oks[2]
	if ok1 && ok2 && ok3 && len(ts) == 32 && len(bal) == 32 && len(dec) == 32 && new(big.Int).SetBytes(dec).Cmp(big.NewInt(255)) <= 0 {
		return []string{"erc20"}, nil
	}
	return nil, nil
}

// lru is a small thread-safe LRU cache.
type lru struct {
	mu    sync.Mutex
	cap   int
	ll    *list.List
	items map[string]*list.Element
}

type lruEntry struct {
	key string
	val *models.ContractInfo
}

func newLRU(capacity int) *lru {
	return &lru{cap: capacity, ll: list.New(), items: map[string]*list.Element{}}
}

func (c *lru) get(k string) (*models.ContractInfo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[k]; ok {
		c.ll.MoveToFront(e)
		return e.Value.(*lruEntry).val, true
	}
	return nil, false
}

func (c *lru) put(k string, v *models.ContractInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[k]; ok {
		e.Value.(*lruEntry).val = v
		c.ll.MoveToFront(e)
		return
	}
	c.items[k] = c.ll.PushFront(&lruEntry{k, v})
	if c.ll.Len() > c.cap {
		last := c.ll.Back()
		c.ll.Remove(last)
		delete(c.items, last.Value.(*lruEntry).key)
	}
}
