package evm

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
	"github.com/pri-3x/txshield/pkg/txerrors"
)

// fakeReader is an in-memory ChainReader.
type fakeReader struct {
	code    map[common.Address][]byte
	storage map[common.Address]map[common.Hash][]byte
	// calls maps "address|selector(+args hex)" to output; missing = revert.
	calls    map[string][]byte
	infraErr error
	n        atomic.Int32
}

var errRevert = &RPCError{Code: 3, Message: "execution reverted"}

func (f *fakeReader) ChainID(context.Context) (*big.Int, error)   { return big.NewInt(1), nil }
func (f *fakeReader) BlockNumber(context.Context) (uint64, error) { return 1, nil }
func (f *fakeReader) CodeAt(_ context.Context, a common.Address, _ *big.Int) ([]byte, error) {
	f.n.Add(1)
	return f.code[a], f.infraErr
}
func (f *fakeReader) BalanceAt(context.Context, common.Address, *big.Int) (*big.Int, error) {
	return new(big.Int), nil
}
func (f *fakeReader) StorageAt(_ context.Context, a common.Address, s common.Hash, _ *big.Int) ([]byte, error) {
	if v, ok := f.storage[a][s]; ok {
		return v, nil
	}
	return make([]byte, 32), nil
}
func (f *fakeReader) CallContract(_ context.Context, tx *models.Transaction, _ *big.Int) ([]byte, error) {
	if out, ok := f.calls[tx.To.Hex()+"|"+hex.EncodeToString(tx.Data)]; ok {
		return out, nil
	}
	return nil, errRevert
}
func (f *fakeReader) EstimateGas(context.Context, *models.Transaction) (uint64, error) { return 0, nil }
func (f *fakeReader) ResolveBlock(context.Context, models.BlockRef) (models.BlockInfo, error) {
	return models.BlockInfo{}, nil
}

type fakeRegistry struct{ r interfaces.ChainReader }

func (f fakeRegistry) Reader(uint64) (interfaces.ChainReader, error) { return f.r, nil }
func (f fakeRegistry) RPCURL(uint64) (string, error)                 { return "", nil }
func (f fakeRegistry) Chains() []uint64                              { return []uint64{1} }

func word(v int64) []byte { return common.LeftPadBytes(big.NewInt(v).Bytes(), 32) }

func ifaceKey(a common.Address, id string) string {
	return a.Hex() + "|01ffc9a7" + id + "00000000000000000000000000000000000000000000000000000000"
}

var (
	eoaAddr   = common.HexToAddress("0x1000000000000000000000000000000000000001")
	tokenAddr = common.HexToAddress("0x2000000000000000000000000000000000000002")
	nftAddr   = common.HexToAddress("0x3000000000000000000000000000000000000003")
	proxyAddr = common.HexToAddress("0x4000000000000000000000000000000000000004")
	implAddr  = common.HexToAddress("0x5000000000000000000000000000000000000005")
	cloneAddr = common.HexToAddress("0x6000000000000000000000000000000000000006")
	delegated = common.HexToAddress("0x7000000000000000000000000000000000000007")
	beaconPxy = common.HexToAddress("0x8000000000000000000000000000000000000008")
	beacon    = common.HexToAddress("0x9000000000000000000000000000000000000009")
)

func world() *fakeReader {
	clone := append(append(append([]byte{}, minimalProxyPrefix...), implAddr.Bytes()...), minimalProxySuffix...)
	return &fakeReader{
		code: map[common.Address][]byte{
			tokenAddr: {0x60, 0x80}, nftAddr: {0x60, 0x80}, proxyAddr: {0x60, 0x80}, cloneAddr: clone,
			delegated: append(append([]byte{}, eip7702Prefix...), implAddr.Bytes()...), beaconPxy: {0x60}, beacon: {0x60},
		},
		storage: map[common.Address]map[common.Hash][]byte{
			proxyAddr: {slotEIP1967Impl: common.LeftPadBytes(implAddr.Bytes(), 32)},
			beaconPxy: {slotEIP1967Beacon: common.LeftPadBytes(beacon.Bytes(), 32)},
		},
		calls: map[string][]byte{
			tokenAddr.Hex() + "|18160ddd":                                        word(1000),
			tokenAddr.Hex() + "|70a08231" + hex.EncodeToString(make([]byte, 32)): word(0),
			tokenAddr.Hex() + "|313ce567":                                        word(6),
			ifaceKey(nftAddr, "01ffc9a7"):                                        word(1),
			ifaceKey(nftAddr, "ffffffff"):                                        word(0),
			ifaceKey(nftAddr, "80ac58cd"):                                        word(1),
			ifaceKey(nftAddr, "d9b67a26"):                                        word(0),
			beacon.Hex() + "|5c60da1b":                                           common.LeftPadBytes(implAddr.Bytes(), 32),
		},
	}
}

func TestInspectFacts(t *testing.T) {
	r := world()
	ctx := context.Background()
	get := func(a common.Address) *models.ContractInfo {
		info, err := inspect(ctx, r, 1, a, nil)
		if err != nil {
			t.Fatal(err)
		}
		return info
	}
	if i := get(eoaAddr); i.IsContract || i.CodeSize != 0 || i.CodeHash != "" {
		t.Fatalf("eoa %+v", i)
	}
	if i := get(tokenAddr); !i.IsContract || len(i.Standards) != 1 || i.Standards[0] != "erc20" || i.IsProxy {
		t.Fatalf("token %+v", i)
	}
	if i := get(nftAddr); len(i.Standards) != 1 || i.Standards[0] != "erc721" {
		t.Fatalf("nft %+v", i)
	}
	if i := get(proxyAddr); !i.IsProxy || i.Implementation != implAddr.Hex() {
		t.Fatalf("1967 proxy %+v", i)
	}
	if i := get(cloneAddr); !i.IsProxy || i.Implementation != implAddr.Hex() {
		t.Fatalf("1167 clone %+v", i)
	}
	if i := get(beaconPxy); !i.IsProxy || i.Implementation != implAddr.Hex() {
		t.Fatalf("beacon proxy %+v", i)
	}
	if i := get(delegated); i.IsContract || i.Standards[0] != "eip7702-delegated" || i.Implementation != implAddr.Hex() {
		t.Fatalf("7702 %+v", i)
	}
}

func TestERC165MustRejectFFFFFFFF(t *testing.T) {
	r := world()
	r.calls[ifaceKey(nftAddr, "ffffffff")] = word(1) // claims to support everything
	info, err := inspect(context.Background(), r, 1, nftAddr, nil)
	if err != nil || len(info.Standards) != 0 {
		t.Fatalf("non-compliant ERC-165 must not be trusted: %+v %v", info, err)
	}
}

func TestInspectorCachingAndErrors(t *testing.T) {
	r := world()
	in := NewInspector(fakeRegistry{r}, 10)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		info, err := in.Inspect(ctx, 1, tokenAddr, 100)
		if err != nil || info.AtBlock != 100 {
			t.Fatal(info, err)
		}
		info.Standards = nil // callers must not corrupt the cache
	}
	if r.n.Load() != 1 {
		t.Fatalf("pinned-block result should be cached; code fetched %d times", r.n.Load())
	}
	if info, _ := in.Inspect(ctx, 1, tokenAddr, 100); len(info.Standards) != 1 {
		t.Fatal("cache entry was mutated by a caller")
	}
	_, _ = in.Inspect(ctx, 1, tokenAddr, 0)
	_, _ = in.Inspect(ctx, 1, tokenAddr, 0)
	if r.n.Load() != 3 {
		t.Fatal("latest-block results must not be cached")
	}

	r.infraErr = txerrors.New(txerrors.KindUnavailable, "x", "down")
	if _, err := in.Inspect(ctx, 1, eoaAddr, 5); txerrors.KindOf(err) != txerrors.KindUnavailable {
		t.Fatalf("infra error must propagate: %v", err)
	}
}

func TestLRUEviction(t *testing.T) {
	c := newLRU(2)
	c.put("a", &models.ContractInfo{Address: "a"})
	c.put("b", &models.ContractInfo{Address: "b"})
	c.get("a")
	c.put("c", &models.ContractInfo{Address: "c"})
	if _, ok := c.get("b"); ok {
		t.Fatal("least recently used entry should be evicted")
	}
	if _, ok := c.get("a"); !ok {
		t.Fatal("recently used entry evicted")
	}
}

func TestIsExecutionError(t *testing.T) {
	if !IsExecutionError(errRevert) || IsExecutionError(errors.New("x")) || IsExecutionError(txerrors.Wrap(errRevert, txerrors.KindUnavailable, "c", "m")) {
		t.Fatal("classification")
	}
}
