package decoder

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/txshield/txshield/pkg/interfaces"
	"github.com/txshield/txshield/pkg/models"
)

// mustNotFail asserts the decoder's core contract: arbitrary calldata never
// produces an error or panic, and the result is always JSON-serializable.
func mustNotFail(t *testing.T, data []byte) {
	dec := New(Builtin(), DefaultLimits)
	c, err := dec.Decode(context.Background(), &models.Transaction{To: ptr(router), Value: new(big.Int), Data: data}, interfaces.DecodeOptions{})
	if err != nil {
		t.Fatalf("Decode error on %x: %v", data, err)
	}
	if _, err := json.Marshal(c); err != nil {
		t.Fatalf("JSON error on %x: %v", data, err)
	}
}

func seedCorpus(f *testing.F) {
	type call struct {
		Target   common.Address
		CallData []byte
	}
	f.Add(calldata(f, "transfer(address,uint256)", bob, big.NewInt(1)))
	f.Add(calldata(f, "approve(address,uint256)", bob, maxU))
	f.Add(calldata(f, "multicall(bytes[])", [][]byte{calldata(f, "transfer(address,uint256)", bob, big.NewInt(1))}))
	f.Add(calldata(f, "aggregate((address target, bytes callData)[] calls)", []call{{token, []byte{1, 2, 3, 4}}}))
	f.Add(calldata(f, "execute(bytes commands, bytes[] inputs)", []byte{0x0b, 0x00}, [][]byte{encodeArgs(f, "f(address,uint256)", alice, big.NewInt(1)), {}}))
	f.Add([]byte{})
	f.Add([]byte{0xff})
}

func FuzzDecode(f *testing.F) {
	seedCorpus(f)
	f.Fuzz(func(t *testing.T, data []byte) { mustNotFail(t, data) })
}

// FuzzDecodeKnownSelector forces a registered selector so the fuzzer spends
// its time inside argument decoding rather than on unknown selectors.
func FuzzDecodeKnownSelector(f *testing.F) {
	entries := Builtin().Entries()
	f.Add(uint16(0), []byte{})
	f.Add(uint16(3), make([]byte, 64))
	f.Fuzz(func(t *testing.T, idx uint16, args []byte) {
		e := entries[int(idx)%len(entries)]
		mustNotFail(t, append(append([]byte{}, e.Method.ID...), args...))
	})
}

func BenchmarkDecodeERC20Transfer(b *testing.B) {
	dec := New(Builtin(), DefaultLimits)
	tx := &models.Transaction{To: ptr(token), Value: new(big.Int), Data: calldata(b, "transfer(address,uint256)", bob, big.NewInt(1234))}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := dec.Decode(context.Background(), tx, interfaces.DecodeOptions{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeUniversalRouter(b *testing.B) {
	path := v3Path([]common.Address{token, weth}, []uint32{3000})
	swap := encodeArgs(b, "f(address recipient, uint256 amountIn, uint256 amountOutMin, bytes path, bool payerIsUser)", alice, big.NewInt(1000), big.NewInt(1), path, true)
	unwrap := encodeArgs(b, "f(address recipient, uint256 amountMin)", alice, big.NewInt(1))
	data := calldata(b, "execute(bytes commands, bytes[] inputs, uint256 deadline)", []byte{0x00, 0x0c}, [][]byte{swap, unwrap}, big.NewInt(1))
	dec := New(Builtin(), DefaultLimits)
	tx := &models.Transaction{To: ptr(router), Value: new(big.Int), Data: data}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := dec.Decode(context.Background(), tx, interfaces.DecodeOptions{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeMulticall3With50Calls(b *testing.B) {
	type call struct {
		Target       common.Address
		AllowFailure bool
		CallData     []byte
	}
	calls := make([]call, 50)
	for i := range calls {
		calls[i] = call{token, true, calldata(b, "approve(address,uint256)", bob, maxU)}
	}
	data := calldata(b, "aggregate3((address target, bool allowFailure, bytes callData)[] calls)", calls)
	dec := New(Builtin(), DefaultLimits)
	tx := &models.Transaction{To: ptr(router), Value: new(big.Int), Data: data}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := dec.Decode(context.Background(), tx, interfaces.DecodeOptions{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeUnknownSelector(b *testing.B) {
	dec := New(Builtin(), DefaultLimits)
	tx := &models.Transaction{To: ptr(token), Value: new(big.Int), Data: append([]byte{0xde, 0xad, 0xbe, 0xef}, make([]byte, 256)...)}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := dec.Decode(context.Background(), tx, interfaces.DecodeOptions{}); err != nil {
			b.Fatal(err)
		}
	}
}
