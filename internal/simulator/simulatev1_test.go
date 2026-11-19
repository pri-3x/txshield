package simulator

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/pri-3x/txshield/internal/evm"
	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
)

type simNode struct {
	mu      sync.Mutex
	methods []string
	params  map[string][]json.RawMessage
	handle  func(method string, params []json.RawMessage, n int) (any, *evm.RPCError)
	status  int
}

func (f *simNode) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.status != 0 {
		w.WriteHeader(f.status)
		return
	}
	var req struct {
		ID     uint64            `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	f.mu.Lock()
	f.methods = append(f.methods, req.Method)
	n := 0
	for _, m := range f.methods {
		if m == req.Method {
			n++
		}
	}
	if f.params == nil {
		f.params = map[string][]json.RawMessage{}
	}
	if _, ok := f.params[req.Method]; !ok {
		f.params[req.Method] = req.Params
	}
	f.mu.Unlock()
	resp := map[string]any{"jsonrpc": "2.0", "id": req.ID}
	result, rpcErr := f.handle(req.Method, req.Params, n)
	if rpcErr != nil {
		resp["error"] = rpcErr
	} else {
		resp["result"] = result
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (f *simNode) called(m string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := 0
	for _, x := range f.methods {
		if x == m {
			c++
		}
	}
	return c
}

const sepolia = 11155111

var (
	sender   = common.HexToAddress("0x1111111111111111111111111111111111111111")
	attacker = common.HexToAddress("0x2222222222222222222222222222222222222222")
	token    = common.HexToAddress("0x3333333333333333333333333333333333333333")
	drainer  = common.HexToAddress("0x4444444444444444444444444444444444444444")
)

func word(b []byte) string { return "0x" + common.Bytes2Hex(common.LeftPadBytes(b, 32)) }

func addrWord(a common.Address) string { return word(a.Bytes()) }

func amountWord(n int64) string { return word(big.NewInt(n).Bytes()) }

// baseHandler answers the reads every simulation makes.
func baseHandler(method string) (any, *evm.RPCError, bool) {
	switch method {
	case "eth_chainId":
		return "0xaa36a7", nil, true
	case "eth_getBlockByNumber":
		return map[string]any{"number": "0x100", "hash": "0x" + strings.Repeat("ab", 32), "timestamp": "0x64", "baseFeePerGas": "0x1", "gasLimit": "0x1c9c380"}, nil, true
	case "eth_getBalance":
		return "0xde0b6b3a7640000", nil, true // 1 ETH
	}
	return nil, nil, false
}

func newSim(t *testing.T, node *simNode) *RPCSimulate {
	t.Helper()
	srv := httptest.NewServer(node)
	t.Cleanup(srv.Close)
	reg := evm.NewRegistry(map[uint64]string{sepolia: srv.URL}, evm.Options{
		Retry: evm.RetryPolicy{MaxAttempts: 1, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond}, BreakerThreshold: 100,
	})
	return NewRPCSimulate(reg, 5*time.Second)
}

func drainTx() *models.Transaction {
	return &models.Transaction{ChainID: sepolia, From: sender, To: &drainer, Value: big.NewInt(1e18), Data: common.FromHex("0x4e71d92d")}
}

func TestRPCSimulateDrainer(t *testing.T) {
	topicXfer := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	node := &simNode{}
	node.handle = func(m string, p []json.RawMessage, n int) (any, *evm.RPCError) {
		if r, e, ok := baseHandler(m); ok {
			return r, e
		}
		if m != "eth_simulateV1" {
			return nil, &evm.RPCError{Code: -32601, Message: "method not found"}
		}
		if n == 1 {
			return []any{map[string]any{"calls": []any{map[string]any{
				"status": "0x1", "gasUsed": "0x1d4c0", "returnData": "0x",
				"logs": []any{
					// native 1 ETH sender -> drainer (geth pseudo-log)
					map[string]any{"address": "0xfffffffffffffffffffffffffffffffffffffffe", "topics": []string{topicXfer, addrWord(sender), addrWord(drainer)}, "data": amountWord(1e18)},
					// all 500 tokens sender -> attacker
					map[string]any{"address": token.Hex(), "topics": []string{topicXfer, addrWord(sender), addrWord(attacker)}, "data": amountWord(500)},
				},
			}}}}, nil
		}
		// Balance round trip: [balanceOf, tx, balanceOf].
		return []any{map[string]any{"calls": []any{
			map[string]any{"status": "0x1", "returnData": amountWord(500), "logs": []any{}, "gasUsed": "0x1"},
			map[string]any{"status": "0x1", "returnData": "0x", "logs": []any{}, "gasUsed": "0x1"},
			map[string]any{"status": "0x1", "returnData": amountWord(0), "logs": []any{}, "gasUsed": "0x1"},
		}}}, nil
	}
	sim := newSim(t, node)
	res, err := sim.Simulate(context.Background(), interfaces.SimulationRequest{Tx: drainTx()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Backend != "rpc-simulate" || res.Status != models.SimSuccess || res.Completeness != models.CompletenessPartial {
		t.Fatalf("result header: %+v", res)
	}
	if len(res.AssetTransfers) != 2 {
		t.Fatalf("transfers: %+v", res.AssetTransfers)
	}
	if nt := res.AssetTransfers[0]; nt.Asset.Kind != models.AssetNative || nt.From != sender.Hex() || nt.Amount != "1000000000000000000" {
		t.Fatalf("native transfer: %+v", nt)
	}
	if tt := res.AssetTransfers[1]; tt.Asset.Kind != models.AssetERC20 || tt.Asset.Address != token.Hex() || tt.Amount != "500" {
		t.Fatalf("token transfer: %+v", tt)
	}
	// The native pseudo-log is not reported as a contract log.
	if len(res.Logs) != 1 || res.Logs[0].Address != token.Hex() {
		t.Fatalf("logs: %+v", res.Logs)
	}
	var native, tok *models.BalanceChange
	for i := range res.BalanceChanges {
		switch res.BalanceChanges[i].Asset.Kind {
		case models.AssetNative:
			native = &res.BalanceChanges[i]
		case models.AssetERC20:
			tok = &res.BalanceChanges[i]
		}
	}
	if native == nil || native.Before != "1000000000000000000" || native.After != "0" {
		t.Fatalf("native change: %+v", native)
	}
	if tok == nil || tok.Before != "500" || tok.After != "0" || tok.Delta != "-500" {
		t.Fatalf("token change: %+v", tok)
	}
	if res.GasUsed != 0x1d4c0 {
		t.Fatalf("gas used %d", res.GasUsed)
	}
	// Request shape: traceTransfers on, validation off, pinned block.
	var payload struct {
		BlockStateCalls []struct {
			Calls []map[string]any `json:"calls"`
		} `json:"blockStateCalls"`
		TraceTransfers bool  `json:"traceTransfers"`
		Validation     *bool `json:"validation"`
	}
	ps := node.params["eth_simulateV1"]
	if err := json.Unmarshal(ps[0], &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.TraceTransfers || payload.Validation == nil || *payload.Validation {
		t.Fatalf("payload flags: %+v", payload)
	}
	if string(ps[1]) != `"0x100"` {
		t.Fatalf("block arg %s", ps[1])
	}
	if node.called("eth_simulateV1") != 2 {
		t.Fatalf("expected 2 eth_simulateV1 calls, got %d", node.called("eth_simulateV1"))
	}
}

func TestRPCSimulateRevert(t *testing.T) {
	// Error(string) "nope"
	revertData := "0x08c379a0" + strings.Repeat("0", 62) + "20" + strings.Repeat("0", 63) + "4" + "6e6f7065" + strings.Repeat("0", 56)
	node := &simNode{}
	node.handle = func(m string, _ []json.RawMessage, _ int) (any, *evm.RPCError) {
		if r, e, ok := baseHandler(m); ok {
			return r, e
		}
		return []any{map[string]any{"calls": []any{map[string]any{
			"status": "0x0", "gasUsed": "0x5208", "returnData": revertData, "logs": []any{},
			"error": map[string]any{"code": 3, "message": "execution reverted: nope", "data": revertData},
		}}}}, nil
	}
	res, err := newSim(t, node).Simulate(context.Background(), interfaces.SimulationRequest{Tx: drainTx()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != models.SimReverted || !strings.Contains(res.RevertReason, "nope") {
		t.Fatalf("revert: %+v", res)
	}
	if len(res.AssetTransfers) != 0 || len(res.BalanceChanges) != 0 {
		t.Fatalf("reverted tx must not report movements: %+v", res)
	}
}

func TestRPCSimulatePreExecutionRejection(t *testing.T) {
	node := &simNode{}
	node.handle = func(m string, _ []json.RawMessage, _ int) (any, *evm.RPCError) {
		if r, e, ok := baseHandler(m); ok {
			return r, e
		}
		return nil, &evm.RPCError{Code: -38014, Message: "err: insufficient funds for gas * price + value"}
	}
	res, err := newSim(t, node).Simulate(context.Background(), interfaces.SimulationRequest{Tx: drainTx()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != models.SimReverted || !strings.Contains(res.RevertReason, "insufficient funds") {
		t.Fatalf("pre-execution rejection must be a revert: %+v", res)
	}
}

func TestRPCSimulateFallsBackWithoutMethod(t *testing.T) {
	node := &simNode{}
	node.handle = func(m string, _ []json.RawMessage, _ int) (any, *evm.RPCError) {
		if r, e, ok := baseHandler(m); ok {
			return r, e
		}
		switch m {
		case "eth_estimateGas":
			return "0x5208", nil
		case "eth_call":
			return "0x", nil
		}
		return nil, &evm.RPCError{Code: -32601, Message: "the method " + m + " does not exist/is not available"}
	}
	res, err := newSim(t, node).Simulate(context.Background(), interfaces.SimulationRequest{Tx: drainTx()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Backend != "rpc-trace" || res.Status != models.SimSuccess {
		t.Fatalf("fallback result: %+v", res)
	}
	if !strings.Contains(strings.Join(res.IncompleteReasons, "|"), "does not support eth_simulateV1") {
		t.Fatalf("missing reason: %v", res.IncompleteReasons)
	}
	if node.called("debug_traceCall") != 1 {
		t.Fatal("fallback did not try debug_traceCall")
	}
}

func TestRPCSimulateInfrastructureFailureIsError(t *testing.T) {
	node := &simNode{status: http.StatusBadGateway}
	if _, err := newSim(t, node).Simulate(context.Background(), interfaces.SimulationRequest{Tx: drainTx()}); err == nil {
		t.Fatal("an unreachable upstream must be an error, not a result")
	}
}
