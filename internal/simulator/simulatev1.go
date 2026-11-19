package simulator

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/pri-3x/txshield/internal/evm"
	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
	"github.com/pri-3x/txshield/pkg/txerrors"
)

// RPCSimulate simulates with the upstream node's eth_simulateV1 (execution
// APIs spec, Geth 1.14.9+ and most hosted providers). One round trip returns
// status, logs, and (with traceTransfers) native value transfers, which is
// fast enough to run before a wallet opens. Public endpoints commonly offer
// eth_simulateV1 but not debug_traceCall.
//
// It has no call trace, so trace-based rules are skipped and results are at
// most "partial". When the endpoint does not support eth_simulateV1 it falls
// back to the rpc-trace backend.
type RPCSimulate struct {
	reg      *evm.Registry
	timeout  time.Duration
	fallback *RPCTrace
}

var _ interfaces.Simulator = (*RPCSimulate)(nil)

// NewRPCSimulate creates the eth_simulateV1 backend.
func NewRPCSimulate(reg *evm.Registry, timeout time.Duration) *RPCSimulate {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &RPCSimulate{reg: reg, timeout: timeout, fallback: NewRPCTrace(reg, timeout)}
}

// Name implements interfaces.Simulator.
func (s *RPCSimulate) Name() string { return "rpc-simulate" }

// Capabilities implements interfaces.Simulator.
func (s *RPCSimulate) Capabilities() models.SimulatorCapabilities {
	return models.SimulatorCapabilities{BalanceDiff: true}
}

// Pseudo-log emitters for native transfers under traceTransfers. Geth uses
// 0xff..fe; the execution-apis spec and some clients use the ERC-7528
// native-asset address.
var nativeTransferEmitters = map[common.Address]bool{
	common.HexToAddress("0xfffffffffffffffffffffffffffffffffffffffe"): true,
	common.HexToAddress("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"): true,
}

type simCallError struct {
	Code    int           `json:"code"`
	Message string        `json:"message"`
	Data    hexutil.Bytes `json:"data"`
}

type simCallResult struct {
	ReturnData hexutil.Bytes  `json:"returnData"`
	Logs       []RawLog       `json:"logs"`
	GasUsed    hexutil.Uint64 `json:"gasUsed"`
	Status     hexutil.Uint64 `json:"status"`
	Error      *simCallError  `json:"error"`
}

type simBlockResult struct {
	Calls []simCallResult `json:"calls"`
}

type simPayload struct {
	BlockStateCalls []simBlock `json:"blockStateCalls"`
	TraceTransfers  bool       `json:"traceTransfers"`
	Validation      bool       `json:"validation"`
}

type simBlock struct {
	Calls []evm.CallArgs `json:"calls"`
}

// maxRevertText bounds node-supplied error text copied into results.
const maxRevertText = 300

// Simulate implements interfaces.Simulator.
func (s *RPCSimulate) Simulate(ctx context.Context, req interfaces.SimulationRequest) (*models.SimulationResult, error) {
	if req.Tx == nil {
		return nil, txerrors.New(txerrors.KindInvalidInput, "missing_transaction", "transaction is required")
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	start := time.Now()
	tx := req.Tx
	c, err := s.reg.Client(ctx, tx.ChainID)
	if err != nil {
		return nil, err
	}
	// When the caller already resolved the block (the analyzer does), its
	// header (hash, base fee) is fetched alongside the simulation instead of
	// before it: one round trip less on the critical path.
	var block models.BlockInfo
	var blockErr error
	var wg sync.WaitGroup
	if req.BlockNumber > 0 {
		n := req.BlockNumber
		block.Number = n
		wg.Add(1)
		go func() {
			defer wg.Done()
			block, blockErr = c.ResolveBlock(ctx, models.BlockRef{Number: &n})
		}()
	} else {
		block, err = c.ResolveBlock(ctx, models.BlockRef{Tag: models.BlockLatest})
		if err != nil {
			return nil, err
		}
	}
	blockArg := hexutil.EncodeUint64(block.Number)
	blockBig := new(big.Int).SetUint64(block.Number)

	// The sender's native balance is read in parallel with the simulation;
	// the post balance follows from the simulated native transfers (fees are
	// not charged with validation off).
	var nativeBefore *big.Int
	var nativeErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		nativeBefore, nativeErr = c.BalanceAt(ctx, tx.From, blockBig)
	}()

	call := evm.ArgsFor(tx)
	var blocks []simBlockResult
	err = c.Call(ctx, &blocks, "eth_simulateV1", simPayload{
		BlockStateCalls: []simBlock{{Calls: []evm.CallArgs{call}}}, TraceTransfers: true,
	}, blockArg)
	wg.Wait()
	if blockErr != nil {
		return nil, blockErr
	}

	res := &models.SimulationResult{
		Backend: "rpc-simulate", Status: models.SimSuccess, Completeness: models.CompletenessPartial,
		ChainID: tx.ChainID, BlockNumber: block.Number, BlockHash: block.Hash,
		IncompleteReasons: []string{"no call trace (eth_simulateV1): trace-based checks did not run"},
		Notes: []string{
			"Executed with eth_simulateV1 on top of block " + strconv.FormatUint(block.Number, 10) + "; nothing was mined or broadcast.",
			"Fees are not charged in simulation, so balance changes show value movements only.",
		},
	}
	res.Notes = append(res.Notes, feeNotes(tx, block)...)

	if err != nil {
		var rpcErr *evm.RPCError
		if !errors.As(err, &rpcErr) {
			return nil, err // transport, timeout, circuit open: infrastructure
		}
		if isPreExecutionError(rpcErr.Code) {
			// The node refused the transaction before execution (for example
			// insufficient funds): a property of the transaction.
			res.Status = models.SimReverted
			res.RevertReason = clipText(rpcErr.Message)
			res.DurationMs = time.Since(start).Milliseconds()
			return res, nil
		}
		// Method missing or not allowed by this provider.
		fb, ferr := s.fallback.Simulate(ctx, req)
		if fb != nil {
			fb.IncompleteReasons = append(fb.IncompleteReasons, "provider does not support eth_simulateV1")
		}
		return fb, ferr
	}
	if len(blocks) != 1 || len(blocks[0].Calls) != 1 {
		return nil, txerrors.New(txerrors.KindUnavailable, "bad_simulation_response", "the RPC endpoint returned an unexpected eth_simulateV1 response")
	}
	r := blocks[0].Calls[0]
	res.GasUsed = uint64(r.GasUsed)
	gas := uint64(r.GasUsed)
	res.GasEstimate = &gas
	if len(r.ReturnData) > 0 {
		res.ReturnData = hexutil.Encode(r.ReturnData)
	}
	if r.Status == 0 || r.Error != nil {
		res.Status = models.SimReverted
		if r.Error != nil {
			res.RevertReason = DecodeRevert(r.Error.Data)
			if res.RevertReason == "" {
				res.RevertReason = clipText(r.Error.Message)
			}
		}
		if res.RevertReason == "" {
			res.RevertReason = DecodeRevert(r.ReturnData)
		}
		res.DurationMs = time.Since(start).Milliseconds()
		return res, nil
	}

	native, logs := splitNativeTransfers(r.Logs)
	ev := ParseLogs(logs)
	if ev.Truncated {
		res.IncompleteReasons = append(res.IncompleteReasons, fmt.Sprintf("logs truncated at %d", MaxLogs))
	}
	res.Logs, res.ApprovalChanges = ev.Logs, ev.Approvals
	res.AssetTransfers = append(native, ev.Transfers...)

	if nativeErr != nil {
		res.IncompleteReasons = append(res.IncompleteReasons, "native balance before execution unavailable")
	} else if bc := nativeChange(tx.From, nativeBefore, res.AssetTransfers); bc != nil {
		res.BalanceChanges = append(res.BalanceChanges, *bc)
	}
	tokenChanges, reasons := s.tokenBalanceChanges(ctx, c, call, blockArg, tx.From, res.AssetTransfers)
	res.BalanceChanges = append(res.BalanceChanges, tokenChanges...)
	res.IncompleteReasons = append(res.IncompleteReasons, reasons...)
	res.DurationMs = time.Since(start).Milliseconds()
	return res, nil
}

// isPreExecutionError reports eth_simulateV1's -38xxx codes (invalid nonce,
// insufficient funds, fee too low...), which reject the transaction itself.
func isPreExecutionError(code int) bool { return code <= -38000 && code > -39000 }

func clipText(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxRevertText {
		return s[:maxRevertText] + "…"
	}
	return s
}

// splitNativeTransfers separates traceTransfers pseudo-logs (native value
// moves) from contract logs.
func splitNativeTransfers(logs []RawLog) ([]models.AssetTransfer, []RawLog) {
	var native []models.AssetTransfer
	rest := make([]RawLog, 0, len(logs))
	for _, l := range logs {
		if nativeTransferEmitters[l.Address] {
			if len(l.Topics) == 3 && l.Topics[0] == topicTransfer && len(l.Data) == 32 {
				amt := new(big.Int).SetBytes(l.Data)
				if amt.Sign() > 0 {
					native = append(native, models.AssetTransfer{
						Asset: models.AssetRef{Kind: models.AssetNative},
						From:  addrTopic(l.Topics[1]), To: addrTopic(l.Topics[2]), Amount: models.QuantityFromBig(amt),
					})
				}
			}
			continue
		}
		rest = append(rest, l)
	}
	return native, rest
}

// nativeChange derives the owner's native balance change from simulated
// native transfers.
func nativeChange(owner common.Address, before *big.Int, transfers []models.AssetTransfer) *models.BalanceChange {
	delta := new(big.Int)
	o := owner.Hex()
	for _, t := range transfers {
		if t.Asset.Kind != models.AssetNative {
			continue
		}
		amt, ok := new(big.Int).SetString(string(t.Amount), 10)
		if !ok {
			continue
		}
		if t.From == o {
			delta.Sub(delta, amt)
		}
		if t.To == o {
			delta.Add(delta, amt)
		}
	}
	if delta.Sign() == 0 {
		return nil
	}
	bc := change(owner, models.AssetRef{Kind: models.AssetNative}, before, new(big.Int).Add(before, delta))
	return &bc
}

// tokenBalanceChanges reads the owner's balance of every token it sent or
// received, before and after the transaction, in one extra eth_simulateV1
// round trip: [balanceOf..., tx, balanceOf...] in the same simulated block.
func (s *RPCSimulate) tokenBalanceChanges(ctx context.Context, c *evm.Client, call evm.CallArgs, blockArg string, owner common.Address, transfers []models.AssetTransfer) ([]models.BalanceChange, []string) {
	type item struct {
		ref  models.AssetRef
		data []byte
	}
	seen := map[string]bool{}
	var items []item
	o := owner.Hex()
	for _, t := range transfers {
		if t.Asset.Kind == models.AssetNative || (t.From != o && t.To != o) {
			continue
		}
		k := string(t.Asset.Kind) + t.Asset.Address
		if t.Asset.Kind == models.AssetERC1155 {
			k += "/" + string(t.Asset.TokenID)
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		ref := t.Asset
		data := append(append([]byte{}, selBalanceOf...), common.LeftPadBytes(owner.Bytes(), 32)...)
		switch ref.Kind {
		case models.AssetERC721:
			ref.TokenID = "" // balanceOf counts tokens in the collection
		case models.AssetERC1155:
			id, _ := new(big.Int).SetString(string(ref.TokenID), 10)
			if id == nil {
				id = new(big.Int)
			}
			data = append(append(append([]byte{}, selBalanceOf1155...), common.LeftPadBytes(owner.Bytes(), 32)...), common.LeftPadBytes(id.Bytes(), 32)...)
		}
		items = append(items, item{ref, data})
	}
	if len(items) == 0 {
		return nil, nil
	}
	var reasons []string
	const maxTokens = 50
	if len(items) > maxTokens {
		reasons = append(reasons, fmt.Sprintf("balance diffs computed for the first %d of %d tokens", maxTokens, len(items)))
		items = items[:maxTokens]
	}
	gas := hexutil.Uint64(200_000)
	query := func(it item) evm.CallArgs {
		to := common.HexToAddress(it.ref.Address)
		return evm.CallArgs{To: &to, Data: it.data, Gas: &gas}
	}
	calls := make([]evm.CallArgs, 0, 2*len(items)+1)
	for _, it := range items {
		calls = append(calls, query(it))
	}
	calls = append(calls, call)
	for _, it := range items {
		calls = append(calls, query(it))
	}
	var blocks []simBlockResult
	if err := c.Call(ctx, &blocks, "eth_simulateV1", simPayload{BlockStateCalls: []simBlock{{Calls: calls}}}, blockArg); err != nil {
		return nil, append(reasons, "token balance diffs unavailable")
	}
	if len(blocks) != 1 || len(blocks[0].Calls) != len(calls) {
		return nil, append(reasons, "token balance diffs unavailable")
	}
	rs := blocks[0].Calls
	if rs[len(items)].Status == 0 {
		// The replayed transaction behaved differently (state changed between
		// round trips); do not report diffs from an inconsistent run.
		return nil, append(reasons, "token balance diffs unavailable (state changed during simulation)")
	}
	var out []models.BalanceChange
	for i, it := range items {
		b, a := rs[i], rs[len(items)+1+i]
		if b.Status == 0 || a.Status == 0 || len(b.ReturnData) < 32 || len(a.ReturnData) < 32 {
			reasons = append(reasons, "balance of "+it.ref.Address+" unavailable")
			continue
		}
		before := new(big.Int).SetBytes(b.ReturnData[:32])
		after := new(big.Int).SetBytes(a.ReturnData[:32])
		if before.Cmp(after) != 0 {
			out = append(out, change(owner, it.ref, before, after))
		}
	}
	return out, reasons
}
