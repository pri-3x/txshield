package simulator

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/pri-3x/txshield/internal/evm"
	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
	"github.com/pri-3x/txshield/pkg/txerrors"
)

// RPCTrace simulates through the upstream node's own tracing API
// (debug_traceCall with callTracer + logs), falling back to eth_call when
// the provider does not offer debug methods.
//
// It cannot read post-execution state, so balance diffs are never available
// and results are at most "partial". Use it where running Anvil is not
// possible.
type RPCTrace struct {
	reg     *evm.Registry
	timeout time.Duration
}

var _ interfaces.Simulator = (*RPCTrace)(nil)

// NewRPCTrace creates the fallback simulator.
func NewRPCTrace(reg *evm.Registry, timeout time.Duration) *RPCTrace {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &RPCTrace{reg: reg, timeout: timeout}
}

// Name implements interfaces.Simulator.
func (s *RPCTrace) Name() string { return "rpc-trace" }

// Capabilities implements interfaces.Simulator.
func (s *RPCTrace) Capabilities() models.SimulatorCapabilities {
	return models.SimulatorCapabilities{CallTrace: true}
}

// Simulate implements interfaces.Simulator.
func (s *RPCTrace) Simulate(ctx context.Context, req interfaces.SimulationRequest) (*models.SimulationResult, error) {
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
	ref := models.BlockRef{Tag: models.BlockLatest}
	if req.BlockNumber > 0 {
		n := req.BlockNumber
		ref = models.BlockRef{Number: &n}
	}
	block, err := c.ResolveBlock(ctx, ref)
	if err != nil {
		return nil, err
	}
	blockArg := hexutil.EncodeUint64(block.Number)
	res := &models.SimulationResult{
		Backend: "rpc-trace", Status: models.SimSuccess, Completeness: models.CompletenessPartial,
		ChainID: tx.ChainID, BlockNumber: block.Number, BlockHash: block.Hash,
		IncompleteReasons: []string{"balance diffs are not available without a fork (rpc-trace mode)"},
		Notes:             []string{"Executed as a call against the state of block " + strconv.FormatUint(block.Number, 10) + "; nothing was mined or broadcast."},
	}
	res.Notes = append(res.Notes, feeNotes(tx, block)...)

	if est, err := c.EstimateGas(ctx, tx); err == nil {
		res.GasEstimate = &est
	} else if !evm.IsExecutionError(err) {
		return nil, err
	}

	args := evm.ArgsFor(tx)
	var raw RawFrame
	err = c.Call(ctx, &raw, "debug_traceCall", args, blockArg, map[string]any{"tracer": "callTracer", "tracerConfig": map[string]any{"withLog": true}})
	switch {
	case err == nil:
		trace := ConvertTrace(raw)
		res.Trace = trace.Root
		res.GasUsed = uint64(raw.GasUsed)
		if trace.Truncated {
			res.IncompleteReasons = append(res.IncompleteReasons, fmt.Sprintf("call trace truncated at %d frames", MaxTraceFrames))
		}
		if raw.Error != "" {
			res.Status = models.SimReverted
			// Decode the raw data ourselves first so wording is identical
			// across backends; fall back to the node's own rendering.
			res.RevertReason = DecodeRevert(raw.Output)
			if res.RevertReason == "" {
				res.RevertReason = raw.RevertReason
			}
			if res.RevertReason == "" {
				res.RevertReason = raw.Error
			}
			break
		}
		ev := ParseLogs(trace.Logs)
		res.Logs, res.ApprovalChanges = ev.Logs, ev.Approvals
		res.AssetTransfers = append(trace.NativeTransfers, ev.Transfers...)
	case evm.IsExecutionError(err):
		// Provider has no debug_traceCall (method not found / not allowed):
		// fall back to eth_call for success vs revert only.
		res.IncompleteReasons = append(res.IncompleteReasons, "provider does not support debug_traceCall: no call trace, logs, or asset transfers")
		if _, callErr := c.CallContract(ctx, tx, nil); callErr != nil {
			var rpcErr *evm.RPCError
			if !errors.As(callErr, &rpcErr) {
				return nil, callErr
			}
			res.Status = models.SimReverted
			res.RevertReason = DecodeRevert(revertDataFromRPCError(rpcErr.Data))
			if res.RevertReason == "" {
				res.RevertReason = rpcErr.Message
			}
		}
	default:
		return nil, err
	}
	res.DurationMs = time.Since(start).Milliseconds()
	return res, nil
}
