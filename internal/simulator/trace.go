package simulator

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/pri-3x/txshield/pkg/models"
)

// Trace limits keep results bounded on pathological transactions.
const (
	MaxTraceFrames  = 5000
	maxFrameIOBytes = 4096 // input/output kept per frame (selectors and small args)
)

// RawFrame is the callTracer output format (geth and anvil).
type RawFrame struct {
	Type         string          `json:"type"`
	From         common.Address  `json:"from"`
	To           *common.Address `json:"to"`
	Value        *hexutil.Big    `json:"value"`
	Gas          hexutil.Uint64  `json:"gas"`
	GasUsed      hexutil.Uint64  `json:"gasUsed"`
	Input        hexutil.Bytes   `json:"input"`
	Output       hexutil.Bytes   `json:"output"`
	Error        string          `json:"error"`
	RevertReason string          `json:"revertReason"`
	Calls        []RawFrame      `json:"calls"`
	Logs         []RawLog        `json:"logs"`
}

// ConvertedTrace is a trace turned into models plus what was derived from it.
type ConvertedTrace struct {
	Root            *models.CallFrame
	NativeTransfers []models.AssetTransfer
	Logs            []RawLog // logs from successful frames only (callTracer withLog)
	Truncated       bool
}

// ConvertTrace converts a raw trace. Native value moves and logs inside
// frames that failed (or whose ancestor failed) are discarded: their state
// changes were rolled back.
func ConvertTrace(root RawFrame) ConvertedTrace {
	var ct ConvertedTrace
	frames := 0
	var conv func(f RawFrame, reverted bool) models.CallFrame
	conv = func(f RawFrame, reverted bool) models.CallFrame {
		frames++
		failed := reverted || f.Error != ""
		out := models.CallFrame{
			Type: f.Type, From: f.From.Hex(), Gas: uint64(f.Gas), GasUsed: uint64(f.GasUsed),
			Input: hexutil.Encode(clip(f.Input)), Output: hexutil.Encode(clip(f.Output)),
			Error: f.Error, RevertReason: f.RevertReason,
		}
		if f.To != nil {
			out.To = f.To.Hex()
		}
		if f.Value != nil && (*big.Int)(f.Value).Sign() > 0 {
			out.Value = models.QuantityFromBig((*big.Int)(f.Value))
			if !failed && f.To != nil && f.Type != "DELEGATECALL" && f.Type != "STATICCALL" {
				ct.NativeTransfers = append(ct.NativeTransfers, models.AssetTransfer{
					Asset: models.AssetRef{Kind: models.AssetNative}, From: f.From.Hex(), To: f.To.Hex(), Amount: out.Value,
				})
			}
		}
		if !failed {
			ct.Logs = append(ct.Logs, f.Logs...)
		}
		for _, c := range f.Calls {
			if frames >= MaxTraceFrames {
				ct.Truncated = true
				break
			}
			out.Calls = append(out.Calls, conv(c, failed))
		}
		return out
	}
	r := conv(root, false)
	ct.Root = &r
	return ct
}

func clip(b []byte) []byte {
	if len(b) > maxFrameIOBytes {
		return b[:maxFrameIOBytes]
	}
	return b
}
