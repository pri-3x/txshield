// Package simulator executes transactions against forked or historical
// state without broadcasting them, and turns raw execution data (receipts,
// call traces, logs) into structured models.SimulationResult values.
package simulator

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/txshield/txshield/pkg/models"
)

// Event topics, computed from their signatures so they cannot be mistyped.
var (
	topicTransfer       = crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)"))
	topicApproval       = crypto.Keccak256Hash([]byte("Approval(address,address,uint256)"))
	topicApprovalForAll = crypto.Keccak256Hash([]byte("ApprovalForAll(address,address,bool)"))
	topicTransferSingle = crypto.Keccak256Hash([]byte("TransferSingle(address,address,address,uint256,uint256)"))
	topicTransferBatch  = crypto.Keccak256Hash([]byte("TransferBatch(address,address,address,uint256[],uint256[])"))
	topicDeposit        = crypto.Keccak256Hash([]byte("Deposit(address,uint256)"))
	topicWithdrawal     = crypto.Keccak256Hash([]byte("Withdrawal(address,uint256)"))
)

// MaxLogs bounds the logs kept in a result.
const MaxLogs = 2000

// RawLog is a log as returned by receipts and callTracer (withLog).
type RawLog struct {
	Address common.Address `json:"address"`
	Topics  []common.Hash  `json:"topics"`
	Data    hexutil.Bytes  `json:"data"`
}

// ParsedEvents are the asset movements and permission changes found in logs.
type ParsedEvents struct {
	Logs      []models.Log
	Transfers []models.AssetTransfer
	Approvals []models.ApprovalChange
	Truncated bool
}

func addrTopic(h common.Hash) string { return common.BytesToAddress(h.Bytes()).Hex() }

// ParseLogs interprets ERC-20/721/1155 and WETH events. Events are matched by
// topic and shape only: any contract can emit them, so tokens are always
// identified by the emitting address, never by name or symbol.
func ParseLogs(logs []RawLog) ParsedEvents {
	var out ParsedEvents
	for i, l := range logs {
		if i >= MaxLogs {
			out.Truncated = true
			break
		}
		idx := uint(i) //nolint:gosec // bounded by MaxLogs
		topics := make([]string, len(l.Topics))
		for j, t := range l.Topics {
			topics[j] = t.Hex()
		}
		out.Logs = append(out.Logs, models.Log{Address: l.Address.Hex(), Topics: topics, Data: hexutil.Encode(l.Data), Index: idx})
		if len(l.Topics) == 0 {
			continue
		}
		token := l.Address.Hex()
		li := idx
		switch l.Topics[0] {
		case topicTransfer:
			switch {
			case len(l.Topics) == 3 && len(l.Data) == 32: // ERC-20
				out.Transfers = append(out.Transfers, models.AssetTransfer{
					Asset: models.AssetRef{Kind: models.AssetERC20, Address: token},
					From:  addrTopic(l.Topics[1]), To: addrTopic(l.Topics[2]),
					Amount: models.QuantityFromBig(new(big.Int).SetBytes(l.Data)), LogIndex: &li,
				})
			case len(l.Topics) == 4 && len(l.Data) == 0: // ERC-721
				out.Transfers = append(out.Transfers, models.AssetTransfer{
					Asset: models.AssetRef{Kind: models.AssetERC721, Address: token, TokenID: models.QuantityFromBig(l.Topics[3].Big())},
					From:  addrTopic(l.Topics[1]), To: addrTopic(l.Topics[2]), Amount: "1", LogIndex: &li,
				})
			}
		case topicApproval:
			switch {
			case len(l.Topics) == 3 && len(l.Data) == 32:
				out.Approvals = append(out.Approvals, models.ApprovalChange{
					Asset: models.AssetRef{Kind: models.AssetERC20, Address: token},
					Owner: addrTopic(l.Topics[1]), Spender: addrTopic(l.Topics[2]),
					Amount: models.QuantityFromBig(new(big.Int).SetBytes(l.Data)),
				})
			case len(l.Topics) == 4:
				out.Approvals = append(out.Approvals, models.ApprovalChange{
					Asset: models.AssetRef{Kind: models.AssetERC721, Address: token, TokenID: models.QuantityFromBig(l.Topics[3].Big())},
					Owner: addrTopic(l.Topics[1]), Spender: addrTopic(l.Topics[2]),
				})
			}
		case topicApprovalForAll:
			if len(l.Topics) == 3 && len(l.Data) == 32 {
				approved := new(big.Int).SetBytes(l.Data).Sign() != 0
				out.Approvals = append(out.Approvals, models.ApprovalChange{
					Asset: models.AssetRef{Kind: models.AssetERC721, Address: token},
					Owner: addrTopic(l.Topics[1]), Spender: addrTopic(l.Topics[2]), Approved: &approved,
				})
			}
		case topicTransferSingle:
			if len(l.Topics) == 4 && len(l.Data) == 64 {
				out.Transfers = append(out.Transfers, models.AssetTransfer{
					Asset: models.AssetRef{Kind: models.AssetERC1155, Address: token, TokenID: models.QuantityFromBig(new(big.Int).SetBytes(l.Data[:32]))},
					From:  addrTopic(l.Topics[2]), To: addrTopic(l.Topics[3]),
					Amount: models.QuantityFromBig(new(big.Int).SetBytes(l.Data[32:])), LogIndex: &li,
				})
			}
		case topicTransferBatch:
			if len(l.Topics) == 4 {
				ids, vals, ok := decodeTwoUintArrays(l.Data)
				for k := 0; ok && k < len(ids); k++ {
					out.Transfers = append(out.Transfers, models.AssetTransfer{
						Asset: models.AssetRef{Kind: models.AssetERC1155, Address: token, TokenID: models.QuantityFromBig(ids[k])},
						From:  addrTopic(l.Topics[2]), To: addrTopic(l.Topics[3]), Amount: models.QuantityFromBig(vals[k]), LogIndex: &li,
					})
				}
			}
		case topicDeposit: // WETH-style wrap: mints to dst
			if len(l.Topics) == 2 && len(l.Data) == 32 {
				out.Transfers = append(out.Transfers, models.AssetTransfer{
					Asset: models.AssetRef{Kind: models.AssetERC20, Address: token},
					From:  (common.Address{}).Hex(), To: addrTopic(l.Topics[1]),
					Amount: models.QuantityFromBig(new(big.Int).SetBytes(l.Data)), LogIndex: &li,
				})
			}
		case topicWithdrawal: // WETH-style unwrap: burns from src
			if len(l.Topics) == 2 && len(l.Data) == 32 {
				out.Transfers = append(out.Transfers, models.AssetTransfer{
					Asset: models.AssetRef{Kind: models.AssetERC20, Address: token},
					From:  addrTopic(l.Topics[1]), To: (common.Address{}).Hex(),
					Amount: models.QuantityFromBig(new(big.Int).SetBytes(l.Data)), LogIndex: &li,
				})
			}
		}
	}
	return out
}

// decodeTwoUintArrays decodes abi.encode(uint256[], uint256[]) defensively.
func decodeTwoUintArrays(d []byte) ([]*big.Int, []*big.Int, bool) {
	read := func(off uint64) ([]*big.Int, bool) {
		if off+32 > uint64(len(d)) {
			return nil, false
		}
		n := new(big.Int).SetBytes(d[off : off+32])
		if !n.IsUint64() || n.Uint64() > 10_000 || off+32+n.Uint64()*32 > uint64(len(d)) {
			return nil, false
		}
		out := make([]*big.Int, n.Uint64())
		for i := range out {
			s := off + 32 + uint64(i)*32 //nolint:gosec // i bounded by n
			out[i] = new(big.Int).SetBytes(d[s : s+32])
		}
		return out, true
	}
	if len(d) < 64 {
		return nil, nil, false
	}
	o1, o2 := new(big.Int).SetBytes(d[:32]), new(big.Int).SetBytes(d[32:64])
	if !o1.IsUint64() || !o2.IsUint64() {
		return nil, nil, false
	}
	a, ok1 := read(o1.Uint64())
	b, ok2 := read(o2.Uint64())
	if !ok1 || !ok2 || len(a) != len(b) {
		return nil, nil, false
	}
	return a, b, true
}

var panicCodes = map[uint64]string{
	0x01: "assertion failed", 0x11: "arithmetic overflow or underflow", 0x12: "division by zero",
	0x21: "invalid enum value", 0x22: "invalid storage byte array", 0x31: "pop on empty array",
	0x32: "array index out of bounds", 0x41: "out of memory", 0x51: "call to uninitialized function",
}

// DecodeRevert renders revert data. The returned text is attacker-controlled
// for Error(string) and must be sanitized before display.
func DecodeRevert(data []byte) string {
	switch {
	case len(data) == 0:
		return ""
	case len(data) >= 4 && hexutil.Encode(data[:4]) == "0x08c379a0":
		if len(data) >= 4+64 {
			body := data[4:]
			off := new(big.Int).SetBytes(body[:32])
			if off.IsUint64() && off.Uint64()+32 <= uint64(len(body)) {
				n := new(big.Int).SetBytes(body[off.Uint64() : off.Uint64()+32])
				start := off.Uint64() + 32
				if n.IsUint64() && start+n.Uint64() <= uint64(len(body)) {
					return string(body[start : start+n.Uint64()])
				}
			}
		}
		return "Error(string) with malformed payload"
	case len(data) == 36 && hexutil.Encode(data[:4]) == "0x4e487b71":
		code := new(big.Int).SetBytes(data[4:])
		if code.IsUint64() {
			if desc, ok := panicCodes[code.Uint64()]; ok {
				return fmt.Sprintf("panic 0x%02x (%s)", code.Uint64(), desc)
			}
		}
		return "panic " + hexutil.EncodeBig(code)
	case len(data) >= 4:
		return "custom error " + hexutil.Encode(data[:4])
	default:
		return "revert data " + hexutil.Encode(data)
	}
}

// revertDataFromRPCError extracts hex revert data from an RPC error's data
// field (string "0x..." in most clients).
func revertDataFromRPCError(raw []byte) []byte {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if !strings.HasPrefix(s, "0x") {
		return nil
	}
	b, err := hexutil.Decode(s)
	if err != nil {
		return nil
	}
	return b
}
