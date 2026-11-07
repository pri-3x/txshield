// Package models defines the data types exchanged between TxShield modules and
// returned to API clients. Types here are transport-neutral: they carry JSON
// tags for the public API but no HTTP or storage logic.
package models

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/txshield/txshield/pkg/txerrors"
)

// Quantity is an unsigned or signed integer carried as a decimal string in
// JSON output. On input it accepts a JSON number, a decimal string, or a
// 0x-prefixed hex string. The raw text is kept so that validation can report
// errors against the field name (see ParseTransaction).
type Quantity string

// UnmarshalJSON accepts `123`, `"123"`, and `"0x7b"`.
func (q *Quantity) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if bytes.Equal(b, []byte("null")) {
		*q = ""
		return nil
	}
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*q = Quantity(strings.TrimSpace(s))
		return nil
	}
	// Bare JSON number: keep text as-is; fractional/exponent forms are
	// rejected during parsing.
	*q = Quantity(b)
	return nil
}

// QuantityFromBig formats v as a decimal Quantity. A nil v yields "0".
func QuantityFromBig(v *big.Int) Quantity {
	if v == nil {
		return "0"
	}
	return Quantity(v.String())
}

// MaxUint256 is 2^256 - 1, the largest EVM word.
var MaxUint256 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

// ParseUint256 parses a non-negative integer in decimal or 0x-hex form that
// fits in 256 bits.
func ParseUint256(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty value")
	}
	v := new(big.Int)
	var ok bool
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		h := s[2:]
		if h == "" {
			return nil, fmt.Errorf("empty hex value")
		}
		_, ok = v.SetString(h, 16)
	} else {
		for _, c := range s {
			if c < '0' || c > '9' {
				return nil, fmt.Errorf("must be a non-negative integer in decimal or 0x-hex form")
			}
		}
		_, ok = v.SetString(s, 10)
	}
	if !ok {
		return nil, fmt.Errorf("not a valid integer")
	}
	if v.Sign() < 0 || v.Cmp(MaxUint256) > 0 {
		return nil, fmt.Errorf("out of uint256 range")
	}
	return v, nil
}

// ParseAddress parses a 0x-prefixed 20-byte hex address. All-lowercase and
// all-uppercase forms are accepted; mixed-case input must carry a valid
// EIP-55 checksum, because a bad checksum usually indicates a typo.
func ParseAddress(s string) (common.Address, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return common.Address{}, fmt.Errorf("must be 0x-prefixed")
	}
	body := s[2:]
	if len(body) != 2*common.AddressLength {
		return common.Address{}, fmt.Errorf("must be 20 bytes (40 hex characters)")
	}
	if _, err := hexutil.Decode("0x" + body); err != nil {
		return common.Address{}, fmt.Errorf("invalid hex")
	}
	addr := common.HexToAddress(body)
	if body != strings.ToLower(body) && body != strings.ToUpper(body) {
		if addr.Hex()[2:] != body {
			return common.Address{}, fmt.Errorf("invalid EIP-55 checksum")
		}
	}
	return addr, nil
}

// BlockTag is a named block reference.
type BlockTag string

const (
	BlockLatest    BlockTag = "latest"
	BlockSafe      BlockTag = "safe"
	BlockFinalized BlockTag = "finalized"
)

// BlockRef identifies the state a transaction is analyzed against. Exactly one
// of Tag, Number, or Hash is set after parsing. "pending" is intentionally not
// supported: pending state is node-specific and not reproducible.
type BlockRef struct {
	Tag    BlockTag     `json:"tag,omitempty"`
	Number *uint64      `json:"number,omitempty"`
	Hash   *common.Hash `json:"hash,omitempty"`
}

// ParseBlockRef parses "", "latest", "safe", "finalized", a decimal or 0x block
// number, or a 32-byte block hash. Empty means latest.
func ParseBlockRef(s string) (BlockRef, error) {
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "", "latest":
		return BlockRef{Tag: BlockLatest}, nil
	case "safe":
		return BlockRef{Tag: BlockSafe}, nil
	case "finalized":
		return BlockRef{Tag: BlockFinalized}, nil
	case "pending", "earliest":
		return BlockRef{}, fmt.Errorf("block tag %q is not supported", s)
	}
	if strings.HasPrefix(s, "0x") && len(s) == 2+2*common.HashLength {
		b, err := hexutil.Decode(s)
		if err != nil {
			return BlockRef{}, fmt.Errorf("invalid block hash")
		}
		h := common.BytesToHash(b)
		return BlockRef{Hash: &h}, nil
	}
	var n uint64
	var err error
	if strings.HasPrefix(s, "0x") {
		n, err = strconv.ParseUint(s[2:], 16, 64)
	} else {
		n, err = strconv.ParseUint(s, 10, 64)
	}
	if err != nil {
		return BlockRef{}, fmt.Errorf("must be a block tag, number, or 32-byte hash")
	}
	return BlockRef{Number: &n}, nil
}

// String renders the reference in JSON-RPC block parameter form.
func (b BlockRef) String() string {
	switch {
	case b.Hash != nil:
		return b.Hash.Hex()
	case b.Number != nil:
		return hexutil.EncodeUint64(*b.Number)
	case b.Tag != "":
		return string(b.Tag)
	default:
		return string(BlockLatest)
	}
}

// TransactionRequest is the wire form of an unsigned transaction submitted for
// analysis. All fields are untrusted; use ParseTransaction to validate.
type TransactionRequest struct {
	ChainID              uint64   `json:"chainId"`
	From                 string   `json:"from"`
	To                   string   `json:"to,omitempty"` // empty => contract creation
	Value                Quantity `json:"value,omitempty"`
	Data                 string   `json:"data,omitempty"`
	Gas                  Quantity `json:"gas,omitempty"`
	GasPrice             Quantity `json:"gasPrice,omitempty"`
	MaxFeePerGas         Quantity `json:"maxFeePerGas,omitempty"`
	MaxPriorityFeePerGas Quantity `json:"maxPriorityFeePerGas,omitempty"`
	Block                string   `json:"block,omitempty"`
}

// FeeModel describes which fee fields a transaction uses.
type FeeModel string

const (
	FeeUnspecified FeeModel = "unspecified"
	FeeLegacy      FeeModel = "legacy"
	FeeEIP1559     FeeModel = "eip1559"
)

// Transaction is a validated transaction ready for analysis.
type Transaction struct {
	ChainID              uint64
	From                 common.Address
	To                   *common.Address // nil => contract creation
	Value                *big.Int
	Data                 []byte
	Gas                  *uint64
	GasPrice             *big.Int
	MaxFeePerGas         *big.Int
	MaxPriorityFeePerGas *big.Int
	Block                BlockRef
}

// IsContractCreation reports whether the transaction deploys a contract.
func (t *Transaction) IsContractCreation() bool { return t.To == nil }

// Selector returns the 4-byte function selector, if calldata is long enough
// and the transaction is a call (not a creation).
func (t *Transaction) Selector() ([4]byte, bool) {
	var sel [4]byte
	if t.To == nil || len(t.Data) < 4 {
		return sel, false
	}
	copy(sel[:], t.Data[:4])
	return sel, true
}

// FeeModel reports which fee fields are set.
func (t *Transaction) FeeModel() FeeModel {
	switch {
	case t.MaxFeePerGas != nil:
		return FeeEIP1559
	case t.GasPrice != nil:
		return FeeLegacy
	default:
		return FeeUnspecified
	}
}

// MaxGas bounds a caller-chosen gas limit. It is far above any chain's
// block gas limit and stops callers from asking upstream nodes to run
// eth_estimateGas / debug_traceCall with effectively unlimited gas.
const MaxGas = 1_000_000_000

// MaxChainID bounds chain IDs to 2^53-1: every real chain fits, JSON numbers
// stay exact in JavaScript clients, and the value fits Postgres BIGINT.
const MaxChainID = 1<<53 - 1

// ParseLimits bounds untrusted input sizes.
type ParseLimits struct {
	MaxCalldataBytes int
}

// ParseTransaction validates r and converts it to a Transaction. It collects
// every field problem rather than stopping at the first, so API clients can
// fix all issues in one round trip.
func ParseTransaction(r TransactionRequest, lim ParseLimits) (*Transaction, error) {
	var errs []txerrors.FieldError
	bad := func(field, format string, args ...any) {
		errs = append(errs, txerrors.FieldError{Field: field, Message: fmt.Sprintf(format, args...)})
	}

	t := &Transaction{ChainID: r.ChainID}
	if r.ChainID == 0 {
		bad("chainId", "is required and must be > 0")
	} else if r.ChainID > MaxChainID {
		bad("chainId", "must not exceed 2^53-1")
	}

	if strings.TrimSpace(r.From) == "" {
		bad("from", "is required")
	} else if a, err := ParseAddress(r.From); err != nil {
		bad("from", "%v", err)
	} else {
		t.From = a
	}

	if strings.TrimSpace(r.To) != "" {
		if a, err := ParseAddress(r.To); err != nil {
			bad("to", "%v", err)
		} else {
			t.To = &a
		}
	}

	t.Value = new(big.Int)
	if r.Value != "" {
		if v, err := ParseUint256(string(r.Value)); err != nil {
			bad("value", "%v", err)
		} else {
			t.Value = v
		}
	}

	if d := strings.TrimSpace(r.Data); d != "" && d != "0x" {
		if !strings.HasPrefix(d, "0x") {
			bad("data", "must be 0x-prefixed hex")
		} else if lim.MaxCalldataBytes > 0 && (len(d)-2)/2 > lim.MaxCalldataBytes {
			bad("data", "exceeds maximum calldata size of %d bytes", lim.MaxCalldataBytes)
		} else if b, err := hexutil.Decode(d); err != nil {
			bad("data", "invalid hex: %v", err)
		} else {
			t.Data = b
		}
	}
	if t.To == nil && strings.TrimSpace(r.To) == "" && len(t.Data) == 0 {
		bad("to", "is required unless data contains contract creation bytecode")
	}

	if r.Gas != "" {
		if v, err := ParseUint256(string(r.Gas)); err != nil {
			bad("gas", "%v", err)
		} else if !v.IsUint64() || v.Sign() == 0 || v.Uint64() > MaxGas {
			bad("gas", "must be between 1 and %d", MaxGas)
		} else {
			g := v.Uint64()
			t.Gas = &g
		}
	}

	parseFee := func(field string, q Quantity) *big.Int {
		if q == "" {
			return nil
		}
		v, err := ParseUint256(string(q))
		if err != nil {
			bad(field, "%v", err)
			return nil
		}
		return v
	}
	t.GasPrice = parseFee("gasPrice", r.GasPrice)
	t.MaxFeePerGas = parseFee("maxFeePerGas", r.MaxFeePerGas)
	t.MaxPriorityFeePerGas = parseFee("maxPriorityFeePerGas", r.MaxPriorityFeePerGas)

	if r.GasPrice != "" && (r.MaxFeePerGas != "" || r.MaxPriorityFeePerGas != "") {
		bad("gasPrice", "cannot be combined with EIP-1559 fee fields")
	}
	if r.MaxPriorityFeePerGas != "" && r.MaxFeePerGas == "" {
		bad("maxFeePerGas", "is required when maxPriorityFeePerGas is set")
	}
	if t.MaxFeePerGas != nil && t.MaxPriorityFeePerGas != nil && t.MaxPriorityFeePerGas.Cmp(t.MaxFeePerGas) > 0 {
		bad("maxPriorityFeePerGas", "must not exceed maxFeePerGas")
	}

	if br, err := ParseBlockRef(r.Block); err != nil {
		bad("block", "%v", err)
	} else {
		t.Block = br
	}

	if len(errs) > 0 {
		return nil, txerrors.Invalid(errs...)
	}
	return t, nil
}

// BlockInfo identifies a concrete block that state was read at.
type BlockInfo struct {
	Number    uint64 `json:"number"`
	Hash      string `json:"hash"`
	Timestamp uint64 `json:"timestamp"`
	BaseFee   string `json:"baseFee,omitempty"` // wei, decimal; empty before EIP-1559
	GasLimit  uint64 `json:"gasLimit"`
}
