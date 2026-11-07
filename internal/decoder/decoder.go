// Package decoder turns transaction calldata into a structured, JSON-safe
// call tree. It performs no network I/O.
//
// Decoding is best-effort and never fails on unrecognized or malformed
// calldata: unknown selectors return the selector and raw data, malformed
// arguments return warnings. Recognizing a selector says nothing about whether
// a call is safe; security judgments belong to the rules engine.
package decoder

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
	"github.com/pri-3x/txshield/pkg/txerrors"
)

// Limits bound the work done on untrusted calldata.
type Limits struct {
	MaxDepth    int // maximum nesting depth of decoded sub-calls
	MaxCalls    int // maximum total decoded calls (root + all nested)
	MaxABIBytes int // maximum size of a user-supplied ABI
}

// DefaultLimits are suitable for API use.
var DefaultLimits = Limits{MaxDepth: 4, MaxCalls: 256, MaxABIBytes: 512 << 10}

// Decoder implements interfaces.Decoder.
type Decoder struct {
	reg *Registry
	lim Limits
}

var _ interfaces.Decoder = (*Decoder)(nil)

// New returns a decoder using reg (typically Builtin()).
func New(reg *Registry, lim Limits) *Decoder {
	if lim.MaxDepth <= 0 {
		lim.MaxDepth = DefaultLimits.MaxDepth
	}
	if lim.MaxCalls <= 0 {
		lim.MaxCalls = DefaultLimits.MaxCalls
	}
	if lim.MaxABIBytes <= 0 {
		lim.MaxABIBytes = DefaultLimits.MaxABIBytes
	}
	return &Decoder{reg: reg, lim: lim}
}

// state is per-Decode mutable bookkeeping.
type state struct {
	ctx       context.Context
	userABI   *abi.ABI
	abiTarget common.Address // the user ABI applies only to this address
	calls     int
	truncated bool
}

// Decode implements interfaces.Decoder.
func (d *Decoder) Decode(ctx context.Context, tx *models.Transaction, opts interfaces.DecodeOptions) (*models.DecodedCall, error) {
	st := &state{ctx: ctx}
	if len(opts.ABIJSON) > 0 {
		if len(opts.ABIJSON) > d.lim.MaxABIBytes {
			return nil, txerrors.New(txerrors.KindPayloadTooLarge, "abi_too_large", fmt.Sprintf("ABI exceeds %d bytes", d.lim.MaxABIBytes))
		}
		parsed, err := abi.JSON(bytes.NewReader(opts.ABIJSON))
		if err != nil {
			return nil, txerrors.Wrap(err, txerrors.KindInvalidInput, "invalid_abi", "ABI is not valid JSON ABI: "+err.Error())
		}
		st.userABI = &parsed
		if tx.To != nil {
			st.abiTarget = *tx.To
		}
	}

	var call models.DecodedCall
	if tx.IsContractCreation() {
		call = decodeCreation(tx.Value, tx.Data)
	} else {
		call = d.decodeCall(st, *tx.To, tx.Value, tx.Data, 0, models.CallTypeCall)
	}
	if st.truncated {
		call.Warnings = append(call.Warnings, fmt.Sprintf("nested decoding stopped after %d calls or depth %d; some sub-calls are not shown", d.lim.MaxCalls, d.lim.MaxDepth))
	}
	if err := ctx.Err(); err != nil {
		return nil, txerrors.Wrap(err, txerrors.KindTimeout, "decode_cancelled", "decoding cancelled")
	}
	return &call, nil
}

func decodeCreation(value *big.Int, initCode []byte) models.DecodedCall {
	return models.DecodedCall{
		Kind:     models.CallContractCreation,
		CallType: models.CallTypeCreate,
		Value:    quantity(value),
		Source:   models.DecodeNone,
		Params: []models.DecodedParam{
			{Name: "initCodeSize", Type: "uint256", Value: fmt.Sprint(len(initCode))},
			{Name: "initCodeHash", Type: "bytes32", Value: crypto.Keccak256Hash(initCode).Hex()},
		},
		Warnings: []string{"contract creation: init code is not analyzed by the decoder"},
	}
}

func quantity(v *big.Int) models.Quantity {
	if v == nil || v.Sign() == 0 {
		return ""
	}
	return models.Quantity(v.String())
}

// decodeCall decodes one call to target. It never fails.
func (d *Decoder) decodeCall(st *state, target common.Address, value *big.Int, data []byte, depth int, ct models.CallType) models.DecodedCall {
	st.calls++
	c := models.DecodedCall{
		CallType: ct,
		Target:   target.Hex(),
		Value:    quantity(value),
		Source:   models.DecodeNone,
	}
	if len(data) == 0 {
		c.Kind = models.CallNativeTransfer
		return c
	}
	if len(data) < 4 {
		c.Kind = models.CallUnknown
		c.RawData = hexutil.Encode(data)
		c.Warnings = append(c.Warnings, "calldata is shorter than a 4-byte selector; the target's fallback function would handle it")
		return c
	}

	var sel [4]byte
	copy(sel[:], data[:4])
	c.Selector = hexutil.Encode(sel[:])
	args := data[4:]

	type candidate struct {
		method   abi.Method
		standard string
		source   models.DecodeSource
		entry    *Entry
	}
	var cands []candidate
	if st.userABI != nil && target == st.abiTarget {
		if m, err := st.userABI.MethodById(sel[:]); err == nil {
			cands = append(cands, candidate{method: *m, source: models.DecodeUserABI})
		}
	}
	for _, e := range d.reg.Lookup(sel) {
		cands = append(cands, candidate{method: e.Method, standard: e.Standard, source: models.DecodeBuiltin, entry: e})
	}
	if len(cands) == 0 {
		c.Kind = models.CallUnknown
		c.RawData = hexutil.Encode(data)
		return c
	}

	var failures []string
	for i, cand := range cands {
		values, err := safeUnpack(cand.method.Inputs, args)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", cand.method.Sig, err))
			continue
		}
		c.Kind = models.CallContract
		c.Method = cand.method.RawName
		c.Signature = cand.method.Sig
		c.Standard = cand.standard
		c.Source = cand.source
		c.Params = renderArgs(cand.method.Inputs, values)
		for j, other := range cands {
			if j != i && other.method.Sig != cand.method.Sig {
				c.Candidates = append(c.Candidates, other.method.Sig)
			}
		}
		if w := encodingWarning(cand.method.Inputs, values, args); w != "" {
			c.Warnings = append(c.Warnings, w)
		}
		annotate(&c)
		if cand.entry != nil && cand.entry.Nested != NestedNone {
			if depth+1 > d.lim.MaxDepth || st.calls >= d.lim.MaxCalls {
				st.truncated = true
			} else if st.ctx.Err() == nil {
				d.expand(st, &c, cand.entry, target, values, depth)
			}
		}
		return c
	}

	// Selector known, arguments do not decode under any candidate.
	c.Kind = models.CallContract
	c.RawData = hexutil.Encode(data)
	for _, cand := range cands {
		c.Candidates = append(c.Candidates, cand.method.Sig)
	}
	c.Warnings = append(c.Warnings, "selector is known but the arguments do not decode: "+strings.Join(failures, "; "))
	return c
}

// safeUnpack wraps UnpackValues: the input is attacker-controlled, so it
// first bounds the number of values decoding may create (see
// checkElementBudget) and recovers from panics, which ABI decoders have
// historically had on adversarial data.
func safeUnpack(args abi.Arguments, data []byte) (values []any, err error) {
	if err := checkElementBudget(args, data); err != nil {
		return nil, err
	}
	defer func() {
		if r := recover(); r != nil {
			values, err = nil, fmt.Errorf("decoder panic: %v", r)
		}
	}()
	return args.UnpackValues(data)
}

// encodingWarning re-encodes decoded values and compares with the input.
// Trailing bytes are common (frontends append tracking tags) but can also
// smuggle data; non-canonical encodings are unusual and worth surfacing.
func encodingWarning(args abi.Arguments, values []any, input []byte) (w string) {
	defer func() {
		if recover() != nil {
			w = ""
		}
	}()
	packed, err := args.Pack(values...)
	if err != nil || bytes.Equal(packed, input) {
		return ""
	}
	if bytes.HasPrefix(input, packed) {
		extra := input[len(packed):]
		shown := extra
		if len(shown) > 64 {
			shown = shown[:64]
		}
		return fmt.Sprintf("%d trailing bytes after the ABI-encoded arguments (0x%s%s)", len(extra), hex.EncodeToString(shown), map[bool]string{true: "...", false: ""}[len(extra) > 64])
	}
	return "arguments use a non-canonical ABI encoding"
}
