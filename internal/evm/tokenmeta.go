package evm

import (
	"context"
	"math/big"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"

	"github.com/pri-3x/txshield/pkg/interfaces"
)

var selSymbol = common.FromHex("95d89b41")

// MaxSymbolRunes bounds a token symbol taken from a contract.
const MaxSymbolRunes = 16

// TokenMetadata reads a token's self-reported symbol and decimals at blk.
//
// Both values come from the token contract and are display hints only: any
// contract can claim to be "USDC" with 6 decimals. Callers must label them
// as unverified and never base a security decision on them. Missing or
// malformed values are returned empty (symbol "", decimals nil); only
// infrastructure failures are errors.
func TokenMetadata(ctx context.Context, r interfaces.ChainReader, token common.Address, blk *big.Int) (string, *uint8, error) {
	out, ok, err := staticCall(ctx, r, token, selSymbol, blk)
	if err != nil {
		return "", nil, err
	}
	symbol := ""
	if ok {
		symbol = parseSymbol(out)
	}
	var decimals *uint8
	out, ok, err = staticCall(ctx, r, token, selDecimals, blk)
	if err != nil {
		return "", nil, err
	}
	if ok && len(out) == 32 {
		if d, ok := boundedWord(out, 77); ok {
			v := uint8(d) //nolint:gosec // boundedWord guarantees 0 <= d <= 77
			decimals = &v
		}
	}
	return symbol, decimals, nil
}

// parseSymbol decodes an ABI `string` return value, or the `bytes32` that
// some older tokens return, and keeps only printable characters.
func parseSymbol(out []byte) string {
	var raw []byte
	switch {
	case len(out) >= 64:
		o, ok := boundedWord(out[:32], len(out)-32)
		if !ok {
			return ""
		}
		n, ok := boundedWord(out[o:o+32], len(out)-o-32)
		if !ok {
			return ""
		}
		raw = out[o+32 : o+32+n]
	case len(out) == 32:
		raw = []byte(strings.TrimRight(string(out), "\x00"))
	default:
		return ""
	}
	if !utf8.Valid(raw) {
		return ""
	}
	var b strings.Builder
	n := 0
	for _, c := range string(raw) {
		// Letters, digits, currency signs (USD₮), and common punctuation
		// only: no spaces, control, format (bidi, zero-width), or
		// combining characters.
		allowed := unicode.IsLetter(c) || unicode.IsDigit(c) || unicode.Is(unicode.Sc, c) || strings.ContainsRune(".-_+", c)
		if !allowed {
			continue
		}
		if n == MaxSymbolRunes {
			break
		}
		b.WriteRune(c)
		n++
	}
	return b.String()
}

// boundedWord reads a 32-byte big-endian word as an int in [0, max].
func boundedWord(word []byte, max int) (int, bool) {
	if max < 0 {
		return 0, false
	}
	v := new(big.Int).SetBytes(word)
	if v.Cmp(big.NewInt(int64(max))) > 0 {
		return 0, false
	}
	return int(v.Int64()), true
}
