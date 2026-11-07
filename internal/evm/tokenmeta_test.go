package evm

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func abiString(s string) []byte {
	out := common.LeftPadBytes(big.NewInt(32).Bytes(), 32)
	out = append(out, common.LeftPadBytes(big.NewInt(int64(len(s))).Bytes(), 32)...)
	return append(out, common.RightPadBytes([]byte(s), (len(s)+31)/32*32)...)
}

func TestParseSymbol(t *testing.T) {
	cases := []struct {
		in   []byte
		want string
	}{
		{abiString("USDC"), "USDC"},
		{abiString("USD₮0"), "USD₮0"},
		{common.RightPadBytes([]byte("MKR"), 32), "MKR"},                           // bytes32 symbol
		{abiString("US\u202eDC"), "USDC"},                                          // bidi override stripped
		{abiString("A\u200bB C\n"), "ABC"},                                         // zero-width, space, newline stripped
		{abiString(strings.Repeat("X", 100)), strings.Repeat("X", MaxSymbolRunes)}, // capped
		{abiString("<script>"), "script"},
		{[]byte{1, 2, 3}, ""},
		{append(common.LeftPadBytes(big.NewInt(1<<20).Bytes(), 32), make([]byte, 32)...), ""}, // offset out of range
		{abiString("\xff\xfe"), ""},                                                           // invalid UTF-8
	}
	for _, c := range cases {
		if got := parseSymbol(c.in); got != c.want {
			t.Errorf("parseSymbol(%x) = %q, want %q", c.in, got, c.want)
		}
	}
}
