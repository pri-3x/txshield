package decoder

import (
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/pri-3x/txshield/pkg/models"
)

// DerivedParamType marks parameters TxShield computed from other parameters
// rather than read directly from calldata.
const DerivedParamType = "derived"

// annotate adds derived, human-friendly parameters. Derived parameters are
// marked with Type "derived" so consumers can tell them from calldata.
func annotate(c *models.DecodedCall) {
	// Uniswap V3 packed paths: in exactInput / exactOutput (as a tuple field)
	// and in Universal Router V3 swap commands (top-level "path").
	isExactOut := strings.HasPrefix(c.Method, "exactOutput") || c.Method == "V3_SWAP_EXACT_OUT"
	switch {
	case c.Method == "V3_SWAP_EXACT_IN" || c.Method == "V3_SWAP_EXACT_OUT":
		if p, ok := findBytes(c.Params, "path"); ok {
			appendPath(c, p, isExactOut)
		}
	case (c.Standard == StdUniV3Router || c.Standard == StdUniRouter02) && (c.Method == "exactInput" || c.Method == "exactOutput"):
		if len(c.Params) == 1 {
			if fields, ok := c.Params[0].Value.([]models.DecodedParam); ok {
				if p, ok := findBytes(fields, "path"); ok {
					appendPath(c, p, isExactOut)
				}
			}
		}
	}
}

func findBytes(params []models.DecodedParam, name string) ([]byte, bool) {
	for _, p := range params {
		if p.Name == name && p.Type == "bytes" {
			s, _ := p.Value.(string)
			b, err := hexutil.Decode(s)
			return b, err == nil
		}
	}
	return nil, false
}

func appendPath(c *models.DecodedCall, path []byte, reversed bool) {
	tokens, fees, ok := DecodeV3Path(path)
	if !ok {
		c.Warnings = append(c.Warnings, "Uniswap V3 path has an invalid length")
		return
	}
	order := "tokenIn-to-tokenOut"
	if reversed {
		order = "tokenOut-to-tokenIn"
	}
	feeStrs := make([]any, len(fees))
	for i, f := range fees {
		feeStrs[i] = strconv.FormatUint(uint64(f), 10)
	}
	tokStrs := make([]any, len(tokens))
	for i, t := range tokens {
		tokStrs[i] = t.Hex()
	}
	c.Params = append(c.Params, models.DecodedParam{
		Name: "pathDecoded",
		Type: DerivedParamType,
		Value: []models.DecodedParam{
			{Name: "tokens", Type: "address[]", Value: tokStrs},
			{Name: "fees", Type: "uint24[]", Value: feeStrs},
			{Name: "order", Type: "string", Value: order},
		},
	})
}

// DecodeV3Path splits a Uniswap V3 packed path:
// token(20) | fee(3) | token(20) | fee(3) | token(20) ...
func DecodeV3Path(p []byte) ([]common.Address, []uint32, bool) {
	const addrLen, feeLen = 20, 3
	if len(p) < addrLen+feeLen+addrLen || (len(p)-addrLen)%(addrLen+feeLen) != 0 {
		return nil, nil, false
	}
	hops := (len(p) - addrLen) / (addrLen + feeLen)
	tokens := make([]common.Address, 0, hops+1)
	fees := make([]uint32, 0, hops)
	off := 0
	for i := 0; i < hops; i++ {
		tokens = append(tokens, common.BytesToAddress(p[off:off+addrLen]))
		off += addrLen
		fees = append(fees, uint32(p[off])<<16|uint32(p[off+1])<<8|uint32(p[off+2]))
		off += feeLen
	}
	tokens = append(tokens, common.BytesToAddress(p[off:off+addrLen]))
	return tokens, fees, true
}
