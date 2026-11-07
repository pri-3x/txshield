package decoder

import (
	"fmt"
	"math/big"
	"reflect"
	"strconv"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/pri-3x/txshield/pkg/models"
)

// renderArgs converts unpacked ABI values into JSON-safe DecodedParams.
//
// Rendering rules (stable API contract):
//   - integers of every width: decimal strings (JSON numbers lose precision)
//   - address: EIP-55 checksummed hex
//   - bytes / bytesN / function: 0x hex
//   - bool, string: as-is (strings are untrusted; consumers must escape)
//   - arrays / slices: JSON arrays
//   - tuples: arrays of named DecodedParam
func renderArgs(args abi.Arguments, values []any) []models.DecodedParam {
	out := make([]models.DecodedParam, 0, len(args))
	for i, a := range args {
		if i >= len(values) {
			break
		}
		out = append(out, models.DecodedParam{
			Name:  a.Name,
			Type:  a.Type.String(),
			Value: renderValue(a.Type, reflect.ValueOf(values[i])),
		})
	}
	return out
}

func renderValue(t abi.Type, v reflect.Value) any {
	if !v.IsValid() {
		return nil
	}
	switch t.T {
	case abi.IntTy, abi.UintTy:
		return renderInt(v)
	case abi.AddressTy:
		if a, ok := v.Interface().(common.Address); ok {
			return a.Hex()
		}
	case abi.BoolTy:
		return v.Bool()
	case abi.StringTy:
		return v.String()
	case abi.BytesTy:
		return hexutil.Encode(v.Bytes())
	case abi.FixedBytesTy, abi.FunctionTy, abi.HashTy:
		b := make([]byte, v.Len())
		for i := range b {
			b[i] = byte(v.Index(i).Uint())
		}
		return hexutil.Encode(b)
	case abi.SliceTy, abi.ArrayTy:
		arr := make([]any, v.Len())
		for i := range arr {
			arr[i] = renderValue(*t.Elem, v.Index(i))
		}
		return arr
	case abi.TupleTy:
		fields := make([]models.DecodedParam, len(t.TupleElems))
		for i, et := range t.TupleElems {
			fields[i] = models.DecodedParam{
				Name:  t.TupleRawNames[i],
				Type:  et.String(),
				Value: renderValue(*et, v.Field(i)),
			}
		}
		return fields
	}
	return fmt.Sprint(v.Interface())
}

func renderInt(v reflect.Value) string {
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(v.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(v.Uint(), 10)
	}
	if b, ok := v.Interface().(*big.Int); ok && b != nil {
		return b.String()
	}
	return fmt.Sprint(v.Interface())
}
