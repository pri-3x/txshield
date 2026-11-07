package decoder

import (
	"errors"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// errElementBudget is returned when decoding would materialize more values
// than the calldata can legitimately encode.
var errElementBudget = errors.New("arguments would decode to more values than the calldata can encode (offsets reuse the same data); refusing to decode")

// elementBudget is the maximum number of values decoding may produce for
// calldata of n bytes. Without offset aliasing every value occupies at least
// one 32-byte word, so a canonical encoding stays far below this; the
// constant leaves room for small fixed-size arrays in tiny calldata.
func elementBudget(n int) int { return 2*(n/32) + 256 }

// checkElementBudget walks the ABI head/offset layout of data, the way
// go-ethereum's decoder does, and counts the values decoding would create.
//
// go-ethereum follows offsets without checking whether they point at data
// already decoded, so a few KiB of calldata whose array offsets all reference
// the same inner array decodes into billions of values (an allocation bomb
// that the request timeout cannot stop). This walk does no allocation per
// element and stops as soon as the budget is exceeded.
//
// It only rejects on budget exhaustion. Malformed offsets or lengths end the
// walk of that branch without an error; go-ethereum then reports them.
func checkElementBudget(args abi.Arguments, data []byte) error {
	w := walker{budget: elementBudget(len(data))}
	pos := 0
	for _, a := range args {
		if !w.at(a.Type, data, pos) {
			return errElementBudget
		}
		pos += headSize(a.Type)
	}
	return nil
}

type walker struct{ budget int }

// spend consumes n units of budget; false once it is exhausted.
func (w *walker) spend(n int) bool {
	if n < 0 || n > w.budget {
		w.budget = -1
		return false
	}
	w.budget -= n
	return true
}

// at accounts for the value of type t whose head starts at frame[pos:].
// It returns false only when the budget is exhausted.
func (w *walker) at(t abi.Type, frame []byte, pos int) bool {
	if !isDynamic(t) {
		if size := staticSize(t); pos < 0 || size > len(frame)-pos {
			return true // too short: go-ethereum reports it
		}
		return w.spend(staticCount(t))
	}
	off, ok := readInt(frame, pos)
	if !ok || off > len(frame) {
		return w.spend(1)
	}
	return w.dynamic(t, frame[off:])
}

// dynamic accounts for a dynamic value whose encoding starts at region[0].
func (w *walker) dynamic(t abi.Type, region []byte) bool {
	switch t.T {
	case abi.StringTy, abi.BytesTy:
		return w.spend(1)
	case abi.SliceTy:
		n, ok := readInt(region, 0)
		if !ok {
			return w.spend(1)
		}
		elems := region[32:]
		if !w.spend(1) {
			return false
		}
		if !isDynamic(*t.Elem) {
			size := staticSize(*t.Elem)
			if size == 0 || n > len(elems)/size {
				return true // go-ethereum rejects the length
			}
			return w.spend(mulSat(n, staticCount(*t.Elem)))
		}
		if n > len(elems)/32 {
			return true
		}
		for i := 0; i < n; i++ {
			if !w.at(*t.Elem, elems, i*32) {
				return false
			}
		}
		return true
	case abi.ArrayTy: // fixed-size array with dynamic elements
		if !w.spend(1) {
			return false
		}
		for i := 0; i < t.Size; i++ {
			if !w.at(*t.Elem, region, i*32) {
				return false
			}
		}
		return true
	case abi.TupleTy:
		if !w.spend(1) {
			return false
		}
		pos := 0
		for _, e := range t.TupleElems {
			if !w.at(*e, region, pos) {
				return false
			}
			pos += headSize(*e)
		}
		return true
	default:
		return w.spend(1)
	}
}

// readInt reads the 32-byte big-endian word at b[pos:] as a non-negative int.
func readInt(b []byte, pos int) (int, bool) {
	if pos < 0 || pos+32 > len(b) {
		return 0, false
	}
	v := new(big.Int).SetBytes(b[pos : pos+32])
	if !v.IsInt64() || v.Int64() > math.MaxInt32 {
		return 0, false
	}
	return int(v.Int64()), true
}

func isDynamic(t abi.Type) bool {
	switch t.T {
	case abi.StringTy, abi.BytesTy, abi.SliceTy:
		return true
	case abi.ArrayTy:
		return isDynamic(*t.Elem)
	case abi.TupleTy:
		for _, e := range t.TupleElems {
			if isDynamic(*e) {
				return true
			}
		}
	}
	return false
}

// headSize is the number of bytes t occupies in its enclosing head.
func headSize(t abi.Type) int {
	if isDynamic(t) {
		return 32
	}
	return staticSize(t)
}

// staticSize is the encoded size of a static type, saturating on overflow.
func staticSize(t abi.Type) int {
	switch t.T {
	case abi.ArrayTy:
		return mulSat(t.Size, staticSize(*t.Elem))
	case abi.TupleTy:
		s := 0
		for _, e := range t.TupleElems {
			s = addSat(s, staticSize(*e))
		}
		return s
	default:
		return 32
	}
}

// staticCount is the number of values decoding a static type creates.
func staticCount(t abi.Type) int {
	switch t.T {
	case abi.ArrayTy:
		return addSat(1, mulSat(t.Size, staticCount(*t.Elem)))
	case abi.TupleTy:
		c := 1
		for _, e := range t.TupleElems {
			c = addSat(c, staticCount(*e))
		}
		return c
	default:
		return 1
	}
}

func mulSat(a, b int) int {
	if a <= 0 || b <= 0 {
		return 0
	}
	if a > math.MaxInt32/b {
		return math.MaxInt32
	}
	return a * b
}

func addSat(a, b int) int {
	if a > math.MaxInt32-b {
		return math.MaxInt32
	}
	return a + b
}
