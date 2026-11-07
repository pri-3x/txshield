package decoder

import (
	"context"
	"encoding/json"
	"math/big"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/txshield/txshield/pkg/interfaces"
	"github.com/txshield/txshield/pkg/models"
)

func word(n int) []byte { return common.LeftPadBytes(big.NewInt(int64(n)).Bytes(), 32) }

// aliasBomb encodes f(uint256[][][]) where every outer and middle offset
// points at the same array of n elements: n^3 values from ~3n words.
func aliasBomb(n int) []byte {
	d := append([]byte{}, crypto.Keccak256([]byte("f(uint256[][][])"))[:4]...)
	d = append(d, word(32)...)
	d = append(d, word(n)...)
	for i := 0; i < n; i++ {
		d = append(d, word(32*n)...)
	}
	d = append(d, word(n)...)
	for i := 0; i < n; i++ {
		d = append(d, word(32*n)...)
	}
	d = append(d, word(n)...)
	for i := 0; i < n; i++ {
		d = append(d, word(i)...)
	}
	return d
}

// Regression for the security review finding: a 29 KB request used to
// allocate ~2.6 GB (27M big.Ints); at the calldata limit it is unbounded.
func TestAliasedOffsetsDoNotExplode(t *testing.T) {
	abiJSON := json.RawMessage(`[{"type":"function","name":"f","inputs":[{"name":"x","type":"uint256[][][]"}]}]`)
	data := aliasBomb(1300) // ~125 KB, just under the API calldata limit: 2.2e9 values if decoded
	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()

	dec := New(Builtin(), DefaultLimits)
	to := common.Address{}
	c, err := dec.Decode(context.Background(), &models.Transaction{To: &to, Value: new(big.Int), Data: data}, interfaces.DecodeOptions{ABIJSON: abiJSON})
	if err != nil {
		t.Fatal(err)
	}

	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("decoding took %v", d)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
		t.Errorf("decoding allocated %d MiB", grew>>20)
	}
	if len(c.Params) != 0 || !strings.Contains(strings.Join(c.Warnings, " "), "refusing to decode") {
		t.Errorf("expected a refusal warning and no params, got params=%d warnings=%q", len(c.Params), c.Warnings)
	}
}

// Canonical encodings, including nested dynamic arrays and tuples, must
// still decode.
func TestBudgetAcceptsCanonicalEncodings(t *testing.T) {
	type pair struct {
		A common.Address
		B []byte
	}
	nested := make([][][]*big.Int, 8)
	for i := range nested {
		nested[i] = make([][]*big.Int, 8)
		for j := range nested[i] {
			nested[i][j] = []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}
		}
	}
	cases := []struct {
		sig  string
		args []any
	}{
		{"f(uint256[][][])", []any{nested}},
		{"f(uint256[64])", []any{[64]*big.Int{}}},
		{"f(bytes[],string)", []any{[][]byte{{1}, {}, make([]byte, 100)}, "hello"}},
		{"f((address a, bytes b)[])", []any{[]pair{{alice, []byte{1}}, {bob, nil}}}},
		{"f(address[],uint256)", []any{[]common.Address{}, big.NewInt(0)}},
	}
	for _, tc := range cases {
		m, err := ParseSignature(tc.sig)
		if err != nil {
			t.Fatal(err)
		}
		for i, a := range tc.args {
			if v, ok := a.([64]*big.Int); ok {
				for j := range v {
					v[j] = big.NewInt(int64(j))
				}
				tc.args[i] = v
			}
		}
		enc, err := m.Inputs.Pack(tc.args...)
		if err != nil {
			t.Fatalf("%s: pack: %v", tc.sig, err)
		}
		if err := checkElementBudget(m.Inputs, enc); err != nil {
			t.Errorf("%s: canonical encoding rejected: %v", tc.sig, err)
		}
		if _, err := safeUnpack(m.Inputs, enc); err != nil {
			t.Errorf("%s: %v", tc.sig, err)
		}
	}
}

// countValues counts values the way the budget does (containers count too).
func countValues(v reflect.Value) int {
	switch v.Kind() {
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return 1
		}
		fallthrough
	case reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return 1 // bytesN, address
		}
		n := 1
		for i := 0; i < v.Len(); i++ {
			n += countValues(v.Index(i))
		}
		return n
	case reflect.Struct:
		n := 1
		for i := 0; i < v.NumField(); i++ {
			n += countValues(v.Field(i))
		}
		return n
	default:
		return 1
	}
}

// FuzzElementBudget checks the property the guard relies on: whenever the
// walk accepts, go-ethereum creates at most elementBudget values.
func FuzzElementBudget(f *testing.F) {
	sigs := []string{
		"f(uint256[][][])",
		"f(bytes[][])",
		"f((uint256 a, bytes b)[][])",
		"f(uint256[2][][3])",
		"f(string[2][])",
		"f(address,(bytes[] x, uint8[3] y)[])",
	}
	for i := uint8(0); int(i) < len(sigs); i++ {
		f.Add(i, aliasBomb(4)[4:])
		f.Add(i, aliasBomb(20)[4:])
	}
	f.Fuzz(func(t *testing.T, which uint8, data []byte) {
		m, err := ParseSignature(sigs[int(which)%len(sigs)])
		if err != nil {
			t.Fatal(err)
		}
		if checkElementBudget(m.Inputs, data) != nil {
			return
		}
		values, err := safeUnpack(m.Inputs, data)
		if err != nil {
			return
		}
		n := 0
		for _, v := range values {
			n += countValues(reflect.ValueOf(v))
		}
		if n > elementBudget(len(data)) {
			t.Fatalf("budget walk accepted %d values > budget %d for %s", n, elementBudget(len(data)), m.Sig)
		}
	})
}
