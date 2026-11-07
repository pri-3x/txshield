package decoder

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
	"github.com/pri-3x/txshield/pkg/txerrors"
)

var (
	alice  = common.HexToAddress("0x1111111111111111111111111111111111111111")
	bob    = common.HexToAddress("0x2222222222222222222222222222222222222222")
	token  = common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	weth   = common.HexToAddress("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
	router = common.HexToAddress("0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD")
	maxU   = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
)

// calldata ABI-encodes a call to sig with args.
func calldata(t testing.TB, sig string, args ...any) []byte {
	t.Helper()
	m, err := ParseSignature(sig)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := m.Inputs.Pack(args...)
	if err != nil {
		t.Fatalf("pack %s: %v", sig, err)
	}
	return append(append([]byte{}, m.ID...), enc...)
}

// encodeArgs ABI-encodes args without a selector (router command inputs).
func encodeArgs(t testing.TB, sig string, args ...any) []byte {
	t.Helper()
	m, err := ParseSignature(sig)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := m.Inputs.Pack(args...)
	if err != nil {
		t.Fatalf("pack %s: %v", sig, err)
	}
	return enc
}

func decode(t testing.TB, to *common.Address, value *big.Int, data []byte, opts ...interfaces.DecodeOptions) *models.DecodedCall {
	t.Helper()
	var o interfaces.DecodeOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	if value == nil {
		value = new(big.Int)
	}
	c, err := New(Builtin(), DefaultLimits).Decode(context.Background(), &models.Transaction{ChainID: 1, From: alice, To: to, Value: value, Data: data}, o)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	// Every result must be JSON-serializable.
	if _, err := json.Marshal(c); err != nil {
		t.Fatalf("result not JSON-serializable: %v", err)
	}
	return c
}

func param(t testing.TB, c *models.DecodedCall, name string) any {
	t.Helper()
	for _, p := range c.Params {
		if p.Name == name {
			return p.Value
		}
	}
	t.Fatalf("param %q not found in %+v", name, c.Params)
	return nil
}

func ptr(a common.Address) *common.Address { return &a }

func TestNativeTransfer(t *testing.T) {
	c := decode(t, ptr(bob), big.NewInt(1e18), nil)
	if c.Kind != models.CallNativeTransfer || c.Value != "1000000000000000000" || c.Target != bob.Hex() || c.CallType != models.CallTypeCall {
		t.Fatalf("%+v", c)
	}
}

func TestERC20Transfer(t *testing.T) {
	c := decode(t, ptr(token), nil, calldata(t, "transfer(address,uint256)", bob, big.NewInt(1234)))
	if c.Kind != models.CallContract || c.Method != "transfer" || c.Standard != StdERC20 || c.Source != models.DecodeBuiltin {
		t.Fatalf("%+v", c)
	}
	if c.Selector != "0xa9059cbb" || c.Signature != "transfer(address,uint256)" || len(c.Warnings) != 0 {
		t.Fatalf("%+v", c)
	}
	if param(t, c, "to") != bob.Hex() || param(t, c, "amount") != "1234" {
		t.Fatalf("params = %+v", c.Params)
	}
}

func TestUnlimitedApprovalIsDecodedNotJudged(t *testing.T) {
	c := decode(t, ptr(token), nil, calldata(t, "approve(address,uint256)", bob, maxU))
	if c.Method != "approve" || c.Standard != StdERC20or721 {
		t.Fatalf("%+v", c)
	}
	if param(t, c, "amountOrTokenId") != maxU.String() || param(t, c, "spender") != bob.Hex() {
		t.Fatalf("params = %+v", c.Params)
	}
}

func TestSetApprovalForAll(t *testing.T) {
	c := decode(t, ptr(token), nil, calldata(t, "setApprovalForAll(address,bool)", bob, true))
	if c.Standard != StdERC721or1155 || param(t, c, "approved") != true {
		t.Fatalf("%+v", c)
	}
}

func TestUnknownSelector(t *testing.T) {
	data := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02}
	c := decode(t, ptr(token), nil, data)
	if c.Kind != models.CallUnknown || c.Selector != "0xdeadbeef" || c.RawData != "0xdeadbeef0102" || c.Source != models.DecodeNone {
		t.Fatalf("%+v", c)
	}
}

func TestShortCalldata(t *testing.T) {
	c := decode(t, ptr(token), nil, []byte{0x01, 0x02})
	if c.Kind != models.CallUnknown || len(c.Warnings) != 1 || c.Selector != "" {
		t.Fatalf("%+v", c)
	}
}

func TestMalformedArgsForKnownSelector(t *testing.T) {
	data := append(calldata(t, "transfer(address,uint256)", bob, big.NewInt(1))[:4], make([]byte, 10)...)
	c := decode(t, ptr(token), nil, data)
	if c.Kind != models.CallContract || c.Method != "" || c.RawData == "" || len(c.Candidates) != 1 || c.Candidates[0] != "transfer(address,uint256)" {
		t.Fatalf("%+v", c)
	}
	if len(c.Warnings) == 0 || !strings.Contains(c.Warnings[0], "do not decode") {
		t.Fatalf("warnings = %v", c.Warnings)
	}
}

func TestTrailingBytesWarning(t *testing.T) {
	data := append(calldata(t, "transfer(address,uint256)", bob, big.NewInt(1)), 0xca, 0xfe, 0xba, 0xbe)
	c := decode(t, ptr(token), nil, data)
	if c.Method != "transfer" || len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "4 trailing bytes") || !strings.Contains(c.Warnings[0], "cafebabe") {
		t.Fatalf("%+v", c)
	}
}

func TestNonCanonicalEncodingWarning(t *testing.T) {
	// bytes argument whose offset points past a gap word: decodes fine but
	// is not what a compliant encoder produces.
	good := calldata(t, "upgradeToAndCall(address,bytes)", bob, []byte{})
	weird := append([]byte{}, good[:4]...)
	weird = append(weird, good[4:36]...)                            // address
	weird = append(weird, common.LeftPadBytes([]byte{0x60}, 32)...) // offset 96 instead of 64
	weird = append(weird, make([]byte, 32)...)                      // gap
	weird = append(weird, make([]byte, 32)...)                      // length 0
	c := decode(t, ptr(token), nil, weird)
	if c.Method != "upgradeToAndCall" || len(c.Warnings) == 0 || !strings.Contains(strings.Join(c.Warnings, ";"), "non-canonical") {
		t.Fatalf("%+v", c)
	}
}

func TestContractCreation(t *testing.T) {
	c := decode(t, nil, nil, []byte{0x60, 0x80, 0x60, 0x40})
	if c.Kind != models.CallContractCreation || c.CallType != models.CallTypeCreate || param(t, c, "initCodeSize") != "4" {
		t.Fatalf("%+v", c)
	}
}

const customABI = `[
 {"type":"function","name":"doThing","inputs":[{"name":"x","type":"uint256"}],"outputs":[],"stateMutability":"nonpayable"},
 {"type":"function","name":"transfer","inputs":[{"name":"recipient","type":"address"},{"name":"value","type":"uint256"}],"outputs":[{"type":"bool"}],"stateMutability":"nonpayable"}
]`

func TestUserABI(t *testing.T) {
	opts := interfaces.DecodeOptions{ABIJSON: []byte(customABI)}

	c := decode(t, ptr(token), nil, calldata(t, "doThing(uint256 x)", big.NewInt(7)), opts)
	if c.Method != "doThing" || c.Source != models.DecodeUserABI || param(t, c, "x") != "7" {
		t.Fatalf("%+v", c)
	}

	// User ABI takes precedence over the built-in interpretation.
	c = decode(t, ptr(token), nil, calldata(t, "transfer(address,uint256)", bob, big.NewInt(5)), opts)
	if c.Source != models.DecodeUserABI || param(t, c, "recipient") != bob.Hex() {
		t.Fatalf("%+v", c)
	}

	// The ABI belongs to the top-level target only: nested calls to other
	// contracts must not be decoded with it.
	inner := calldata(t, "doThing(uint256 x)", big.NewInt(1))
	type call struct {
		Target   common.Address
		CallData []byte
	}
	outer := calldata(t, "aggregate((address target, bytes callData)[] calls)", []call{{Target: bob, CallData: inner}})
	c = decode(t, ptr(token), nil, outer, opts)
	if len(c.Children) != 1 || c.Children[0].Kind != models.CallUnknown {
		t.Fatalf("user ABI leaked to other target: %+v", c.Children)
	}

	_, err := New(Builtin(), DefaultLimits).Decode(context.Background(),
		&models.Transaction{To: ptr(token), Value: new(big.Int), Data: inner},
		interfaces.DecodeOptions{ABIJSON: []byte(`{not json`)})
	if txerrors.KindOf(err) != txerrors.KindInvalidInput {
		t.Fatalf("invalid ABI: err = %v", err)
	}
	_, err = New(Builtin(), Limits{MaxABIBytes: 10}).Decode(context.Background(),
		&models.Transaction{To: ptr(token), Value: new(big.Int), Data: inner},
		interfaces.DecodeOptions{ABIJSON: []byte(customABI)})
	if txerrors.KindOf(err) != txerrors.KindPayloadTooLarge {
		t.Fatalf("oversized ABI: err = %v", err)
	}
}

func TestMulticall3Aggregate3Value(t *testing.T) {
	type call struct {
		Target       common.Address
		AllowFailure bool
		Value        *big.Int
		CallData     []byte
	}
	data := calldata(t, "aggregate3Value((address target, bool allowFailure, uint256 value, bytes callData)[] calls)", []call{
		{Target: token, AllowFailure: false, Value: big.NewInt(0), CallData: calldata(t, "approve(address,uint256)", bob, maxU)},
		{Target: bob, AllowFailure: true, Value: big.NewInt(5), CallData: []byte{0xde, 0xad, 0xbe, 0xef}},
	})
	c := decode(t, ptr(router), big.NewInt(5), data)
	if c.Standard != StdMulticall3 || len(c.Children) != 2 {
		t.Fatalf("%+v", c)
	}
	a, b := c.Children[0], c.Children[1]
	if a.Method != "approve" || a.Target != token.Hex() || a.Label != "aggregate3Value call 0" || a.CallType != models.CallTypeCall || a.Value != "" {
		t.Fatalf("child0 = %+v", a)
	}
	if b.Kind != models.CallUnknown || b.Target != bob.Hex() || b.Value != "5" {
		t.Fatalf("child1 = %+v", b)
	}
}

func TestSelfMulticallSwapRouter02(t *testing.T) {
	type single struct {
		TokenIn           common.Address
		TokenOut          common.Address
		Fee               *big.Int
		Recipient         common.Address
		AmountIn          *big.Int
		AmountOutMinimum  *big.Int
		SqrtPriceLimitX96 *big.Int
	}
	swap := calldata(t, "exactInputSingle((address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96) params)",
		single{token, weth, big.NewInt(500), common.HexToAddress("0x0000000000000000000000000000000000000002"), big.NewInt(1000), big.NewInt(1), big.NewInt(0)})
	unwrap := calldata(t, "unwrapWETH9(uint256 amountMinimum, address recipient)", big.NewInt(1), alice)
	data := calldata(t, "multicall(uint256 deadline, bytes[] data)", big.NewInt(1700000000), [][]byte{swap, unwrap})

	c := decode(t, ptr(router), nil, data)
	if c.Method != "multicall" || len(c.Children) != 2 {
		t.Fatalf("%+v", c)
	}
	if c.Children[0].Standard != StdUniRouter02 || c.Children[0].CallType != models.CallTypeSelf || c.Children[0].Target != router.Hex() {
		t.Fatalf("child0 = %+v", c.Children[0])
	}
	fields := param(t, &c.Children[0], "params").([]models.DecodedParam)
	if fields[0].Name != "tokenIn" || fields[0].Value != token.Hex() || fields[2].Value != "500" {
		t.Fatalf("tuple fields = %+v", fields)
	}
	if c.Children[1].Method != "unwrapWETH9" || c.Children[1].Standard != StdUniV3Router {
		t.Fatalf("child1 = %+v", c.Children[1])
	}
}

func v3Path(tokens []common.Address, fees []uint32) []byte {
	var p []byte
	for i, tk := range tokens {
		p = append(p, tk.Bytes()...)
		if i < len(fees) {
			p = append(p, binary.BigEndian.AppendUint32(nil, fees[i])[1:]...) // uint24 fee
		}
	}
	return p
}

func TestUniversalRouter(t *testing.T) {
	type details struct {
		Token      common.Address
		Amount     *big.Int
		Expiration *big.Int
		Nonce      *big.Int
	}
	type permitSingleT struct {
		Details     details
		Spender     common.Address
		SigDeadline *big.Int
	}
	maxU160 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 160), big.NewInt(1))
	permit := encodeArgs(t, "f("+permitSingle+" permitSingle, bytes signature)",
		permitSingleT{details{token, maxU160, big.NewInt(1800000000), big.NewInt(0)}, router, big.NewInt(1700000000)}, make([]byte, 65))
	path := v3Path([]common.Address{token, weth}, []uint32{3000})
	swap := encodeArgs(t, "f(address recipient, uint256 amountIn, uint256 amountOutMin, bytes path, bool payerIsUser)",
		common.HexToAddress("0x0000000000000000000000000000000000000002"), big.NewInt(1000), big.NewInt(1), path, true)
	unwrap := encodeArgs(t, "f(address recipient, uint256 amountMin)", alice, big.NewInt(1))

	commands := []byte{0x0a, 0x00, 0x80 | 0x0c, 0x21}
	data := calldata(t, "execute(bytes commands, bytes[] inputs, uint256 deadline)", commands, [][]byte{permit, swap, unwrap, {0x01}}, big.NewInt(1700000000))

	c := decode(t, ptr(router), nil, data)
	if c.Standard != StdUniversal || len(c.Children) != 4 {
		t.Fatalf("%+v", c)
	}
	p := c.Children[0]
	if p.Method != "PERMIT2_PERMIT" || p.CallType != models.CallTypeRouterCommand || p.Label != "command 0 (0x0a)" {
		t.Fatalf("permit = %+v", p)
	}
	ps := param(t, &p, "permitSingle").([]models.DecodedParam)
	det := ps[0].Value.([]models.DecodedParam)
	if ps[1].Value != router.Hex() || det[1].Value != maxU160.String() {
		t.Fatalf("permit params = %+v", ps)
	}

	s := c.Children[1]
	if s.Method != "V3_SWAP_EXACT_IN" {
		t.Fatalf("swap = %+v", s)
	}
	pd := param(t, &s, "pathDecoded").([]models.DecodedParam)
	toks := pd[0].Value.([]any)
	if len(toks) != 2 || toks[0] != token.Hex() || toks[1] != weth.Hex() || pd[1].Value.([]any)[0] != "3000" {
		t.Fatalf("pathDecoded = %+v", pd)
	}

	u := c.Children[2]
	if u.Method != "UNWRAP_WETH" || len(u.Warnings) != 1 || !strings.Contains(u.Warnings[0], "may revert") {
		t.Fatalf("unwrap = %+v", u)
	}
	x := c.Children[3]
	if x.Kind != models.CallUnknown || !strings.Contains(strings.Join(x.Warnings, ";"), "0x21") {
		t.Fatalf("unknown cmd = %+v", x)
	}
}

func TestUniversalRouterLengthMismatch(t *testing.T) {
	data := calldata(t, "execute(bytes commands, bytes[] inputs)", []byte{0x0b, 0x0c}, [][]byte{encodeArgs(t, "f(address,uint256)", alice, big.NewInt(1))})
	c := decode(t, ptr(router), nil, data)
	if len(c.Children) != 1 || !strings.Contains(strings.Join(c.Warnings, ";"), "2 commands but 1 inputs") {
		t.Fatalf("%+v", c)
	}
}

func TestSafeDelegateCall(t *testing.T) {
	inner := calldata(t, "transferOwnership(address)", bob)
	data := calldata(t, "execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures)",
		bob, big.NewInt(0), inner, uint8(1), big.NewInt(0), big.NewInt(0), big.NewInt(0), common.Address{}, common.Address{}, make([]byte, 65))
	c := decode(t, ptr(router), nil, data)
	if len(c.Children) != 1 || c.Children[0].CallType != models.CallTypeDelegateCall || c.Children[0].Method != "transferOwnership" {
		t.Fatalf("%+v", c)
	}
	if !strings.Contains(strings.Join(c.Warnings, ";"), "DELEGATECALL") {
		t.Fatalf("missing delegatecall warning: %v", c.Warnings)
	}
}

func TestUpgradeToAndCall(t *testing.T) {
	impl := common.HexToAddress("0x3333333333333333333333333333333333333333")
	data := calldata(t, "upgradeToAndCall(address,bytes)", impl, calldata(t, "transferOwnership(address)", bob))
	c := decode(t, ptr(token), nil, data)
	if c.Standard != StdProxy || len(c.Children) != 1 {
		t.Fatalf("%+v", c)
	}
	ch := c.Children[0]
	if ch.CallType != models.CallTypeDelegateCall || ch.Target != token.Hex() || !strings.Contains(strings.Join(ch.Warnings, ";"), impl.Hex()) {
		t.Fatalf("child = %+v", ch)
	}

	// ProxyAdmin variant targets the proxy argument.
	data = calldata(t, "upgradeAndCall(address,address,bytes)", bob, impl, calldata(t, "renounceOwnership()"))
	c = decode(t, ptr(token), nil, data)
	if len(c.Children) != 1 || c.Children[0].Target != bob.Hex() {
		t.Fatalf("%+v", c)
	}
}

func TestDepthLimit(t *testing.T) {
	data := calldata(t, "transfer(address,uint256)", bob, big.NewInt(1))
	for i := 0; i < 10; i++ {
		data = calldata(t, "multicall(bytes[])", [][]byte{data})
	}
	c := decode(t, ptr(router), nil, data)
	depth := 0
	for cur := c; len(cur.Children) > 0; cur = &cur.Children[0] {
		depth++
	}
	if depth != DefaultLimits.MaxDepth {
		t.Fatalf("decoded depth = %d, want %d", depth, DefaultLimits.MaxDepth)
	}
	if !strings.Contains(strings.Join(c.Warnings, ";"), "nested decoding stopped") {
		t.Fatalf("missing truncation warning: %v", c.Warnings)
	}
}

func TestCallBudget(t *testing.T) {
	type call struct {
		Target   common.Address
		CallData []byte
	}
	calls := make([]call, 300)
	for i := range calls {
		calls[i] = call{Target: token, CallData: calldata(t, "transfer(address,uint256)", bob, big.NewInt(int64(i)))}
	}
	data := calldata(t, "aggregate((address target, bytes callData)[] calls)", calls)
	c, err := New(Builtin(), Limits{MaxCalls: 50}).Decode(context.Background(), &models.Transaction{To: ptr(router), Value: new(big.Int), Data: data}, interfaces.DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Children) != 49 || !strings.Contains(strings.Join(c.Warnings, ";"), "nested decoding stopped") {
		t.Fatalf("children = %d, warnings = %v", len(c.Children), c.Warnings)
	}
}

func TestCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := New(Builtin(), DefaultLimits).Decode(ctx, &models.Transaction{To: ptr(token), Value: new(big.Int)}, interfaces.DecodeOptions{})
	if txerrors.KindOf(err) != txerrors.KindTimeout {
		t.Fatalf("err = %v", err)
	}
}

func TestDecodeV3Path(t *testing.T) {
	tokens, fees, ok := DecodeV3Path(v3Path([]common.Address{token, weth, bob}, []uint32{500, 10000}))
	if !ok || len(tokens) != 3 || tokens[2] != bob || fees[0] != 500 || fees[1] != 10000 {
		t.Fatalf("%v %v %v", tokens, fees, ok)
	}
	for _, n := range []int{0, 20, 42, 44, 65, 67} { // 43 and 66 are valid 1- and 2-hop lengths
		if _, _, ok := DecodeV3Path(make([]byte, n)); ok {
			t.Errorf("length %d should be invalid", n)
		}
	}
}

func TestRenderTypes(t *testing.T) {
	reg, err := newRegistry([]spec{{standard: "test", sig: "weird(int24 a, bytes32 b, bool c, string d, (uint8 x, address[] ys)[2] t, uint64 e)"}})
	if err != nil {
		t.Fatal(err)
	}
	type inner struct {
		X  uint8
		Ys []common.Address
	}
	var b32 [32]byte
	b32[0] = 0xff
	data := calldata(t, "weird(int24 a, bytes32 b, bool c, string d, (uint8 x, address[] ys)[2] t, uint64 e)",
		big.NewInt(-500), b32, true, "hi\n<script>", [2]inner{{1, []common.Address{bob}}, {2, nil}}, uint64(1<<40))
	c, err := New(reg, DefaultLimits).Decode(context.Background(), &models.Transaction{To: ptr(token), Value: new(big.Int), Data: data}, interfaces.DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if param(t, c, "a") != "-500" || param(t, c, "c") != true || param(t, c, "d") != "hi\n<script>" || param(t, c, "e") != "1099511627776" {
		t.Fatalf("%+v", c.Params)
	}
	if !strings.HasPrefix(param(t, c, "b").(string), "0xff00") {
		t.Fatalf("bytes32 = %v", param(t, c, "b"))
	}
	arr := param(t, c, "t").([]any)
	first := arr[0].([]models.DecodedParam)
	if len(arr) != 2 || first[0].Name != "x" || first[0].Value != "1" || first[1].Value.([]any)[0] != bob.Hex() {
		t.Fatalf("tuple array = %+v", arr)
	}
	js, _ := json.Marshal(c)
	if strings.Contains(string(js), "<script>") {
		t.Fatal("HTML must be escaped in JSON output")
	}
}
