package decoder

import (
	"fmt"
	"math/big"
	"reflect"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/pri-3x/txshield/pkg/models"
)

// expand decodes sub-calls embedded in a call's arguments and attaches them
// as children. Values come from abi.UnpackValues; tuple fields are read by
// position (go-ethereum builds tuple structs in component order).
func (d *Decoder) expand(st *state, c *models.DecodedCall, e *Entry, target common.Address, values []any, depth int) {
	add := func(child models.DecodedCall, label string) {
		child.Label = label
		c.Children = append(c.Children, child)
	}
	budgetOK := func() bool {
		if st.calls >= d.lim.MaxCalls || st.ctx.Err() != nil {
			st.truncated = true
			return false
		}
		return true
	}

	switch e.Nested {
	case NestedSelfMulticall:
		calls, _ := values[e.ArgIndex[0]].([][]byte)
		for i, data := range calls {
			if !budgetOK() {
				return
			}
			add(d.decodeCall(st, target, nil, data, depth+1, models.CallTypeSelf), fmt.Sprintf("multicall call %d", i))
		}

	case NestedMulticall3:
		arr := reflect.ValueOf(values[e.ArgIndex[0]])
		for i := 0; i < arr.Len(); i++ {
			if !budgetOK() {
				return
			}
			call := arr.Index(i)
			to, _ := call.Field(0).Interface().(common.Address)
			var value *big.Int
			var data []byte
			switch call.NumField() {
			case 2: // (target, callData)
				data, _ = call.Field(1).Interface().([]byte)
			case 3: // (target, allowFailure, callData)
				data, _ = call.Field(2).Interface().([]byte)
			case 4: // (target, allowFailure, value, callData)
				value, _ = call.Field(2).Interface().(*big.Int)
				data, _ = call.Field(3).Interface().([]byte)
			}
			add(d.decodeCall(st, to, value, data, depth+1, models.CallTypeCall), fmt.Sprintf("%s call %d", e.Method.RawName, i))
		}

	case NestedUniversalRouter:
		commands, _ := values[0].([]byte)
		inputs, _ := values[1].([][]byte)
		if len(commands) != len(inputs) {
			c.Warnings = append(c.Warnings, fmt.Sprintf("Universal Router: %d commands but %d inputs; the router would revert", len(commands), len(inputs)))
		}
		for i, cmd := range commands {
			if i >= len(inputs) || !budgetOK() {
				return
			}
			st.calls++
			add(decodeRouterCommand(target, cmd, inputs[i]), fmt.Sprintf("command %d (0x%02x)", i, cmd))
		}

	case NestedSafeExec:
		to, _ := values[0].(common.Address)
		value, _ := values[1].(*big.Int)
		data, _ := values[2].([]byte)
		op, _ := values[3].(uint8)
		ct := models.CallTypeCall
		switch op {
		case 0:
		case 1:
			ct = models.CallTypeDelegateCall
			c.Warnings = append(c.Warnings, fmt.Sprintf("Safe transaction uses DELEGATECALL to %s: that code runs with the Safe's own storage and balance", to.Hex()))
		default:
			c.Warnings = append(c.Warnings, fmt.Sprintf("Safe transaction has invalid operation %d", op))
		}
		add(d.decodeCall(st, to, value, data, depth+1, ct), "Safe inner transaction")

	case NestedUpgradeAndCall:
		data, _ := values[e.ArgIndex[0]].([]byte)
		if len(data) == 0 {
			return
		}
		proxy := target
		var impl common.Address
		if len(values) == 3 { // ProxyAdmin.upgradeAndCall(proxy, implementation, data)
			proxy, _ = values[0].(common.Address)
			impl, _ = values[1].(common.Address)
		} else {
			impl, _ = values[0].(common.Address)
		}
		child := d.decodeCall(st, proxy, nil, data, depth+1, models.CallTypeDelegateCall)
		child.Warnings = append(child.Warnings, fmt.Sprintf("executed via DELEGATECALL into new implementation %s in the proxy's storage context", impl.Hex()))
		add(child, "post-upgrade initialization call")
	}
}

// Universal Router commands. Only command types 0x00-0x0e are decoded:
// they are identical across router versions, while 0x10+ differ between
// versions (e.g. NFT marketplaces in v1 vs Uniswap v4 in v2).
var routerCommands = map[byte]abi.Method{}

func init() {
	defs := map[byte]string{
		0x00: "V3_SWAP_EXACT_IN(address recipient, uint256 amountIn, uint256 amountOutMin, bytes path, bool payerIsUser)",
		0x01: "V3_SWAP_EXACT_OUT(address recipient, uint256 amountOut, uint256 amountInMax, bytes path, bool payerIsUser)",
		0x02: "PERMIT2_TRANSFER_FROM(address token, address recipient, uint160 amount)",
		0x03: "PERMIT2_PERMIT_BATCH(" + permitBatch + " permitBatch, bytes signature)",
		0x04: "SWEEP(address token, address recipient, uint256 amountMin)",
		0x05: "TRANSFER(address token, address recipient, uint256 value)",
		0x06: "PAY_PORTION(address token, address recipient, uint256 bips)",
		0x08: "V2_SWAP_EXACT_IN(address recipient, uint256 amountIn, uint256 amountOutMin, address[] path, bool payerIsUser)",
		0x09: "V2_SWAP_EXACT_OUT(address recipient, uint256 amountOut, uint256 amountInMax, address[] path, bool payerIsUser)",
		0x0a: "PERMIT2_PERMIT(" + permitSingle + " permitSingle, bytes signature)",
		0x0b: "WRAP_ETH(address recipient, uint256 amountMin)",
		0x0c: "UNWRAP_WETH(address recipient, uint256 amountMin)",
		0x0d: "PERMIT2_TRANSFER_FROM_BATCH((address from, address to, uint160 amount, address token)[] transfers)",
		0x0e: "BALANCE_CHECK_ERC20(address owner, address token, uint256 minBalance)",
	}
	for k, sig := range defs {
		m, err := ParseSignature(sig)
		if err != nil {
			panic("decoder: invalid router command " + sig + ": " + err.Error())
		}
		routerCommands[k] = m
	}
}

const (
	routerFlagAllowRevert = 0x80
	routerCommandTypeMask = 0x3f
)

func decodeRouterCommand(router common.Address, cmd byte, input []byte) models.DecodedCall {
	c := models.DecodedCall{
		CallType: models.CallTypeRouterCommand,
		Target:   router.Hex(),
		Source:   models.DecodeNone,
	}
	if cmd&routerFlagAllowRevert != 0 {
		c.Warnings = append(c.Warnings, "command may revert without reverting the whole transaction")
	}
	m, ok := routerCommands[cmd&routerCommandTypeMask]
	if !ok {
		c.Kind = models.CallUnknown
		c.RawData = hexutil.Encode(input)
		c.Warnings = append(c.Warnings, fmt.Sprintf("unrecognized Universal Router command type 0x%02x (command sets differ between router versions)", cmd&routerCommandTypeMask))
		return c
	}
	values, err := safeUnpack(m.Inputs, input)
	if err != nil {
		c.Kind = models.CallContract
		c.Method = m.RawName
		c.RawData = hexutil.Encode(input)
		c.Warnings = append(c.Warnings, "command input does not decode: "+err.Error())
		return c
	}
	c.Kind = models.CallContract
	c.Method = m.RawName
	c.Signature = m.Sig
	c.Standard = StdRouterCommand
	c.Source = models.DecodeBuiltin
	c.Params = renderArgs(m.Inputs, values)
	annotate(&c)
	return c
}
