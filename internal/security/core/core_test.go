package core

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/pri-3x/txshield/pkg/models"
)

var (
	user  = common.HexToAddress("0x1111111111111111111111111111111111111111")
	mc    = common.HexToAddress("0xcA11bde05977b3631167028862bE2a173976CA11")
	token = common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	other = common.HexToAddress("0x2222222222222222222222222222222222222222")
)

func TestWalkTracksSenderAndContext(t *testing.T) {
	root := &models.DecodedCall{Kind: models.CallContract, Target: mc.Hex(), CallType: models.CallTypeCall, Children: []models.DecodedCall{
		{Label: "c0", CallType: models.CallTypeCall, Target: token.Hex()},
		{Label: "c1", CallType: models.CallTypeSelf, Target: mc.Hex()},
		{Label: "c2", CallType: models.CallTypeDelegateCall, Target: other.Hex()},
	}}
	tx := &models.Transaction{From: user, To: &mc}
	frames := map[string]Frame{}
	Walk(tx, root, func(f Frame) { frames[f.Call.Label] = f })

	if f := frames[""]; f.Sender != user || f.Self != mc || f.Path != "root" {
		t.Fatalf("root = %+v", f)
	}
	if f := frames["c0"]; f.Sender != mc || f.Self != token || f.Depth != 1 || f.Path != "root > c0" {
		t.Fatalf("call child: sender must be the container, got %+v", f)
	}
	if f := frames["c1"]; f.Sender != user || f.Self != mc {
		t.Fatalf("self-multicall keeps msg.sender: %+v", f)
	}
	if f := frames["c2"]; f.Sender != user || f.Self != mc {
		t.Fatalf("delegatecall runs in caller context: %+v", f)
	}
}

func TestCollectAddresses(t *testing.T) {
	root := &models.DecodedCall{Kind: models.CallContract, Target: token.Hex(), Params: []models.DecodedParam{
		{Name: "spender", Type: "address", Value: other.Hex()},
		{Name: "path", Type: "address[]", Value: []any{mc.Hex(), "not-an-address"}},
		{Name: "pathDecoded", Type: "derived", Value: []models.DecodedParam{{Name: "tokens", Type: "address[]", Value: []any{user.Hex()}}}},
	}}
	trace := &models.CallFrame{To: token.Hex(), Calls: []models.CallFrame{{To: "0x3333333333333333333333333333333333333333"}}}
	roles := CollectAddresses(&models.Transaction{From: user, To: &token}, root, nil, &models.SimulationResult{Trace: trace})
	if roles.Roles(token) != "target,traced" || roles.Roles(other) != "spender" || roles.Roles(mc) != "token" {
		t.Fatalf("roles: token=%s other=%s mc=%s", roles.Roles(token), roles.Roles(other), roles.Roles(mc))
	}
	if !roles[user][RoleSender] || !roles[user][RoleToken] {
		t.Fatal("derived path tokens must be collected")
	}
	if roles[common.HexToAddress("0x3333333333333333333333333333333333333333")] == nil {
		t.Fatal("trace addresses must be collected")
	}
}

func TestParamHelpersAndFingerprint(t *testing.T) {
	c := &models.DecodedCall{Params: []models.DecodedParam{{Name: "t", Value: []models.DecodedParam{{Name: "x", Value: "42"}}}}}
	v, _ := Param(c, "t")
	x, _ := Field(v, "x")
	if b, ok := AsBig(x); !ok || b.Int64() != 42 {
		t.Fatal("tuple field access")
	}
	if _, ok := AsAddress("0x12"); ok {
		t.Fatal("short address accepted")
	}
	f := NewFinding(models.RuleMetadata{ID: "R", Name: "n", DefaultSeverity: models.SeverityHigh}, "A", "B")
	if f.Fingerprint != "R:a|b" || f.Severity != models.SeverityHigh || f.Source != models.SourceFact {
		t.Fatalf("%+v", f)
	}
}

func TestAddressWords(t *testing.T) {
	data := append(append(common.LeftPadBytes(token.Bytes(), 32), common.LeftPadBytes([]byte{0x05}, 32)...), make([]byte, 7)...)
	got := AddressWords(data)
	if len(got) != 1 || got[0] != token {
		t.Fatalf("got %v: small integers must not be treated as addresses", got)
	}
	root := &models.DecodedCall{Kind: models.CallUnknown, Target: mc.Hex(), RawData: "0xdeadbeef" + common.Bytes2Hex(common.LeftPadBytes(other.Bytes(), 32))}
	roles := CollectAddresses(&models.Transaction{From: user, To: &mc}, root, nil, nil)
	if !roles[other][RoleParam] {
		t.Fatal("address arguments of undecoded calls must be collected")
	}
}
