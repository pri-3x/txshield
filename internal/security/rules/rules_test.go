package rules

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/txshield/txshield/internal/decoder"
	"github.com/txshield/txshield/internal/security/approvals"
	"github.com/txshield/txshield/internal/security/core"
	"github.com/txshield/txshield/pkg/interfaces"
	"github.com/txshield/txshield/pkg/models"
)

var (
	user     = common.HexToAddress("0x1111111111111111111111111111111111111111")
	attacker = common.HexToAddress("0x9999999999999999999999999999999999999999")
	usdc     = common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	dai      = common.HexToAddress("0x6B175474E89094C44Da98b954EedeAC495271d0F")
	weth     = common.HexToAddress("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
	router   = common.HexToAddress("0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD")
	pool     = common.HexToAddress("0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640")
	drainer  = common.HexToAddress("0xdeAD00000000000000000000000000000000dEaD")
	safe     = common.HexToAddress("0x5555555555555555555555555555555555555555")
)

func cd(t *testing.T, sig string, a ...any) []byte {
	t.Helper()
	m, err := decoder.ParseSignature(sig)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := m.Inputs.Pack(a...)
	if err != nil {
		t.Fatalf("pack %s: %v", sig, err)
	}
	return append(append([]byte{}, m.ID...), enc...)
}

type opt func(*interfaces.AnalysisContext)

func ctxFor(t *testing.T, to common.Address, value int64, data []byte, opts ...opt) *interfaces.AnalysisContext {
	t.Helper()
	tx := &models.Transaction{ChainID: 1, From: user, To: &to, Value: big.NewInt(value), Data: data}
	return build(t, tx, interfaces.DecodeOptions{}, opts...)
}

func build(t *testing.T, tx *models.Transaction, dopts interfaces.DecodeOptions, opts ...opt) *interfaces.AnalysisContext {
	t.Helper()
	dec, err := decoder.New(decoder.Builtin(), decoder.DefaultLimits).Decode(context.Background(), tx, dopts)
	if err != nil {
		t.Fatal(err)
	}
	ac := &interfaces.AnalysisContext{
		Tx: tx, Decoded: dec, Now: time.Unix(1_700_000_000, 0),
		Contracts: map[common.Address]*models.ContractInfo{}, Reputation: map[common.Address][]models.ReputationRecord{},
	}
	for _, o := range opts {
		o(ac)
	}
	ac.Approvals = approvals.Extract(tx, dec, ac.Contracts)
	return ac
}

func runAll(t *testing.T, ac *interfaces.AnalysisContext) map[string][]models.Finding {
	t.Helper()
	eng, err := NewEngine(time.Second, Default(Config{})...)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]models.Finding{}
	for _, r := range eng.Run(context.Background(), ac) {
		if r.Err != nil {
			t.Fatalf("%s failed: %v", r.RuleID, r.Err)
		}
		for _, f := range r.Findings {
			out[f.RuleID] = append(out[f.RuleID], f)
		}
	}
	return out
}

func has(t *testing.T, got map[string][]models.Finding, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if len(got[id]) == 0 {
			t.Errorf("expected %s; got %v", id, ruleIDs(got))
		}
	}
}

func lacks(t *testing.T, got map[string][]models.Finding, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if len(got[id]) > 0 {
			t.Errorf("unexpected %s: %s", id, got[id][0].Description)
		}
	}
}

func ruleIDs(m map[string][]models.Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func sim(transfers []models.AssetTransfer, balances []models.BalanceChange, trace *models.CallFrame) opt {
	return func(ac *interfaces.AnalysisContext) {
		ac.Simulation = &models.SimulationResult{Status: models.SimSuccess, Completeness: models.CompletenessFull, AssetTransfers: transfers, BalanceChanges: balances, Trace: trace, BlockNumber: 100}
	}
}

func erc20(tok, from, to common.Address, amt string) models.AssetTransfer {
	return models.AssetTransfer{Asset: models.AssetRef{Kind: models.AssetERC20, Address: tok.Hex()}, From: from.Hex(), To: to.Hex(), Amount: models.Quantity(amt)}
}

func list(status models.ReputationStatus, addrs ...common.Address) opt {
	return func(ac *interfaces.AnalysisContext) {
		ac.ReputationSources = []string{"list:team"}
		for _, a := range addrs {
			ac.Reputation[a] = []models.ReputationRecord{{Address: a.Hex(), Status: status, Source: "list:team", SourceKind: models.ReputationSourceList, Confidence: models.ConfidenceHigh, Reason: "test"}}
		}
	}
}

func code(addrs map[common.Address]bool) opt {
	return func(ac *interfaces.AnalysisContext) {
		ac.ContractsKnown = true
		for a, isContract := range addrs {
			ac.Contracts[a] = &models.ContractInfo{Address: a.Hex(), IsContract: isContract, AtBlock: 100}
		}
	}
}

// ---------------------------------------------------------------------------
// Engine

type stubRule struct {
	id   string
	eval func(context.Context) ([]models.Finding, error)
}

func (s stubRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{ID: s.id, Name: "n", Description: "d", Category: models.CategoryInteraction, Mitigation: "m", FalsePositiveNotes: "fp"}
}
func (s stubRule) Evaluate(ctx context.Context, _ *interfaces.AnalysisContext) ([]models.Finding, error) {
	return s.eval(ctx)
}

func TestEngineIsolation(t *testing.T) {
	ok := stubRule{"OK", func(context.Context) ([]models.Finding, error) {
		return []models.Finding{{RuleID: "SPOOFED", Title: "x"}}, nil
	}}
	panicky := stubRule{"PANIC", func(context.Context) ([]models.Finding, error) { panic("boom") }}
	slow := stubRule{"SLOW", func(context.Context) ([]models.Finding, error) {
		time.Sleep(500 * time.Millisecond)
		return []models.Finding{{Title: "late"}}, nil
	}}
	failing := stubRule{"FAIL", func(context.Context) ([]models.Finding, error) { return nil, errors.New("nope") }}
	many := stubRule{"MANY", func(context.Context) ([]models.Finding, error) {
		return make([]models.Finding, 500), nil
	}}
	eng, err := NewEngine(50*time.Millisecond, ok, panicky, slow, failing, many)
	if err != nil {
		t.Fatal(err)
	}
	res := eng.Run(context.Background(), &interfaces.AnalysisContext{})
	byID := map[string]interfaces.RuleResult{}
	for _, r := range res {
		byID[r.RuleID] = r
	}
	if r := byID["OK"]; r.Err != nil || len(r.Findings) != 1 || r.Findings[0].RuleID != "OK" || r.Findings[0].Fingerprint != "OK" {
		t.Fatalf("OK = %+v (rule IDs must not be spoofable)", r)
	}
	if r := byID["PANIC"]; r.Err == nil || !strings.Contains(r.Err.Error(), "panicked") {
		t.Fatalf("PANIC = %+v", r)
	}
	if r := byID["SLOW"]; !errors.Is(r.Err, ErrRuleTimeout) || r.Findings != nil {
		t.Fatalf("SLOW = %+v", r)
	}
	if r := byID["FAIL"]; r.Err == nil {
		t.Fatal("FAIL must report error")
	}
	if r := byID["MANY"]; len(r.Findings) != MaxFindingsPerRule {
		t.Fatalf("MANY = %d findings", len(r.Findings))
	}
	if res[0].RuleID != "OK" || res[4].RuleID != "MANY" {
		t.Fatal("results must keep registration order")
	}
}

func TestEngineValidation(t *testing.T) {
	nop := func(context.Context) ([]models.Finding, error) { return nil, nil }
	if _, err := NewEngine(time.Second, stubRule{"A", nop}, stubRule{"A", nop}); err == nil {
		t.Fatal("duplicate IDs must be rejected")
	}
	if _, err := NewEngine(time.Second, incomplete{}); err == nil {
		t.Fatal("incomplete metadata must be rejected")
	}
	eng, err := NewEngine(time.Second, Default(Config{})...)
	if err != nil {
		t.Fatalf("built-in rules invalid: %v", err)
	}
	if n := len(eng.Rules()); n != 29 {
		t.Fatalf("built-in rule count = %d", n)
	}
}

type incomplete struct{}

func (incomplete) Metadata() models.RuleMetadata { return models.RuleMetadata{ID: "X", Name: "x"} }
func (incomplete) Evaluate(context.Context, *interfaces.AnalysisContext) ([]models.Finding, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// Interaction

func TestBlocklistedTarget(t *testing.T) {
	got := runAll(t, ctxFor(t, drainer, 0, cd(t, "claim()"), list(models.ReputationBlocked, drainer)))
	has(t, got, "TXS-INTERACT-001")
	if f := got["TXS-INTERACT-001"][0]; f.Severity != models.SeverityCritical || f.Source != models.SourceFact || !strings.Contains(f.Description, "target") {
		t.Fatalf("%+v", f)
	}
}

func TestBlocklistedSpenderOnlyReportedOnce(t *testing.T) {
	got := runAll(t, ctxFor(t, usdc, 0, cd(t, "approve(address,uint256)", drainer, big.NewInt(1)), list(models.ReputationBlocked, drainer)))
	has(t, got, "TXS-APPROVAL-005")
	lacks(t, got, "TXS-INTERACT-001")
}

func TestSuspiciousRecipient(t *testing.T) {
	got := runAll(t, ctxFor(t, usdc, 0, cd(t, "transfer(address,uint256)", attacker, big.NewInt(1)), list(models.ReputationSuspicious, attacker)))
	has(t, got, "TXS-INTERACT-002")
}

func TestUnknownTarget(t *testing.T) {
	data := cd(t, "transfer(address,uint256)", attacker, big.NewInt(1))
	has(t, runAll(t, ctxFor(t, usdc, 0, data, list(models.ReputationBlocked))), "TXS-INTERACT-003")
	lacks(t, runAll(t, ctxFor(t, usdc, 0, data)), "TXS-INTERACT-003")                                    // no sources configured
	lacks(t, runAll(t, ctxFor(t, attacker, 5, nil, list(models.ReputationBlocked))), "TXS-INTERACT-003") // plain transfer
}

func TestUnverifiedAndCalldataToEOA(t *testing.T) {
	f := false
	unverified := func(ac *interfaces.AnalysisContext) {
		ac.ContractsKnown = true
		ac.Contracts[usdc] = &models.ContractInfo{IsContract: true, Verified: &f}
	}
	has(t, runAll(t, ctxFor(t, usdc, 0, cd(t, "transfer(address,uint256)", attacker, big.NewInt(1)), unverified)), "TXS-INTERACT-004")

	eoa := code(map[common.Address]bool{attacker: false})
	has(t, runAll(t, ctxFor(t, attacker, 0, []byte{1, 2, 3, 4}, eoa)), "TXS-INTERACT-005")
	lacks(t, runAll(t, ctxFor(t, attacker, 1, nil, eoa)), "TXS-INTERACT-005") // plain ETH transfer
}

func TestUnexpectedTraceCalls(t *testing.T) {
	trace := &models.CallFrame{Type: "CALL", From: user.Hex(), To: router.Hex(), Calls: []models.CallFrame{
		{Type: "CALL", From: router.Hex(), To: pool.Hex()},
		{Type: "STATICCALL", From: router.Hex(), To: attacker.Hex()},
		{Type: "STATICCALL", From: router.Hex(), To: "0x0000000000000000000000000000000000000001"},
		{Type: "CALL", From: router.Hex(), To: "0x0000000000000000000000000000000000000002"},
	}}
	got := runAll(t, ctxFor(t, router, 0, cd(t, "refundETH()"), sim(nil, nil, trace)))
	has(t, got, "TXS-INTERACT-006")
	f := got["TXS-INTERACT-006"][0]
	if f.Severity != models.SeverityInfo || len(f.Subjects) != 1 || f.Subjects[0] != pool.Hex() {
		t.Fatalf("%+v", f)
	}
}

// ---------------------------------------------------------------------------
// Value transfer

func TestDrainerClaim(t *testing.T) {
	transfers := []models.AssetTransfer{
		erc20(usdc, user, attacker, "1000"),
		erc20(dai, user, attacker, "5"),
		{Asset: models.AssetRef{Kind: models.AssetERC721, Address: pool.Hex(), TokenID: "7"}, From: user.Hex(), To: attacker.Hex(), Amount: "1"},
	}
	balances := []models.BalanceChange{{Owner: user.Hex(), Asset: models.AssetRef{Kind: models.AssetERC20, Address: usdc.Hex()}, Before: "1000", After: "0", Delta: "-1000"}}
	got := runAll(t, ctxFor(t, drainer, 1e15, cd(t, "claim()"), sim(transfers, balances, nil)))
	has(t, got, "TXS-VALUE-001", "TXS-VALUE-002", "TXS-VALUE-003", "TXS-VALUE-004", "TXS-VALUE-005")
	if len(got["TXS-VALUE-001"]) != 3 {
		t.Fatalf("each unexpected asset should be reported: %d", len(got["TXS-VALUE-001"]))
	}
	if got["TXS-VALUE-004"][0].Confidence != models.ConfidenceLow {
		t.Fatal("value to unrecognized function must be low confidence")
	}
}

// The call's value shows up both as tx.value and as a simulated native
// transfer from the sender; the net-loss finding must list it once.
func TestNetLossCountsNativeOnce(t *testing.T) {
	transfers := []models.AssetTransfer{
		{Asset: models.AssetRef{Kind: models.AssetNative}, From: user.Hex(), To: drainer.Hex(), Amount: "1000000000000000"},
		erc20(usdc, user, attacker, "1000"),
	}
	got := runAll(t, ctxFor(t, drainer, 1e15, cd(t, "claim()"), sim(transfers, nil, nil)))
	d := got["TXS-VALUE-003"][0].Description
	if n := strings.Count(d, "native"); n != 1 {
		t.Fatalf("native listed %d times: %s", n, d)
	}
	// Value sent with no simulated native transfer is still listed.
	got = runAll(t, ctxFor(t, drainer, 1e15, cd(t, "claim()"), sim([]models.AssetTransfer{erc20(usdc, user, attacker, "1000")}, nil, nil)))
	if d := got["TXS-VALUE-003"][0].Description; !strings.Contains(d, "1000000000000000 wei of native currency") {
		t.Fatalf("missing native: %s", d)
	}
}

func TestFalsePositive_SwapThroughPool(t *testing.T) {
	// UR V3 swap: USDC goes to a pool that is not in calldata, WETH comes back.
	path := append(append(usdc.Bytes(), 0x00, 0x01, 0xf4), weth.Bytes()...)
	in := mustArgs(t, "f(address recipient, uint256 amountIn, uint256 amountOutMin, bytes path, bool payerIsUser)", user, big.NewInt(1000), big.NewInt(1), path, true)
	data := cd(t, "execute(bytes commands, bytes[] inputs)", []byte{0x00}, [][]byte{in})
	transfers := []models.AssetTransfer{erc20(usdc, user, pool, "1000"), erc20(weth, pool, user, "1")}
	got := runAll(t, ctxFor(t, router, 0, data, sim(transfers, nil, nil)))
	lacks(t, got, "TXS-VALUE-001", "TXS-VALUE-002", "TXS-VALUE-003")
}

func TestFalsePositive_ExplicitTransfer(t *testing.T) {
	got := runAll(t, ctxFor(t, usdc, 0, cd(t, "transfer(address,uint256)", attacker, big.NewInt(10)),
		sim([]models.AssetTransfer{erc20(usdc, user, attacker, "10")}, nil, nil)))
	lacks(t, got, "TXS-VALUE-001", "TXS-VALUE-003")
}

func TestRevertSilencesValueRules(t *testing.T) {
	reverted := func(ac *interfaces.AnalysisContext) {
		ac.Simulation = &models.SimulationResult{Status: models.SimReverted, Completeness: models.CompletenessFull, RevertReason: "nope\n\x1b[31mfake", BlockNumber: 5,
			AssetTransfers: []models.AssetTransfer{erc20(usdc, user, attacker, "1")}}
	}
	got := runAll(t, ctxFor(t, drainer, 0, cd(t, "claim()"), reverted))
	has(t, got, "TXS-SIM-001")
	lacks(t, got, "TXS-VALUE-001", "TXS-VALUE-003")
	if d := got["TXS-SIM-001"][0].Description; strings.ContainsAny(d, "\n\x1b") {
		t.Fatalf("revert reason not sanitized: %q", d)
	}
}

func TestValueToNonPayable(t *testing.T) {
	got := runAll(t, ctxFor(t, usdc, 1, cd(t, "approve(address,uint256)", attacker, big.NewInt(1))))
	has(t, got, "TXS-VALUE-004")
	if got["TXS-VALUE-004"][0].Confidence != models.ConfidenceHigh {
		t.Fatal("known non-payable must be high confidence")
	}
	lacks(t, runAll(t, ctxFor(t, router, 1, cd(t, "swapExactETHForTokens(uint256,address[],address,uint256)", big.NewInt(1), []common.Address{weth, usdc}, user, big.NewInt(1)))), "TXS-VALUE-004")
	// Contract creation with value must not crash.
	tx := &models.Transaction{ChainID: 1, From: user, Value: big.NewInt(1), Data: []byte{0x60, 0x80}}
	runAll(t, build(t, tx, interfaces.DecodeOptions{}))
}

// ---------------------------------------------------------------------------
// Patterns

func TestSafeDelegatecall(t *testing.T) {
	data := cd(t, "execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures)",
		attacker, big.NewInt(0), []byte{}, uint8(1), big.NewInt(0), big.NewInt(0), big.NewInt(0), common.Address{}, common.Address{}, make([]byte, 65))
	got := runAll(t, ctxFor(t, safe, 0, data))
	has(t, got, "TXS-PATTERN-001")
	if got["TXS-PATTERN-001"][0].Severity != models.SeverityHigh {
		t.Fatal("severity")
	}
}

func TestTraceDelegatecall(t *testing.T) {
	impl := common.HexToAddress("0x4444444444444444444444444444444444444444")
	trace := &models.CallFrame{Type: "CALL", From: user.Hex(), To: usdc.Hex(), Calls: []models.CallFrame{
		{Type: "DELEGATECALL", From: usdc.Hex(), To: impl.Hex()},
	}}
	proxy := func(ac *interfaces.AnalysisContext) {
		ac.ContractsKnown = true
		ac.Contracts[usdc] = &models.ContractInfo{IsContract: true, IsProxy: true, Implementation: impl.Hex()}
	}
	data := cd(t, "transfer(address,uint256)", attacker, big.NewInt(1))
	lacks(t, runAll(t, ctxFor(t, usdc, 0, data, proxy, sim(nil, nil, trace))), "TXS-PATTERN-001")

	// Delegatecall into an address that is neither the implementation nor
	// mentioned in calldata: weak signal.
	trace.Calls[0].To = drainer.Hex()
	got := runAll(t, ctxFor(t, usdc, 0, data, proxy, sim(nil, nil, trace)))
	has(t, got, "TXS-PATTERN-001")
	if got["TXS-PATTERN-001"][0].Severity != models.SeverityLow {
		t.Fatal("trace-only delegatecall is a weak signal")
	}

	// Delegatecall into an address the caller supplied in calldata: arbitrary
	// delegatecall, high severity.
	trace.Calls[0].To = attacker.Hex() // attacker is the transfer recipient in data
	got = runAll(t, ctxFor(t, usdc, 0, data, proxy, sim(nil, nil, trace)))
	if f := got["TXS-PATTERN-001"]; len(f) != 1 || f[0].Severity != models.SeverityHigh || f[0].Confidence != models.ConfidenceMedium {
		t.Fatalf("calldata-supplied delegatecall target: %+v", f)
	}
}

func TestOwnershipUpgradeBatch(t *testing.T) {
	has(t, runAll(t, ctxFor(t, usdc, 0, cd(t, "transferOwnership(address)", attacker))), "TXS-PATTERN-004")
	has(t, runAll(t, ctxFor(t, usdc, 0, cd(t, "renounceOwnership()"))), "TXS-PATTERN-004")
	has(t, runAll(t, ctxFor(t, usdc, 0, cd(t, "upgradeTo(address)", attacker))), "TXS-PATTERN-005")
	batch := cd(t, "multicall(bytes[])", [][]byte{cd(t, "refundETH()"), cd(t, "refundETH()")})
	has(t, runAll(t, ctxFor(t, router, 0, batch)), "TXS-PATTERN-003")
	lacks(t, runAll(t, ctxFor(t, router, 0, cd(t, "multicall(bytes[])", [][]byte{cd(t, "refundETH()")}))), "TXS-PATTERN-003")
}

func TestSelfdestructAndReentrancy(t *testing.T) {
	trace := &models.CallFrame{Type: "CALL", From: user.Hex(), To: router.Hex(), Calls: []models.CallFrame{
		{Type: "CALL", From: router.Hex(), To: pool.Hex(), Calls: []models.CallFrame{
			{Type: "CALL", From: pool.Hex(), To: router.Hex()}, // callback re-enters router
		}},
		{Type: "SELFDESTRUCT", From: pool.Hex(), To: attacker.Hex(), Value: "5"},
	}}
	got := runAll(t, ctxFor(t, router, 0, cd(t, "refundETH()"), sim(nil, nil, trace)))
	has(t, got, "TXS-PATTERN-006", "TXS-PATTERN-010")
	if got["TXS-PATTERN-010"][0].Severity != models.SeverityInfo {
		t.Fatal("re-entrancy is informational")
	}
}

func TestFlashLoan(t *testing.T) {
	has(t, runAll(t, ctxFor(t, pool, 0, cd(t, "flashLoanSimple(address,address,uint256,bytes,uint16)", user, usdc, big.NewInt(1), []byte{}, uint16(0)))), "TXS-PATTERN-007")
	lacks(t, runAll(t, ctxFor(t, pool, 0, cd(t, "swap(uint256,uint256,address,bytes)", big.NewInt(1), big.NewInt(0), user, []byte{}))), "TXS-PATTERN-007")
	has(t, runAll(t, ctxFor(t, pool, 0, cd(t, "swap(uint256,uint256,address,bytes)", big.NewInt(1), big.NewInt(0), user, []byte{1}))), "TXS-PATTERN-007")
}

const execABI = `[{"type":"function","name":"execute","inputs":[{"name":"target","type":"address"},{"name":"data","type":"bytes"}],"outputs":[],"stateMutability":"nonpayable"}]`

func TestEmbeddedTransferFrom(t *testing.T) {
	steal := cd(t, "transferFrom(address,address,uint256)", user, attacker, big.NewInt(1000))
	// Known ABI: embedded call visible as a bytes parameter.
	tx := &models.Transaction{ChainID: 1, From: user, To: &drainer, Value: new(big.Int), Data: cd(t, "execute(address target, bytes data)", usdc, steal)}
	got := runAll(t, build(t, tx, interfaces.DecodeOptions{ABIJSON: []byte(execABI)}))
	has(t, got, "TXS-PATTERN-008")
	if got["TXS-PATTERN-008"][0].Confidence != models.ConfidenceHigh {
		t.Fatal("embedded transferFrom of the sender's tokens must be high confidence")
	}
	// Unknown ABI: found by scanning raw ABI words.
	got = runAll(t, ctxFor(t, drainer, 0, cd(t, "x(address target, bytes data)", usdc, steal)))
	has(t, got, "TXS-PATTERN-008")

	// False positive guard: ERC-1155 transfer with empty data.
	lacks(t, runAll(t, ctxFor(t, pool, 0, cd(t, "safeTransferFrom(address,address,uint256,uint256,bytes)", user, attacker, big.NewInt(1), big.NewInt(1), []byte{}))), "TXS-PATTERN-008")
}

func TestTrailingDataAndSignedPermit(t *testing.T) {
	data := append(cd(t, "transfer(address,uint256)", attacker, big.NewInt(1)), 0xab, 0xcd)
	has(t, runAll(t, ctxFor(t, usdc, 0, data)), "TXS-PATTERN-009")
	permit := cd(t, "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)", user, router, big.NewInt(5), big.NewInt(1), uint8(27), [32]byte{}, [32]byte{})
	has(t, runAll(t, ctxFor(t, usdc, 0, permit)), "TXS-PATTERN-002")
}

func TestScanABIWordsBounds(t *testing.T) {
	// Length words pointing past the end must be ignored without panicking.
	buf := make([]byte, 96)
	buf[31] = 0xff
	if len(scanABIWords(buf)) != 0 {
		t.Fatal("out-of-range length accepted")
	}
	for n := 0; n < 200; n++ {
		scanABIWords(make([]byte, n))
	}
}

func mustArgs(t *testing.T, sig string, a ...any) []byte {
	t.Helper()
	full := cd(t, sig, a...)
	return full[4:]
}

func TestFingerprintsStable(t *testing.T) {
	f1 := core.NewFinding(unexpectedOutflowRule{}.Metadata(), "ERC20:0xAbC", "0xDEF")
	f2 := core.NewFinding(unexpectedOutflowRule{}.Metadata(), "erc20:0xabc", "0xdef")
	if f1.Fingerprint != f2.Fingerprint || f1.Fingerprint != fmt.Sprintf("%s:erc20:0xabc|0xdef", "TXS-VALUE-001") {
		t.Fatalf("%s vs %s", f1.Fingerprint, f2.Fingerprint)
	}
}

// TestRuleCatalogDocumented keeps docs/security-rules.md in sync with code.
func TestRuleCatalogDocumented(t *testing.T) {
	doc, err := os.ReadFile("../../../docs/security-rules.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range Default(Config{}) {
		if id := r.Metadata().ID; !strings.Contains(string(doc), "| "+id+" |") {
			t.Errorf("%s missing from docs/security-rules.md", id)
		}
	}
}

// Each slow rule costs only its own result: rules after it still run on a
// fresh worker, and a second slow rule times out independently.
func TestEngineRecoversAfterEachTimeout(t *testing.T) {
	sleepy := func(id string) stubRule {
		return stubRule{id, func(ctx context.Context) ([]models.Finding, error) {
			select {
			case <-time.After(time.Second):
			case <-ctx.Done(): // abandoned workers are cancelled
			}
			return []models.Finding{{Title: "late"}}, nil
		}}
	}
	hit := func(id string) stubRule {
		return stubRule{id, func(context.Context) ([]models.Finding, error) { return []models.Finding{{Title: id}}, nil }}
	}
	eng, err := NewEngine(30*time.Millisecond, hit("A"), sleepy("S1"), hit("B"), sleepy("S2"), hit("C"))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	res := eng.Run(context.Background(), &interfaces.AnalysisContext{})
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("Run took %v", d)
	}
	want := map[string]bool{"A": true, "S1": false, "B": true, "S2": false, "C": true}
	for i, r := range res {
		if r.RuleID != []string{"A", "S1", "B", "S2", "C"}[i] {
			t.Fatalf("order: %d = %s", i, r.RuleID)
		}
		if ok := want[r.RuleID]; ok != (r.Err == nil && len(r.Findings) == 1) {
			t.Errorf("%s: err=%v findings=%d", r.RuleID, r.Err, len(r.Findings))
		}
		if !want[r.RuleID] && !errors.Is(r.Err, ErrRuleTimeout) {
			t.Errorf("%s: want timeout, got %v", r.RuleID, r.Err)
		}
	}
}

func TestEngineCallerCancellation(t *testing.T) {
	block := stubRule{"BLOCK", func(ctx context.Context) ([]models.Finding, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	after := stubRule{"AFTER", func(context.Context) ([]models.Finding, error) { return nil, nil }}
	eng, err := NewEngine(time.Minute, block, after)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	res := eng.Run(ctx, &interfaces.AnalysisContext{})
	if len(res) != 2 || res[0].Err == nil || res[1].Err == nil {
		t.Fatalf("cancelled run must mark unfinished rules: %+v", res)
	}
}
