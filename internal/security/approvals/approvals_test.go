package approvals

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/pri-3x/txshield/internal/decoder"
	"github.com/pri-3x/txshield/internal/security/core"
	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
)

var (
	user      = common.HexToAddress("0x1111111111111111111111111111111111111111")
	spender   = common.HexToAddress("0x2222222222222222222222222222222222222222")
	token     = common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	nft       = common.HexToAddress("0x57f1887a8BF19b14fC0dF6Fd9B2acc9Af147eA85")
	permit2   = common.HexToAddress("0x000000000022D473030F116dDEE9F6B43aC78BA3")
	multicall = common.HexToAddress("0xcA11bde05977b3631167028862bE2a173976CA11")
	safe      = common.HexToAddress("0x5555555555555555555555555555555555555555")
	router    = common.HexToAddress("0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD")
)

func cd(t *testing.T, sig string, args ...any) []byte {
	t.Helper()
	m, err := decoder.ParseSignature(sig)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := m.Inputs.Pack(args...)
	if err != nil {
		t.Fatalf("pack %s: %v", sig, err)
	}
	return append(append([]byte{}, m.ID...), enc...)
}

func args(t *testing.T, sig string, a ...any) []byte {
	t.Helper()
	m, err := decoder.ParseSignature(sig)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := m.Inputs.Pack(a...)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// analysis decodes data sent by user to `to` and returns a ready context.
func analysis(t *testing.T, to common.Address, data []byte, mutate ...func(*interfaces.AnalysisContext)) *interfaces.AnalysisContext {
	t.Helper()
	tx := &models.Transaction{ChainID: 1, From: user, To: &to, Value: new(big.Int), Data: data}
	dec, err := decoder.New(decoder.Builtin(), decoder.DefaultLimits).Decode(context.Background(), tx, interfaces.DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ac := &interfaces.AnalysisContext{Tx: tx, Decoded: dec, Now: time.Unix(1_700_000_000, 0), Contracts: map[common.Address]*models.ContractInfo{}, Reputation: map[common.Address][]models.ReputationRecord{}}
	for _, m := range mutate {
		m(ac)
	}
	ac.Approvals = Extract(tx, dec, ac.Contracts)
	return ac
}

func run(t *testing.T, ac *interfaces.AnalysisContext) map[string][]models.Finding {
	t.Helper()
	out := map[string][]models.Finding{}
	for _, r := range Rules(Config{}) {
		fs, err := r.Evaluate(context.Background(), ac)
		if err != nil {
			t.Fatalf("%s: %v", r.Metadata().ID, err)
		}
		for _, f := range fs {
			if f.RuleID != r.Metadata().ID || f.Fingerprint == "" || f.Mitigation == "" {
				t.Fatalf("malformed finding %+v", f)
			}
			out[f.RuleID] = append(out[f.RuleID], f)
		}
	}
	return out
}

func only(t *testing.T, got map[string][]models.Finding, ids ...string) {
	t.Helper()
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
		if len(got[id]) == 0 {
			t.Errorf("expected %s, got %v", id, keys(got))
		}
	}
	for id := range got {
		if !want[id] {
			t.Errorf("unexpected %s: %+v", id, got[id])
		}
	}
}

func keys(m map[string][]models.Finding) []string {
	var k []string
	for id := range m {
		k = append(k, id)
	}
	return k
}

func withStandard(addr common.Address, std string) func(*interfaces.AnalysisContext) {
	return func(ac *interfaces.AnalysisContext) {
		ac.Contracts[addr] = &models.ContractInfo{Address: addr.Hex(), IsContract: true, Standards: []string{std}}
		ac.ContractsKnown = true
	}
}

func TestUnlimitedERC20Approval(t *testing.T) {
	data := cd(t, "approve(address,uint256)", spender, core.MaxUint256)

	// Standard unresolved (offline): reported with medium confidence.
	ac := analysis(t, token, data)
	if len(ac.Approvals) != 1 || ac.Approvals[0].Kind != models.ApprovalAmbiguous || !ac.Approvals[0].OwnerIsSender || !ac.Approvals[0].Unlimited {
		t.Fatalf("grants = %+v", ac.Approvals)
	}
	got := run(t, ac)
	only(t, got, "TXS-APPROVAL-001")
	if got["TXS-APPROVAL-001"][0].Confidence != models.ConfidenceMedium {
		t.Fatal("unresolved standard must lower confidence")
	}

	// Resolved ERC-20: high confidence.
	got = run(t, analysis(t, token, data, withStandard(token, "erc20")))
	if got["TXS-APPROVAL-001"][0].Confidence != models.ConfidenceHigh {
		t.Fatal("resolved ERC-20 should be high confidence")
	}
}

func TestFalsePositive_NFTApproveWithHugeTokenID(t *testing.T) {
	// ENS token IDs are keccak hashes: approve(spender, 2^255+x) on an ERC-721
	// is a single-token approval, not an "unlimited allowance".
	id, _ := new(big.Int).SetString("90000000000000000000000000000000000000000000000000000000000000000000000000000", 10)
	ac := analysis(t, nft, cd(t, "approve(address,uint256)", spender, id), withStandard(nft, "erc721"))
	if ac.Approvals[0].Kind != models.ApprovalNFTToken || ac.Approvals[0].TokenID == "" {
		t.Fatalf("grant = %+v", ac.Approvals[0])
	}
	only(t, run(t, ac))
}

func TestFalsePositive_Revocations(t *testing.T) {
	for name, data := range map[string][]byte{
		"erc20 approve 0":         cd(t, "approve(address,uint256)", spender, big.NewInt(0)),
		"setApprovalForAll false": cd(t, "setApprovalForAll(address,bool)", spender, false),
	} {
		ac := analysis(t, token, data)
		if len(ac.Approvals) != 1 || !ac.Approvals[0].Revocation {
			t.Fatalf("%s: grants = %+v", name, ac.Approvals)
		}
		only(t, run(t, ac))
	}
}

func TestFalsePositive_ExactAmountApproval(t *testing.T) {
	only(t, run(t, analysis(t, token, cd(t, "approve(address,uint256)", spender, big.NewInt(1_000_000)), withStandard(token, "erc20"))))
}

func TestVeryLargeAllowance(t *testing.T) {
	amt := new(big.Int).Lsh(big.NewInt(1), 200)
	got := run(t, analysis(t, token, cd(t, "approve(address,uint256)", spender, amt), withStandard(token, "erc20")))
	only(t, got, "TXS-APPROVAL-002")
	if got["TXS-APPROVAL-002"][0].Source != models.SourceHeuristic {
		t.Fatal("threshold-based finding must be labeled heuristic")
	}
}

func TestOperatorApproval(t *testing.T) {
	got := run(t, analysis(t, nft, cd(t, "setApprovalForAll(address,bool)", spender, true)))
	only(t, got, "TXS-APPROVAL-003")
	if got["TXS-APPROVAL-003"][0].Severity != models.SeverityHigh {
		t.Fatal("severity")
	}
}

func TestIntermediaryApprovalNotScored(t *testing.T) {
	type call struct {
		Target   common.Address
		CallData []byte
	}
	data := cd(t, "aggregate((address target, bytes callData)[] calls)", []call{{token, cd(t, "approve(address,uint256)", spender, core.MaxUint256)}})
	ac := analysis(t, multicall, data)
	if len(ac.Approvals) != 1 || ac.Approvals[0].Owner != multicall.Hex() || ac.Approvals[0].OwnerIsSender {
		t.Fatalf("owner must be the Multicall3 contract: %+v", ac.Approvals)
	}
	only(t, run(t, ac))
}

func TestSelfMulticallApprovalIsSenders(t *testing.T) {
	data := cd(t, "multicall(bytes[])", [][]byte{cd(t, "approve(address,uint256)", spender, core.MaxUint256)})
	ac := analysis(t, token, data)
	if len(ac.Approvals) != 1 || !ac.Approvals[0].OwnerIsSender || ac.Approvals[0].Token != token.Hex() {
		t.Fatalf("%+v", ac.Approvals)
	}
	only(t, run(t, ac), "TXS-APPROVAL-001")
}

func TestSafeApprovalCountsAsSenders(t *testing.T) {
	inner := cd(t, "approve(address,uint256)", spender, core.MaxUint256)
	data := cd(t, "execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures)",
		token, big.NewInt(0), inner, uint8(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), common.Address{}, common.Address{}, make([]byte, 65))
	ac := analysis(t, safe, data)
	if len(ac.Approvals) != 1 || ac.Approvals[0].Owner != safe.Hex() {
		t.Fatalf("%+v", ac.Approvals)
	}
	only(t, run(t, ac), "TXS-APPROVAL-001")
}

func TestPermit2ApproveUnlimitedLongExpiry(t *testing.T) {
	far := big.NewInt(1_700_000_000 + 365*24*3600)
	got := run(t, analysis(t, permit2, cd(t, "approve(address,address,uint160,uint48)", token, spender, core.MaxUint160, far)))
	only(t, got, "TXS-APPROVAL-001", "TXS-APPROVAL-007")

	// Short expiry and bounded amount: nothing to report.
	soon := big.NewInt(1_700_000_000 + 3600)
	only(t, run(t, analysis(t, permit2, cd(t, "approve(address,address,uint160,uint48)", token, spender, big.NewInt(5), soon))))
}

type details struct {
	Token      common.Address
	Amount     *big.Int
	Expiration *big.Int
	Nonce      *big.Int
}

func TestPermit2SignedBatch(t *testing.T) {
	type batch struct {
		Details     []details
		Spender     common.Address
		SigDeadline *big.Int
	}
	other := common.HexToAddress("0x6B175474E89094C44Da98b954EedeAC495271d0F")
	data := cd(t, "permit(address owner, ((address token, uint160 amount, uint48 expiration, uint48 nonce)[] details, address spender, uint256 sigDeadline) permitBatch, bytes signature)",
		user, batch{[]details{{token, core.MaxUint160, big.NewInt(1), big.NewInt(0)}, {other, big.NewInt(10), big.NewInt(1), big.NewInt(0)}}, spender, big.NewInt(1)}, make([]byte, 65))
	ac := analysis(t, permit2, data)
	if len(ac.Approvals) != 2 || !ac.Approvals[0].Signed || ac.Approvals[1].Token != other.Hex() || !ac.Approvals[0].Unlimited {
		t.Fatalf("%+v", ac.Approvals)
	}
	only(t, run(t, ac), "TXS-APPROVAL-001")
}

func TestUniversalRouterPermit2Permit(t *testing.T) {
	type single struct {
		Details     details
		Spender     common.Address
		SigDeadline *big.Int
	}
	permit := args(t, "f(((address token, uint160 amount, uint48 expiration, uint48 nonce) details, address spender, uint256 sigDeadline) permitSingle, bytes signature)",
		single{details{token, core.MaxUint160, big.NewInt(1_800_000_000), big.NewInt(0)}, router, big.NewInt(1)}, make([]byte, 65))
	data := cd(t, "execute(bytes commands, bytes[] inputs)", []byte{0x0a}, [][]byte{permit})
	ac := analysis(t, router, data)
	if len(ac.Approvals) != 1 || ac.Approvals[0].Owner != user.Hex() || ac.Approvals[0].Kind != models.ApprovalPermit2Signed || ac.Approvals[0].Spender != router.Hex() {
		t.Fatalf("%+v", ac.Approvals)
	}
	only(t, run(t, ac), "TXS-APPROVAL-001", "TXS-APPROVAL-007")
}

func TestEIP2612PermitForSomeoneElse(t *testing.T) {
	other := common.HexToAddress("0x7777777777777777777777777777777777777777")
	data := cd(t, "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)", other, spender, core.MaxUint256, big.NewInt(1), uint8(27), [32]byte{}, [32]byte{})
	ac := analysis(t, token, data)
	if ac.Approvals[0].OwnerIsSender || !ac.Approvals[0].Signed {
		t.Fatalf("%+v", ac.Approvals)
	}
	// Relaying another account's permit does not expose the sender's assets.
	only(t, run(t, ac))
}

func TestDAIPermitAllowed(t *testing.T) {
	data := cd(t, "permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)", user, spender, big.NewInt(0), big.NewInt(0), true, uint8(27), [32]byte{}, [32]byte{})
	ac := analysis(t, token, data)
	if !ac.Approvals[0].Unlimited || ac.Approvals[0].Expiration != nil {
		t.Fatalf("%+v", ac.Approvals[0])
	}
	only(t, run(t, ac), "TXS-APPROVAL-001")
}

func TestEOASpender(t *testing.T) {
	data := cd(t, "approve(address,uint256)", spender, big.NewInt(5))
	eoa := func(ac *interfaces.AnalysisContext) {
		ac.Contracts[spender] = &models.ContractInfo{Address: spender.Hex(), IsContract: false, AtBlock: 100}
		ac.ContractsKnown = true
	}
	only(t, run(t, analysis(t, token, data, eoa)), "TXS-APPROVAL-004")
	// Without chain facts, stay silent.
	only(t, run(t, analysis(t, token, data)))
}

func TestFlaggedAndUnknownSpender(t *testing.T) {
	data := cd(t, "approve(address,uint256)", spender, big.NewInt(5))
	blocked := func(ac *interfaces.AnalysisContext) {
		ac.ReputationSources = []string{"list:team"}
		ac.Reputation[spender] = []models.ReputationRecord{{Address: spender.Hex(), Status: models.ReputationBlocked, Source: "list:team", SourceKind: models.ReputationSourceList, Confidence: models.ConfidenceHigh}}
	}
	got := run(t, analysis(t, token, data, blocked))
	only(t, got, "TXS-APPROVAL-005")
	f := got["TXS-APPROVAL-005"][0]
	if f.Severity != models.SeverityCritical || f.Source != models.SourceFact || f.Confidence != models.ConfidenceHigh {
		t.Fatalf("%+v", f)
	}

	suspicious := func(ac *interfaces.AnalysisContext) {
		ac.ReputationSources = []string{"provider:x"}
		ac.Reputation[spender] = []models.ReputationRecord{{Status: models.ReputationSuspicious, Source: "provider:x", SourceKind: models.ReputationSourceExternal, Confidence: models.ConfidenceMedium}}
	}
	f = run(t, analysis(t, token, data, suspicious))["TXS-APPROVAL-005"][0]
	if f.Severity != models.SeverityHigh || f.Source != models.SourceExternal || f.Confidence != models.ConfidenceMedium {
		t.Fatalf("%+v", f)
	}

	// Operator allowlist overrides external opinion.
	allowed := func(ac *interfaces.AnalysisContext) {
		suspicious(ac)
		ac.Reputation[spender] = append(ac.Reputation[spender], models.ReputationRecord{Status: models.ReputationAllowed, Source: "list:team", SourceKind: models.ReputationSourceList})
	}
	only(t, run(t, analysis(t, token, data, allowed)))

	unknown := func(ac *interfaces.AnalysisContext) { ac.ReputationSources = []string{"list:team"} }
	only(t, run(t, analysis(t, token, data, unknown)), "TXS-APPROVAL-006")
}
