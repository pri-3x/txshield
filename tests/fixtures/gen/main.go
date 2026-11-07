// Command gen regenerates the scenario fixtures in tests/fixtures/scenarios.
//
//	go run ./tests/fixtures/gen
//
// All addresses, balances, and simulation results are synthetic.
package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/txshield/txshield/internal/decoder"
	"github.com/txshield/txshield/pkg/models"
	"github.com/txshield/txshield/tests/fixtures"
)

var (
	user     = common.HexToAddress("0x1111111111111111111111111111111111111111")
	attacker = common.HexToAddress("0x9999999999999999999999999999999999999999")
	drainer  = common.HexToAddress("0xdEAD000000000000000000000000000000000001")
	usdc     = common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	dai      = common.HexToAddress("0x6B175474E89094C44Da98b954EedeAC495271d0F")
	weth     = common.HexToAddress("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
	nft      = common.HexToAddress("0x57f1887a8BF19b14fC0dF6Fd9B2acc9Af147eA85")
	router   = common.HexToAddress("0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD")
	uniV2    = common.HexToAddress("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D")
	pool     = common.HexToAddress("0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640")
	mc3      = common.HexToAddress("0xcA11bde05977b3631167028862bE2a173976CA11")
	safe     = common.HexToAddress("0x5555555555555555555555555555555555555555")
	lib      = common.HexToAddress("0x6666666666666666666666666666666666666666")
	impl     = common.HexToAddress("0x4444444444444444444444444444444444444444")
	aave     = common.HexToAddress("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2")

	maxU256  = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	maxU160  = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 160), big.NewInt(1))
	year2100 = big.NewInt(4102444800)
)

func cd(sig string, args ...any) string {
	m, err := decoder.ParseSignature(sig)
	if err != nil {
		panic(err)
	}
	enc, err := m.Inputs.Pack(args...)
	if err != nil {
		panic(fmt.Sprintf("%s: %v", sig, err))
	}
	return hexutil.Encode(append(append([]byte{}, m.ID...), enc...))
}

func raw(sig string, args ...any) []byte {
	b, _ := hexutil.Decode(cd(sig, args...))
	return b[4:]
}

func bytesOf(h string) []byte { b, _ := hexutil.Decode(h); return b }

func tx(to common.Address, value, data string) models.TransactionRequest {
	return models.TransactionRequest{ChainID: 1, From: user.Hex(), To: to.Hex(), Value: models.Quantity(value), Data: data}
}

func contract(a common.Address, standards ...string) models.ContractInfo {
	return models.ContractInfo{ChainID: 1, Address: a.Hex(), IsContract: true, CodeSize: 1000, Standards: standards, AtBlock: 19000000}
}

func eoa(a common.Address) models.ContractInfo {
	return models.ContractInfo{ChainID: 1, Address: a.Hex(), IsContract: false, AtBlock: 19000000}
}

func rep(a common.Address, s models.ReputationStatus) models.ReputationRecord {
	return models.ReputationRecord{ChainID: 1, Address: a.Hex(), Status: s, Reason: "fixture record", Confidence: models.ConfidenceHigh}
}

func success(transfers []models.AssetTransfer, balances []models.BalanceChange, trace *models.CallFrame) *models.SimulationResult {
	return &models.SimulationResult{Backend: "fixture", Status: models.SimSuccess, Completeness: models.CompletenessFull, ChainID: 1, BlockNumber: 19000000, GasUsed: 100000, AssetTransfers: transfers, BalanceChanges: balances, Trace: trace}
}

func xfer(kind models.AssetKind, token, from, to common.Address, amt string) models.AssetTransfer {
	return models.AssetTransfer{Asset: models.AssetRef{Kind: kind, Address: token.Hex()}, From: from.Hex(), To: to.Hex(), Amount: models.Quantity(amt)}
}

type details struct {
	Token      common.Address
	Amount     *big.Int
	Expiration *big.Int
	Nonce      *big.Int
}

func scenarios() []fixtures.Scenario {
	safeExec := func(to common.Address, data []byte, op uint8) string {
		return cd("execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures)",
			to, big.NewInt(0), data, op, big.NewInt(0), big.NewInt(0), big.NewInt(0), common.Address{}, common.Address{}, make([]byte, 65))
	}
	type mcCall struct {
		Target   common.Address
		CallData []byte
	}
	type single struct {
		Details     details
		Spender     common.Address
		SigDeadline *big.Int
	}
	v3path := append(append(append([]byte{}, usdc.Bytes()...), 0x00, 0x01, 0xf4), weth.Bytes()...)

	return []fixtures.Scenario{
		// ------------------------------------------------------------ malicious
		{
			Name: "malicious-unlimited-approval-blocklisted-spender", Kind: "malicious",
			Description: "Unlimited USDC approval to a spender on the operator blocklist.",
			Tx:          tx(usdc, "0", cd("approve(address,uint256)", drainer, maxU256)),
			Contracts:   []models.ContractInfo{contract(usdc, "erc20"), contract(drainer)},
			Reputation:  []models.ReputationRecord{rep(drainer, models.ReputationBlocked)},
			Expect:      fixtures.Expect{Rules: []string{"TXS-APPROVAL-001", "TXS-APPROVAL-005"}, AbsentRules: []string{"TXS-INTERACT-001"}, MinScore: 80, MaxScore: 100, Category: models.RiskCritical},
		},
		{
			Name: "malicious-nft-operator-approval-to-eoa", Kind: "malicious",
			Description: "setApprovalForAll on an NFT collection to an account with no code (classic NFT phishing).",
			Tx:          tx(nft, "0", cd("setApprovalForAll(address,bool)", attacker, true)),
			Contracts:   []models.ContractInfo{contract(nft, "erc721"), eoa(attacker)},
			Expect:      fixtures.Expect{Rules: []string{"TXS-APPROVAL-003", "TXS-APPROVAL-004"}, MinScore: 60, MaxScore: 100},
		},
		{
			Name: "malicious-fake-claim-drainer", Kind: "malicious",
			Description: "Payable claim() on an unknown contract; simulation shows three assets leaving the wallet to the attacker and nothing returned.",
			Tx:          tx(drainer, "10000000000000000", cd("claim()")),
			Contracts:   []models.ContractInfo{contract(drainer)},
			Simulation: success([]models.AssetTransfer{
				xfer(models.AssetERC20, usdc, user, attacker, "2500000000"),
				xfer(models.AssetERC20, dai, user, attacker, "1000000000000000000000"),
				{Asset: models.AssetRef{Kind: models.AssetERC721, Address: nft.Hex(), TokenID: "42"}, From: user.Hex(), To: attacker.Hex(), Amount: "1"},
			}, []models.BalanceChange{
				{Owner: user.Hex(), Asset: models.AssetRef{Kind: models.AssetERC20, Address: usdc.Hex()}, Before: "2500000000", After: "0", Delta: "-2500000000"},
			}, nil),
			Expect: fixtures.Expect{Rules: []string{"TXS-VALUE-001", "TXS-VALUE-002", "TXS-VALUE-003", "TXS-VALUE-004", "TXS-VALUE-005"}, MinScore: 80, MaxScore: 100, Category: models.RiskCritical},
		},
		{
			Name: "malicious-forwarded-transferfrom", Kind: "malicious",
			Description: "Unknown contract call whose calldata embeds transferFrom(user -> attacker) for a token the user approved earlier (arbitrary external call drainer).",
			Tx:          tx(drainer, "0", cd("multicallProxy(address target, bytes data)", usdc, bytesOf(cd("transferFrom(address,address,uint256)", user, attacker, maxU256)))),
			Expect:      fixtures.Expect{Rules: []string{"TXS-PATTERN-008"}, MinScore: 60, MaxScore: 100},
		},
		{
			Name: "malicious-safe-delegatecall", Kind: "malicious",
			Description: "Safe transaction with operation=1 (DELEGATECALL) into an unknown library that would run with the Safe's storage.",
			Tx:          tx(safe, "0", safeExec(lib, bytesOf(cd("transferOwnership(address)", attacker)), 1)),
			Expect:      fixtures.Expect{Rules: []string{"TXS-PATTERN-001", "TXS-PATTERN-004"}, MinScore: 60, MaxScore: 100},
		},
		{
			Name: "malicious-proxy-upgrade", Kind: "malicious",
			Description: "Proxy upgrade to a new implementation with an initialization call.",
			Tx:          tx(usdc, "0", cd("upgradeToAndCall(address,bytes)", impl, bytesOf(cd("transferOwnership(address)", attacker)))),
			Expect:      fixtures.Expect{Rules: []string{"TXS-PATTERN-005", "TXS-PATTERN-001", "TXS-PATTERN-004"}, MinScore: 60, MaxScore: 100},
		},
		{
			Name: "malicious-multicall-to-blocklisted", Kind: "malicious",
			Description: "Self-multicall that transfers USDC to a blocklisted address.",
			Tx:          tx(usdc, "0", cd("multicall(bytes[])", [][]byte{bytesOf(cd("transfer(address,uint256)", drainer, big.NewInt(1000)))})),
			Reputation:  []models.ReputationRecord{rep(drainer, models.ReputationBlocked)},
			Expect:      fixtures.Expect{Rules: []string{"TXS-INTERACT-001"}, MinScore: 80, MaxScore: 100},
		},
		{
			Name: "malicious-calldata-to-eoa", Kind: "malicious",
			Description: "Approve calldata sent to an address that has no code (wrong network or address).",
			Tx:          tx(attacker, "0", cd("approve(address,uint256)", router, maxU256)),
			Contracts:   []models.ContractInfo{eoa(attacker), contract(router)},
			Expect:      fixtures.Expect{Rules: []string{"TXS-INTERACT-005"}, AbsentRules: []string{"TXS-APPROVAL-001"}, MinScore: 20, MaxScore: 39},
		},
		{
			Name: "unusual-flash-loan-reentrancy", Kind: "benign",
			Description: "Aave flashLoanSimple whose simulated trace re-enters the receiver. Reported as unusual (low/info), not as an exploit.",
			Tx:          tx(aave, "0", cd("flashLoanSimple(address,address,uint256,bytes,uint16)", drainer, usdc, big.NewInt(1e12), []byte{1}, uint16(0))),
			Simulation: success(nil, nil, &models.CallFrame{Type: "CALL", From: user.Hex(), To: aave.Hex(), Calls: []models.CallFrame{
				{Type: "CALL", From: aave.Hex(), To: drainer.Hex(), Calls: []models.CallFrame{{Type: "CALL", From: drainer.Hex(), To: aave.Hex()}}},
			}}),
			Expect: fixtures.Expect{Rules: []string{"TXS-PATTERN-007", "TXS-PATTERN-010"}, MinScore: 0, MaxScore: 39},
		},
		{
			Name: "failed-transaction-revert", Kind: "malicious",
			Description: "Swap that reverts in simulation (attacker-controlled revert string is sanitized).",
			Tx:          tx(uniV2, "0", cd("swapExactTokensForTokens(uint256,uint256,address[],address,uint256)", big.NewInt(1000), big.NewInt(1), []common.Address{usdc, weth}, user, big.NewInt(1))),
			Simulation:  &models.SimulationResult{Backend: "fixture", Status: models.SimReverted, Completeness: models.CompletenessFull, ChainID: 1, BlockNumber: 19000000, RevertReason: "UniswapV2Router: EXPIRED"},
			Expect:      fixtures.Expect{Rules: []string{"TXS-SIM-001"}, AbsentRules: []string{"TXS-VALUE-001", "TXS-VALUE-003"}, MinScore: 1, MaxScore: 19},
		},
		{
			Name: "permit2-unlimited-long-lived-via-router", Kind: "malicious",
			Description: "Universal Router PERMIT2_PERMIT granting an unlimited allowance that expires in 2100.",
			Tx: tx(router, "0", cd("execute(bytes commands, bytes[] inputs)", []byte{0x0a}, [][]byte{
				raw("f(((address token, uint160 amount, uint48 expiration, uint48 nonce) details, address spender, uint256 sigDeadline) permitSingle, bytes signature)",
					single{details{usdc, maxU160, year2100, big.NewInt(0)}, router, big.NewInt(1)}, make([]byte, 65)),
			})),
			Expect: fixtures.Expect{Rules: []string{"TXS-APPROVAL-001", "TXS-APPROVAL-007", "TXS-PATTERN-002"}, MinScore: 20, MaxScore: 59},
		},
		// ------------------------------------------------------------- benign
		{
			Name: "benign-usdc-transfer", Kind: "benign",
			Description: "Plain ERC-20 transfer with matching simulation.",
			Tx:          tx(usdc, "0", cd("transfer(address,uint256)", attacker, big.NewInt(1_000_000))),
			Contracts:   []models.ContractInfo{contract(usdc, "erc20")},
			Simulation:  success([]models.AssetTransfer{xfer(models.AssetERC20, usdc, user, attacker, "1000000")}, nil, nil),
			Expect:      fixtures.Expect{MinScore: 0, MaxScore: 0, Category: models.RiskLow, Verdict: models.NoSignificantRisks},
		},
		{
			Name: "benign-exact-approval-allowlisted-router", Kind: "benign", FalsePositiveCase: true,
			Description: "Exact-amount approval to an allowlisted router; no approval findings expected.",
			Tx:          tx(usdc, "0", cd("approve(address,uint256)", uniV2, big.NewInt(1_000_000))),
			Contracts:   []models.ContractInfo{contract(usdc, "erc20"), contract(uniV2)},
			Reputation:  []models.ReputationRecord{rep(uniV2, models.ReputationAllowed), rep(usdc, models.ReputationAllowed)},
			Simulation:  success(nil, nil, nil),
			Expect:      fixtures.Expect{AbsentRules: []string{"TXS-APPROVAL-001", "TXS-APPROVAL-002", "TXS-APPROVAL-006", "TXS-INTERACT-003"}, MinScore: 0, MaxScore: 0, Verdict: models.NoSignificantRisks},
		},
		{
			Name: "benign-ens-nft-single-approval", Kind: "benign", FalsePositiveCase: true,
			Description: "ERC-721 approve with a 256-bit token ID (ENS-style); must not be mistaken for an unlimited ERC-20 allowance.",
			Tx:          tx(nft, "0", cd("approve(address,uint256)", router, new(big.Int).Sub(maxU256, big.NewInt(12345)))),
			Contracts:   []models.ContractInfo{contract(nft, "erc721"), contract(router)},
			Expect:      fixtures.Expect{AbsentRules: []string{"TXS-APPROVAL-001", "TXS-APPROVAL-002"}, MinScore: 0, MaxScore: 19},
		},
		{
			Name: "benign-universal-router-swap", Kind: "benign", FalsePositiveCase: true,
			Description: "USDC->WETH swap; USDC goes to a pool not named in calldata and WETH comes back. Value rules must stay silent.",
			Tx: tx(router, "0", cd("execute(bytes commands, bytes[] inputs, uint256 deadline)", []byte{0x00}, [][]byte{
				raw("f(address recipient, uint256 amountIn, uint256 amountOutMin, bytes path, bool payerIsUser)", user, big.NewInt(1_000_000), big.NewInt(1), v3path, true),
			}, big.NewInt(1_800_000_000))),
			Simulation: success([]models.AssetTransfer{xfer(models.AssetERC20, usdc, user, pool, "1000000"), xfer(models.AssetERC20, weth, pool, user, "300000000000000")}, nil,
				&models.CallFrame{Type: "CALL", From: user.Hex(), To: router.Hex(), Calls: []models.CallFrame{
					{Type: "CALL", From: router.Hex(), To: pool.Hex(), Calls: []models.CallFrame{{Type: "CALL", From: pool.Hex(), To: router.Hex()}}},
				}}),
			Expect: fixtures.Expect{AbsentRules: []string{"TXS-VALUE-001", "TXS-VALUE-002", "TXS-VALUE-003"}, MinScore: 0, MaxScore: 0, Verdict: models.NoSignificantRisks},
		},
		{
			Name: "benign-revoke-approval", Kind: "benign", FalsePositiveCase: true,
			Description: "approve(spender, 0) revocation.",
			Tx:          tx(usdc, "0", cd("approve(address,uint256)", drainer, big.NewInt(0))),
			Expect:      fixtures.Expect{AbsentRules: []string{"TXS-APPROVAL-001", "TXS-APPROVAL-002", "TXS-APPROVAL-003"}, MinScore: 0, MaxScore: 0, Verdict: models.NoSignificantRisks},
		},
		{
			Name: "benign-multicall3-intermediary-approval", Kind: "benign", FalsePositiveCase: true,
			Description: "Multicall3 aggregate containing an approve: the allowance belongs to the Multicall3 contract, not the user.",
			Tx:          tx(mc3, "0", cd("aggregate((address target, bytes callData)[] calls)", []mcCall{{usdc, bytesOf(cd("approve(address,uint256)", attacker, maxU256))}})),
			Expect:      fixtures.Expect{AbsentRules: []string{"TXS-APPROVAL-001"}, MinScore: 0, MaxScore: 0},
		},
		{
			Name: "benign-eth-transfer", Kind: "benign",
			Description: "Plain ETH transfer to an account.",
			Tx:          tx(attacker, "1000000000000000000", ""),
			Contracts:   []models.ContractInfo{eoa(attacker)},
			Simulation:  success(nil, nil, nil),
			Expect:      fixtures.Expect{MinScore: 0, MaxScore: 0, Verdict: models.NoSignificantRisks},
		},
		{
			Name: "benign-unlimited-approval-known-router", Kind: "benign", FalsePositiveCase: true,
			Description: "Unlimited approval to an allowlisted router is reported (exposure) but stays in the moderate band, not high.",
			Tx:          tx(usdc, "0", cd("approve(address,uint256)", uniV2, maxU256)),
			Contracts:   []models.ContractInfo{contract(usdc, "erc20"), contract(uniV2)},
			Reputation:  []models.ReputationRecord{rep(uniV2, models.ReputationAllowed), rep(usdc, models.ReputationAllowed)},
			Simulation:  success(nil, nil, nil),
			Expect:      fixtures.Expect{Rules: []string{"TXS-APPROVAL-001"}, AbsentRules: []string{"TXS-APPROVAL-005", "TXS-APPROVAL-006"}, MinScore: 20, MaxScore: 39, Category: models.RiskModerate},
		},
	}
}

func main() {
	dir := fixtures.Dir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		panic(err)
	}
	old, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	for _, p := range old {
		_ = os.Remove(p)
	}
	for _, s := range scenarios() {
		b, err := json.MarshalIndent(s, "", "  ")
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(filepath.Join(dir, s.Name+".json"), append(b, '\n'), 0o600); err != nil {
			panic(err)
		}
	}
	fmt.Printf("wrote %d scenarios to %s\n", len(scenarios()), dir)
}
