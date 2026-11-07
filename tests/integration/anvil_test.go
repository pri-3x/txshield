//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/txshield/txshield/internal/analyzer"
	"github.com/txshield/txshield/internal/decoder"
	"github.com/txshield/txshield/internal/evm"
	"github.com/txshield/txshield/internal/simulator"
	"github.com/txshield/txshield/pkg/interfaces"
	"github.com/txshield/txshield/pkg/models"
	"github.com/txshield/txshield/pkg/txerrors"
)

// Anvil's default unlocked development accounts.
var (
	deployer = common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	victim   = common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	attacker = common.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
	poor     = common.HexToAddress("0x00000000000000000000000000000000000Beef1")
)

const chainID = 31337

var oneEther = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)

// world is a local chain with deployed fixtures.
type world struct {
	cmd                                      *exec.Cmd
	url                                      string
	node                                     *evm.Client // write access to the test chain (setup only)
	token, token2, nft, drainer, forwarder   common.Address
	vault, vaultAttacker, reverter, exchange common.Address
	proxy, logic, clone                      common.Address
	delegateExec, hijack                     common.Address
}

var (
	worldOnce sync.Once
	theWorld  *world
	worldErr  error
)

// TestMain stops the shared local chain: child processes are not killed
// automatically when the test binary exits.
func TestMain(m *testing.M) {
	code := m.Run()
	if theWorld != nil && theWorld.cmd != nil && theWorld.cmd.Process != nil {
		_ = theWorld.cmd.Process.Kill()
		_ = theWorld.cmd.Wait()
	}
	os.Exit(code)
}

func requireTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"anvil", "forge"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed; install Foundry to run simulation integration tests", tool)
		}
	}
}

func repoRoot() string {
	wd, _ := os.Getwd()
	return filepath.Join(wd, "..", "..")
}

func getWorld(t *testing.T) *world {
	t.Helper()
	requireTools(t)
	worldOnce.Do(func() { theWorld, worldErr = buildWorld() })
	if worldErr != nil {
		t.Fatalf("setting up local chain: %v", worldErr)
	}
	return theWorld
}

func freePort() int {
	l, _ := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func buildWorld() (*world, error) {
	build := exec.CommandContext(context.Background(), "forge", "build", "--root", filepath.Join(repoRoot(), "contracts"))
	if out, err := build.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("forge build: %w: %s", err, out)
	}
	port := freePort()
	cmd := exec.CommandContext(context.Background(), "anvil", "--host", "127.0.0.1", "--port", strconv.Itoa(port), "--chain-id", strconv.Itoa(chainID), "--silent")
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// Stopped by TestMain after all tests finish.
	w := &world{cmd: cmd, url: "http://127.0.0.1:" + strconv.Itoa(port)}
	var err error
	if w.node, err = evm.DialLocal(context.Background(), w.url, evm.Options{}); err != nil {
		return nil, err
	}
	ctx := context.Background()
	for i := 0; ; i++ {
		if _, err := w.node.BlockNumber(ctx); err == nil {
			break
		}
		if i > 100 {
			return nil, fmt.Errorf("anvil did not start")
		}
		time.Sleep(50 * time.Millisecond)
	}

	d := func(file, name, ctorSig string, args ...any) common.Address {
		if err != nil {
			return common.Address{}
		}
		var a common.Address
		a, err = w.deploy(file, name, ctorSig, args...)
		return a
	}
	w.token = d("Tokens.sol", "TestToken", "c(string,string)", "Test USD", "TUSD")
	w.token2 = d("Tokens.sol", "TestToken", "c(string,string)", "Other", "OTH")
	w.nft = d("Tokens.sol", "TestNFT", "")
	w.forwarder = d("Malicious.sol", "Forwarder", "")
	w.vault = d("Malicious.sol", "ReentrantVault", "")
	w.vaultAttacker = d("Malicious.sol", "VaultAttacker", "c(address)", w.vault)
	w.reverter = d("Malicious.sol", "Reverter", "")
	w.exchange = d("Benign.sol", "SimpleExchange", "")
	w.logic = d("Benign.sol", "ProxyLogic", "")
	w.proxy = d("Benign.sol", "ERC1967Proxy", "c(address)", w.logic)
	cloner := d("Benign.sol", "Cloner", "")
	w.delegateExec = d("Malicious.sol", "DelegateExecutor", "")
	w.hijack = d("Malicious.sol", "OwnerHijack", "")
	w.drainer = d("Malicious.sol", "Drainer", "c(address,address[],address,uint256[])", attacker, []common.Address{w.token, w.token2}, w.nft, []*big.Int{big.NewInt(7)})
	if err != nil {
		return nil, err
	}

	maxU := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	steps := []struct {
		from common.Address
		to   common.Address
		data []byte
	}{
		{deployer, w.token, cd("mint(address,uint256)", victim, new(big.Int).Mul(big.NewInt(1000), oneEther))},
		{deployer, w.token2, cd("mint(address,uint256)", victim, new(big.Int).Mul(big.NewInt(50), oneEther))},
		{deployer, w.token2, cd("mint(address,uint256)", w.exchange, new(big.Int).Mul(big.NewInt(1000), oneEther))},
		{deployer, w.nft, cd("mint(address,uint256)", victim, big.NewInt(7))},
		// The victim was phished earlier: approvals to the drainer and forwarder.
		{victim, w.token, cd("approve(address,uint256)", w.drainer, maxU)},
		{victim, w.token2, cd("approve(address,uint256)", w.drainer, maxU)},
		{victim, w.nft, cd("setApprovalForAll(address,bool)", w.drainer, true)},
		{victim, w.token, cd("approve(address,uint256)", w.forwarder, maxU)},
		{victim, w.token, cd("approve(address,uint256)", w.exchange, maxU)},
		{deployer, w.vault, cd("deposit()")},
	}
	for i, s := range steps {
		value := new(big.Int)
		if s.to == w.vault {
			value = new(big.Int).Mul(big.NewInt(5), oneEther)
		}
		if _, err := w.send(s.from, &s.to, s.data, value); err != nil {
			return nil, fmt.Errorf("setup step %d: %w", i, err)
		}
	}
	rcpt, err := w.send(deployer, &cloner, cd("clone(address)", w.logic), new(big.Int))
	if err != nil {
		return nil, err
	}
	w.clone = common.BytesToAddress(rcpt.Logs[0].Data[12:32])
	return w, nil
}

type txReceipt struct {
	Status          hexutil.Uint64  `json:"status"`
	ContractAddress *common.Address `json:"contractAddress"`
	Logs            []struct {
		Data hexutil.Bytes `json:"data"`
	} `json:"logs"`
}

func (w *world) send(from common.Address, to *common.Address, data []byte, value *big.Int) (*txReceipt, error) {
	ctx := context.Background()
	args := map[string]any{"from": from, "data": hexutil.Bytes(data), "gas": "0x1c9c380", "value": (*hexutil.Big)(value)}
	if to != nil {
		args["to"] = to
	}
	var hash common.Hash
	if err := w.node.Call(ctx, &hash, "eth_sendTransaction", args); err != nil {
		return nil, err
	}
	var r *txReceipt
	for i := 0; i < 200 && r == nil; i++ {
		if err := w.node.Call(ctx, &r, "eth_getTransactionReceipt", hash); err != nil {
			return nil, err
		}
		if r == nil {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if r == nil {
		return nil, fmt.Errorf("no receipt for %s", hash.Hex())
	}
	if r.Status != 1 {
		var trace json.RawMessage
		_ = w.node.Call(ctx, &trace, "debug_traceTransaction", hash, map[string]any{"tracer": "callTracer"})
		return nil, fmt.Errorf("transaction reverted: %.300s", trace)
	}
	return r, nil
}

func (w *world) deploy(file, name, ctorSig string, args ...any) (common.Address, error) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(), "contracts", "out", file, name+".json"))
	if err != nil {
		return common.Address{}, err
	}
	var art struct {
		Bytecode struct {
			Object string `json:"object"`
		} `json:"bytecode"`
	}
	if err := json.Unmarshal(raw, &art); err != nil {
		return common.Address{}, err
	}
	code := hexutil.MustDecode(art.Bytecode.Object)
	if ctorSig != "" {
		code = append(code, cd(ctorSig, args...)[4:]...)
	}
	r, err := w.send(deployer, nil, code, new(big.Int))
	if err != nil {
		return common.Address{}, fmt.Errorf("deploy %s: %w", name, err)
	}
	return *r.ContractAddress, nil
}

func cd(sig string, args ...any) []byte {
	m, err := decoder.ParseSignature(sig)
	if err != nil {
		panic(err)
	}
	enc, err := m.Inputs.Pack(args...)
	if err != nil {
		panic(fmt.Sprintf("%s: %v", sig, err))
	}
	return append(append([]byte{}, m.ID...), enc...)
}

func tx(from, to common.Address, value *big.Int, data []byte) *models.Transaction {
	if value == nil {
		value = new(big.Int)
	}
	return &models.Transaction{ChainID: chainID, From: from, To: &to, Value: value, Data: data, Block: models.BlockRef{Tag: models.BlockLatest}}
}

func (w *world) registry() *evm.Registry {
	return evm.NewRegistry(map[uint64]string{chainID: w.url}, evm.Options{})
}

type chainState struct {
	block, victimNonce uint64
	victimToken        *big.Int
}

func (w *world) snapshot(t *testing.T) chainState {
	t.Helper()
	ctx := context.Background()
	n, err := w.node.BlockNumber(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var nonce hexutil.Uint64
	if err := w.node.Call(ctx, &nonce, "eth_getTransactionCount", victim, "latest"); err != nil {
		t.Fatal(err)
	}
	out, err := w.node.CallContract(ctx, &models.Transaction{To: &w.token, Data: cd("balanceOf(address)", victim), Value: new(big.Int)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return chainState{n, uint64(nonce), new(big.Int).SetBytes(out)}
}

// ---------------------------------------------------------------------------

func newAnvil(t *testing.T, w *world) *simulator.Anvil {
	t.Helper()
	sim := simulator.NewAnvil(w.registry(), simulator.AnvilOptions{Workers: 2})
	t.Cleanup(sim.Close)
	return sim
}

func simulate(t *testing.T, s interfaces.Simulator, x *models.Transaction) *models.SimulationResult {
	t.Helper()
	res, err := s.Simulate(context.Background(), interfaces.SimulationRequest{Tx: x})
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	return res
}

func TestAnvilSimulatesWithoutBroadcasting(t *testing.T) {
	w := getWorld(t)
	before := w.snapshot(t)
	sim := newAnvil(t, w)

	amount := new(big.Int).Mul(big.NewInt(10), oneEther)
	res := simulate(t, sim, tx(victim, w.token, nil, cd("transfer(address,uint256)", attacker, amount)))
	if res.Status != models.SimSuccess || res.Completeness != models.CompletenessFull || res.Backend != "anvil" {
		t.Fatalf("%+v", res)
	}
	if res.BlockNumber != before.block || res.GasUsed == 0 || res.GasEstimate == nil || res.Trace == nil {
		t.Fatalf("block/gas/trace: %+v", res)
	}
	if len(res.AssetTransfers) != 1 || res.AssetTransfers[0].Amount != models.QuantityFromBig(amount) || res.AssetTransfers[0].From != victim.Hex() {
		t.Fatalf("transfers %+v", res.AssetTransfers)
	}
	if len(res.BalanceChanges) != 1 || res.BalanceChanges[0].Delta != models.Quantity("-"+amount.String()) {
		t.Fatalf("balance changes %+v", res.BalanceChanges)
	}

	// Several more simulations, some concurrent, then confirm the real chain
	// never saw any of them.
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := sim.Simulate(context.Background(), interfaces.SimulationRequest{Tx: tx(victim, w.drainer, oneEther, cd("claim()"))})
			if err != nil || r.Status != models.SimSuccess {
				t.Errorf("concurrent simulation: %v %+v", err, r)
			}
		}()
	}
	wg.Wait()
	after := w.snapshot(t)
	if after != before && (after.block != before.block || after.victimNonce != before.victimNonce || after.victimToken.Cmp(before.victimToken) != 0) {
		t.Fatalf("simulation changed the real chain: before %+v after %+v", before, after)
	}
}

func TestAnvilDrainerEffects(t *testing.T) {
	w := getWorld(t)
	res := simulate(t, newAnvil(t, w), tx(victim, w.drainer, oneEther, cd("claim()")))
	if res.Status != models.SimSuccess {
		t.Fatalf("%+v", res)
	}
	kinds := map[models.AssetKind]int{}
	for _, tr := range res.AssetTransfers {
		kinds[tr.Asset.Kind]++
		if tr.Asset.Kind != models.AssetNative && tr.To != attacker.Hex() {
			t.Errorf("token went to %s, want attacker", tr.To)
		}
	}
	if kinds[models.AssetERC20] != 2 || kinds[models.AssetERC721] != 1 || kinds[models.AssetNative] != 2 {
		t.Fatalf("transfers by kind %v: %+v", kinds, res.AssetTransfers)
	}
	zeroed := 0
	for _, b := range res.BalanceChanges {
		if b.After == "0" && b.Asset.Kind == models.AssetERC20 {
			zeroed++
		}
	}
	if zeroed != 2 {
		t.Fatalf("both token balances should be drained: %+v", res.BalanceChanges)
	}
}

func TestAnvilReverts(t *testing.T) {
	w := getWorld(t)
	sim := newAnvil(t, w)
	cases := map[string]struct {
		x    *models.Transaction
		want string
	}{
		"require string": {tx(victim, w.reverter, nil, cd("swap(uint256)", big.NewInt(1))), "EXPIRED"},
		"panic":          {tx(victim, w.reverter, nil, cd("overflow(uint256)", big.NewInt(5))), "panic 0x11 (arithmetic overflow or underflow)"},
		"custom error":   {tx(victim, w.reverter, nil, cd("guarded()")), "custom error"},
		"insufficient":   {tx(poor, w.vault, oneEther, cd("deposit()")), "rejected before execution"},
	}
	for name, c := range cases {
		res := simulate(t, sim, c.x)
		if res.Status != models.SimReverted || !strings.Contains(res.RevertReason, c.want) {
			t.Errorf("%s: status %s reason %q", name, res.Status, res.RevertReason)
		}
	}
}

func TestAnvilInfrastructureFailuresAreErrors(t *testing.T) {
	w := getWorld(t)
	// Endpoint configured for chain 1 actually serves chain 31337.
	wrong := simulator.NewAnvil(evm.NewRegistry(map[uint64]string{1: w.url}, evm.Options{}), simulator.AnvilOptions{Workers: 1})
	defer wrong.Close()
	x := tx(victim, w.token, nil, cd("transfer(address,uint256)", attacker, big.NewInt(1)))
	x.ChainID = 1
	if _, err := wrong.Simulate(context.Background(), interfaces.SimulationRequest{Tx: x}); txerrors.KindOf(err) != txerrors.KindUnsupported {
		t.Fatalf("chain mismatch: %v", err)
	}

	down := simulator.NewAnvil(evm.NewRegistry(map[uint64]string{chainID: "http://127.0.0.1:1"}, evm.Options{Retry: evm.RetryPolicy{MaxAttempts: 1}}), simulator.AnvilOptions{Workers: 1})
	defer down.Close()
	if _, err := down.Simulate(context.Background(), interfaces.SimulationRequest{Tx: tx(victim, w.token, nil, nil)}); txerrors.KindOf(err) != txerrors.KindUnavailable {
		t.Fatalf("upstream down must be Unavailable, not a revert: %v", err)
	}

	slow := simulator.NewAnvil(w.registry(), simulator.AnvilOptions{Workers: 1, Timeout: time.Millisecond})
	defer slow.Close()
	if _, err := slow.Simulate(context.Background(), interfaces.SimulationRequest{Tx: tx(victim, w.token, nil, nil)}); txerrors.KindOf(err) != txerrors.KindTimeout {
		t.Fatalf("timeout: %v", err)
	}
}

func TestRPCTraceFallback(t *testing.T) {
	w := getWorld(t)
	s := simulator.NewRPCTrace(w.registry(), 0)
	res := simulate(t, s, tx(victim, w.token, nil, cd("transfer(address,uint256)", attacker, big.NewInt(5))))
	if res.Status != models.SimSuccess || res.Completeness != models.CompletenessPartial || len(res.AssetTransfers) != 1 || len(res.BalanceChanges) != 0 {
		t.Fatalf("%+v", res)
	}
	res = simulate(t, s, tx(victim, w.reverter, nil, cd("swap(uint256)", big.NewInt(1))))
	if res.Status != models.SimReverted || !strings.Contains(res.RevertReason, "EXPIRED") {
		t.Fatalf("%+v", res)
	}
}

func TestInspectorOnRealContracts(t *testing.T) {
	w := getWorld(t)
	in := evm.NewInspector(w.registry(), 0)
	ctx := context.Background()
	get := func(a common.Address) *models.ContractInfo {
		info, err := in.Inspect(ctx, chainID, a, 0)
		if err != nil {
			t.Fatal(err)
		}
		return info
	}
	if i := get(w.token); !i.IsContract || len(i.Standards) != 1 || i.Standards[0] != "erc20" {
		t.Errorf("token %+v", i)
	}
	if i := get(w.nft); len(i.Standards) != 1 || i.Standards[0] != "erc721" {
		t.Errorf("nft %+v", i)
	}
	if i := get(w.proxy); !i.IsProxy || i.Implementation != w.logic.Hex() {
		t.Errorf("1967 proxy %+v", i)
	}
	if i := get(w.clone); !i.IsProxy || i.Implementation != w.logic.Hex() {
		t.Errorf("1167 clone %+v", i)
	}
	if i := get(victim); i.IsContract {
		t.Errorf("EOA %+v", i)
	}
	if i := get(w.reverter); !i.IsContract || len(i.Standards) != 0 || i.IsProxy {
		t.Errorf("plain contract %+v", i)
	}
}

// TestEndToEndAnalysis runs the full analyzer with real simulation and
// contract facts against the deployed fixtures.
func TestEndToEndAnalysis(t *testing.T) {
	w := getWorld(t)
	reg := w.registry()
	a, err := analyzer.Build(analyzer.BuildOptions{
		Chains: reg, Inspector: evm.NewInspector(reg, 0), Simulator: newAnvil(t, w),
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		x        *models.Transaction
		rules    []string
		absent   []string
		min, max int
	}{
		{"drainer claim", tx(victim, w.drainer, oneEther, cd("claim()")),
			[]string{"TXS-VALUE-001", "TXS-VALUE-002", "TXS-VALUE-003", "TXS-VALUE-004"}, nil, 80, 100},
		{"forwarded transferFrom", tx(victim, w.forwarder, nil, cd("execute(address,bytes)", w.token, cd("transferFrom(address,address,uint256)", victim, attacker, oneEther))),
			[]string{"TXS-PATTERN-008"}, nil, 60, 100},
		{"reentrancy", tx(victim, w.vaultAttacker, oneEther, cd("attack()")),
			[]string{"TXS-PATTERN-010"}, nil, 0, 100},
		{"delegatecall backdoor", tx(victim, w.delegateExec, nil, cd("run(address,bytes)", w.hijack, cd("hijack(address)", attacker))),
			[]string{"TXS-PATTERN-001"}, nil, 20, 100},
		{"reverting swap", tx(victim, w.reverter, nil, cd("swap(uint256)", big.NewInt(1))),
			[]string{"TXS-SIM-001"}, []string{"TXS-VALUE-001", "TXS-VALUE-003"}, 1, 19},
		{"benign token transfer", tx(victim, w.token, nil, cd("transfer(address,uint256)", attacker, oneEther)),
			nil, []string{"TXS-VALUE-001", "TXS-VALUE-002", "TXS-VALUE-003"}, 0, 0},
		{"benign exchange swap (false positive guard)", tx(victim, w.exchange, nil, cd("swap(address,address,uint256)", w.token, w.token2, oneEther)),
			nil, []string{"TXS-VALUE-001", "TXS-VALUE-002", "TXS-VALUE-003"}, 0, 19},
		{"approve to EOA", tx(victim, w.token, nil, cd("approve(address,uint256)", attacker, oneEther)),
			[]string{"TXS-APPROVAL-004"}, []string{"TXS-APPROVAL-001"}, 20, 100},
		{"calldata to EOA", tx(victim, attacker, nil, cd("claim()")),
			[]string{"TXS-INTERACT-005"}, nil, 20, 100},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := a.Analyze(context.Background(), analyzer.Request{Tx: c.x, Simulate: true})
			if err != nil {
				t.Fatal(err)
			}
			fired := map[string]bool{}
			for _, f := range r.Findings {
				fired[f.RuleID] = true
			}
			for _, id := range c.rules {
				if !fired[id] {
					t.Errorf("expected %s; fired %v", id, fired)
				}
			}
			for _, id := range c.absent {
				if fired[id] {
					t.Errorf("%s must not fire", id)
				}
			}
			if r.Risk.Score < c.min || r.Risk.Score > c.max {
				t.Errorf("score %d not in [%d,%d]: %+v", r.Risk.Score, c.min, c.max, r.Risk.Contributions)
			}
			if r.Simulation.Backend != "anvil" || r.Simulation.Completeness == models.CompletenessNone {
				t.Errorf("simulation not used: %+v", r.Simulation)
			}
			if r.Risk.Confidence != models.ConfidenceHigh && r.Simulation.Completeness == models.CompletenessFull {
				t.Errorf("full simulation + chain facts should give high confidence, got %s (warnings %v)", r.Risk.Confidence, r.Warnings)
			}
			t.Logf("score=%d %s confidence=%s fired=%v", r.Risk.Score, r.Risk.Category, r.Risk.Confidence, fired)
		})
	}
}

// TestCLIAgainstLocalChain builds the txshield binary and drives it end to
// end against the fixture chain.
func TestCLIAgainstLocalChain(t *testing.T) {
	w := getWorld(t)
	bin := filepath.Join(t.TempDir(), "txshield")
	if out, err := exec.CommandContext(context.Background(), "go", "build", "-o", bin, filepath.Join(repoRoot(), "cmd", "txshield")).CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	run := func(args ...string) (int, string) {
		cmd := exec.CommandContext(context.Background(), bin, args...)
		out, err := cmd.CombinedOutput()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return code, string(out)
	}
	base := []string{"--chain", "31337", "--rpc", w.url, "--from", victim.Hex()}

	code, out := run(append([]string{"analyze"}, append(base, "--to", w.drainer.Hex(), "--value", oneEther.String(), "--data", hexutil.Encode(cd("claim()")), "--json")...)...)
	if code != 3 {
		t.Fatalf("drainer analyze exit %d: %s", code, out)
	}
	var r models.RiskReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if r.Risk.Score < 80 || r.Simulation.Backend != "anvil" || r.Risk.Confidence != models.ConfidenceHigh {
		t.Fatalf("report: score %d sim %s confidence %s", r.Risk.Score, r.Simulation.Backend, r.Risk.Confidence)
	}

	code, out = run(append([]string{"simulate"}, append(base, "--to", w.reverter.Hex(), "--data", hexutil.Encode(cd("swap(uint256)", big.NewInt(1))))...)...)
	if code != 5 || !strings.Contains(out, "EXPIRED") {
		t.Fatalf("revert simulate exit %d: %s", code, out)
	}

	code, out = run(append([]string{"simulate"}, append(base, "--to", w.token.Hex(), "--data", hexutil.Encode(cd("transfer(address,uint256)", attacker, oneEther)))...)...)
	if code != 0 || !strings.Contains(out, "delta -1000000000000000000") {
		t.Fatalf("transfer simulate exit %d: %s", code, out)
	}

	// Wrong --chain for the endpoint: refused as invalid input, not simulated.
	code, out = run("analyze", "--chain", "1", "--rpc", w.url, "--from", victim.Hex(), "--to", w.token.Hex())
	if code != 2 || !strings.Contains(out, "reports chain 31337") {
		t.Fatalf("chain mismatch exit %d: %s", code, out)
	}
}

// BenchmarkAnvilSimulate measures warm-worker simulation latency (re-fork +
// execute + trace + balance diffs) against a local chain, i.e. TxShield's
// own overhead without upstream network latency.
//
//	go test -tags integration -run '^$' -bench AnvilSimulate -benchtime 50x ./tests/integration/
func BenchmarkAnvilSimulate(b *testing.B) {
	t := &testing.T{}
	w := getWorld(t)
	if w == nil {
		b.Skip("local chain unavailable")
	}
	sim := simulator.NewAnvil(w.registry(), simulator.AnvilOptions{Workers: 1})
	defer sim.Close()
	cases := map[string]*models.Transaction{
		"erc20-transfer": tx(victim, w.token, nil, cd("transfer(address,uint256)", attacker, oneEther)),
		"drainer-claim":  tx(victim, w.drainer, oneEther, cd("claim()")),
	}
	for name, x := range cases {
		b.Run(name, func(b *testing.B) {
			// Warm the worker (process start excluded from the measurement).
			if _, err := sim.Simulate(context.Background(), interfaces.SimulationRequest{Tx: x}); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for b.Loop() {
				if _, err := sim.Simulate(context.Background(), interfaces.SimulationRequest{Tx: x}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkAnvilSimulateWorkers measures simulation throughput with 1, 2,
// and 4 anvil workers under parallel load (warm workers; queueing included).
//
//	go test -tags integration -run '^$' -bench AnvilSimulateWorkers -benchtime 200x ./tests/integration/
func BenchmarkAnvilSimulateWorkers(b *testing.B) {
	t := &testing.T{}
	w := getWorld(t)
	if w == nil {
		b.Skip("local chain unavailable")
	}
	x := tx(victim, w.token, nil, cd("transfer(address,uint256)", attacker, oneEther))
	for _, n := range []int{1, 2, 4} {
		b.Run(fmt.Sprintf("workers=%d", n), func(b *testing.B) {
			sim := simulator.NewAnvil(w.registry(), simulator.AnvilOptions{Workers: n})
			defer sim.Close()
			var wg sync.WaitGroup
			for range n { // start every worker before measuring
				wg.Add(1)
				go func() {
					defer wg.Done()
					if _, err := sim.Simulate(context.Background(), interfaces.SimulationRequest{Tx: x}); err != nil {
						b.Error(err)
					}
				}()
			}
			wg.Wait()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, err := sim.Simulate(context.Background(), interfaces.SimulationRequest{Tx: x}); err != nil {
						b.Error(err)
						return
					}
				}
			})
		})
	}
}

// TestAnvilColdStart reports how long the first simulation (process start)
// takes, for documentation.
func TestAnvilColdStart(t *testing.T) {
	w := getWorld(t)
	sim := simulator.NewAnvil(w.registry(), simulator.AnvilOptions{Workers: 1})
	defer sim.Close()
	start := time.Now()
	if _, err := sim.Simulate(context.Background(), interfaces.SimulationRequest{Tx: tx(victim, w.token, nil, cd("transfer(address,uint256)", attacker, oneEther))}); err != nil {
		t.Fatal(err)
	}
	t.Logf("cold start (process launch + fork + simulate): %s", time.Since(start))
}

// anvilWorkerArgs returns the command lines of simulation anvil processes
// (identified by the fork relay path in their arguments).
func anvilWorkerArgs(t *testing.T) []string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "ps", "-ax", "-o", "pid=,args=").Output()
	if err != nil {
		t.Skipf("ps unavailable: %v", err)
	}
	var lines []string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, "anvil") && strings.Contains(l, "/fork/") {
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	return lines
}

// The upstream RPC URL (usually holding an API key) must not appear in the
// anvil worker's process arguments, which every local user can read.
func TestAnvilArgumentsHideUpstreamURL(t *testing.T) {
	w := getWorld(t)
	sim := newAnvil(t, w)
	simulate(t, sim, tx(victim, w.token, nil, cd("transfer(address,uint256)", attacker, oneEther)))
	lines := anvilWorkerArgs(t)
	if len(lines) == 0 {
		t.Fatal("no anvil worker process found")
	}
	for _, l := range lines {
		f := strings.Fields(l)
		for i, a := range f {
			if a == "--fork-url" && i+1 < len(f) && (f[i+1] == w.url || !strings.Contains(f[i+1], "/fork/")) {
				t.Fatalf("worker arguments expose the upstream: %s", l)
			}
		}
	}
}

// A worker whose anvil process died is restarted instead of reusing its old
// port, which another process could have taken.
func TestAnvilWorkerRecoversFromCrash(t *testing.T) {
	w := getWorld(t)
	sim := simulator.NewAnvil(w.registry(), simulator.AnvilOptions{Workers: 1})
	t.Cleanup(sim.Close)
	simulate(t, sim, tx(victim, w.token, nil, cd("transfer(address,uint256)", attacker, oneEther)))
	lines := anvilWorkerArgs(t)
	if len(lines) != 1 {
		t.Fatalf("want one worker, got %q", lines)
	}
	pid, err := strconv.Atoi(strings.Fields(lines[0])[0])
	if err != nil {
		t.Fatal(err)
	}
	p, _ := os.FindProcess(pid)
	if err := p.Kill(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	res := simulate(t, sim, tx(victim, w.token, nil, cd("transfer(address,uint256)", attacker, oneEther)))
	if res.Status != models.SimSuccess {
		t.Fatalf("after crash: %+v", res)
	}
	if after := anvilWorkerArgs(t); len(after) != 1 || after[0] == lines[0] {
		t.Fatalf("worker not restarted: before %q after %q", lines, after)
	}
}
