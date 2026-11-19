package analyzer

import (
	"context"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/pri-3x/txshield/internal/security/reputation"
	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
)

// slowSimulator returns res after delay.
type slowSimulator struct {
	res   *models.SimulationResult
	delay time.Duration
}

func (slowSimulator) Name() string { return "slow" }
func (slowSimulator) Capabilities() models.SimulatorCapabilities {
	return models.SimulatorCapabilities{}
}
func (s slowSimulator) Simulate(ctx context.Context, _ interfaces.SimulationRequest) (*models.SimulationResult, error) {
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	r := *s.res
	return &r, nil
}

// slowInspector records which addresses it was asked about.
type slowInspector struct {
	delay time.Duration
	mu    sync.Mutex
	seen  map[common.Address]int
}

func (s *slowInspector) Inspect(_ context.Context, _ uint64, a common.Address, _ uint64) (*models.ContractInfo, error) {
	time.Sleep(s.delay)
	s.mu.Lock()
	s.seen[a]++
	s.mu.Unlock()
	return &models.ContractInfo{Address: a.Hex()}, nil
}

// A drainer claim() names no recipient in calldata; it sends the user's ETH
// to a collection wallet. That wallet is blocklisted, so the analysis must
// flag it from the simulated transfer alone.
func TestSimulatedRecipientIsReputationChecked(t *testing.T) {
	collector := common.HexToAddress("0xc011ec7000000000000000000000000000000001")
	drainer := common.HexToAddress("0xd7a1000000000000000000000000000000000001")
	tx := &models.Transaction{ChainID: 1, From: from, To: &drainer, Value: big1e18(), Data: common.FromHex("0x4e71d92d")}
	sim := &models.SimulationResult{
		Backend: "rpc-simulate", Status: models.SimSuccess, Completeness: models.CompletenessPartial, ChainID: 1,
		AssetTransfers: []models.AssetTransfer{
			{Asset: models.AssetRef{Kind: models.AssetNative}, From: from.Hex(), To: drainer.Hex(), Amount: "1000000000000000000"},
			{Asset: models.AssetRef{Kind: models.AssetNative}, From: drainer.Hex(), To: collector.Hex(), Amount: "1000000000000000000"},
		},
	}
	list := reputation.NewStaticProvider("list:test", models.ReputationSourceList, []models.ReputationRecord{
		{ChainID: 1, Address: collector.Hex(), Status: models.ReputationBlocked, Reason: "known drainer collection wallet", Confidence: models.ConfidenceHigh},
	})
	a, err := Build(BuildOptions{Simulator: fakeSimulator{res: sim}, ExtraReputation: []interfaces.ReputationProvider{list}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := a.Analyze(context.Background(), Request{Tx: tx, Simulate: true})
	if err != nil {
		t.Fatal(err)
	}
	var hit bool
	for _, f := range r.Findings {
		if f.RuleID == "TXS-INTERACT-001" {
			for _, s := range f.Subjects {
				if common.HexToAddress(s) == collector {
					hit = true
				}
			}
		}
	}
	if !hit {
		t.Fatalf("blocklisted collection wallet seen only in simulation was not flagged; findings=%v", ruleIDs(r.Findings))
	}
	if r.Risk.Category != models.RiskCritical && r.Risk.Category != models.RiskHigh {
		t.Fatalf("risk = %+v", r.Risk)
	}
}

// Context gathering for calldata addresses must overlap the simulation, and
// addresses that only the simulation reveals are inspected afterwards.
func TestSimulationOverlapsContextGathering(t *testing.T) {
	recipient := common.HexToAddress("0x2222222222222222222222222222222222222222")
	collector := common.HexToAddress("0x9999999999999999999999999999999999999999")
	sim := &models.SimulationResult{
		Backend: "slow", Status: models.SimSuccess, Completeness: models.CompletenessPartial, ChainID: 1,
		AssetTransfers: []models.AssetTransfer{
			{Asset: models.AssetRef{Kind: models.AssetERC20, Address: usdc.Hex()}, From: from.Hex(), To: collector.Hex(), Amount: "10"},
		},
	}
	const delay = 150 * time.Millisecond
	insp := &slowInspector{delay: delay, seen: map[common.Address]int{}}
	a, err := Build(BuildOptions{Simulator: slowSimulator{res: sim, delay: delay}, Inspector: insp})
	if err != nil {
		t.Fatal(err)
	}
	var tm Timings
	start := time.Now()
	if _, err := a.Analyze(context.Background(), Request{Tx: simpleTx(), Simulate: true, Timings: &tm}); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	// Sequential would be sim + pre-inspect + post-inspect = 3 x delay.
	if elapsed >= 3*delay-20*time.Millisecond {
		t.Fatalf("stages did not overlap: %s", elapsed)
	}
	for _, addr := range []common.Address{usdc, recipient, collector} {
		if insp.seen[addr] != 1 {
			t.Errorf("%s inspected %d times, want 1", addr.Hex(), insp.seen[addr])
		}
	}
	if tm.Simulate < delay || tm.Context < delay || tm.Total < tm.Simulate || tm.Total != tm.Total.Round(0) {
		t.Fatalf("timings: %+v", tm)
	}
}

func big1e18() *big.Int { v, _ := new(big.Int).SetString("1000000000000000000", 10); return v }

func ruleIDs(fs []models.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.RuleID
	}
	return out
}

type stubRegistry struct{ interfaces.ChainRegistry }

// Every API request analyzes through With; the copy must have a token cache
// (a nil cache crashed the server), shared only for the same chains.
func TestWithTokenCache(t *testing.T) {
	own := &stubRegistry{}
	a, err := Build(BuildOptions{Chains: own})
	if err != nil {
		t.Fatal(err)
	}
	same := a.With(own, nil, nil)
	if same.tokens == nil || same.tokens != a.tokens {
		t.Fatal("same chains must share the token cache")
	}
	other := a.With(&stubRegistry{}, nil, nil)
	if other.tokens == nil || other.tokens == a.tokens {
		t.Fatal("other chains (e.g. a caller-supplied RPC) must get a private cache")
	}
	if off := a.With(nil, nil, nil); off.tokens == nil {
		t.Fatal("offline copy must still have a cache")
	}
	// fetchTokenMeta on a copy must not panic when results are cached.
	sim := &models.SimulationResult{AssetTransfers: []models.AssetTransfer{{Asset: models.AssetRef{Kind: models.AssetERC20, Address: usdc.Hex()}}}}
	same.tokens.put(1, usdc, tokenMeta{symbol: "USDC"})
	if m := same.fetchTokenMeta(context.Background(), 1, sim); m[usdc].symbol != "USDC" {
		t.Fatalf("cached metadata not used: %v", m)
	}
}

type panicSimulator struct{}

func (panicSimulator) Name() string { return "panic" }
func (panicSimulator) Capabilities() models.SimulatorCapabilities {
	return models.SimulatorCapabilities{}
}
func (panicSimulator) Simulate(context.Context, interfaces.SimulationRequest) (*models.SimulationResult, error) {
	panic("boom")
}

// The simulation runs outside the HTTP handler's panic recovery: a bug there
// must degrade the report, not crash the process.
func TestSimulatorPanicDegrades(t *testing.T) {
	a, _ := Build(BuildOptions{Simulator: panicSimulator{}})
	r, err := a.Analyze(context.Background(), Request{Tx: simpleTx(), Simulate: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Simulation.Status != models.SimError {
		t.Fatalf("sim = %+v", r.Simulation)
	}
}
