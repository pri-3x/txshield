package analyzer

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/pri-3x/txshield/internal/security/reputation"
	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
	"github.com/pri-3x/txshield/pkg/txerrors"
	"github.com/pri-3x/txshield/tests/fixtures"
)

// fakeInspector serves fixed contract facts.
type fakeInspector struct {
	m   map[common.Address]models.ContractInfo
	err error
}

func (f fakeInspector) Inspect(_ context.Context, _ uint64, a common.Address, _ uint64) (*models.ContractInfo, error) {
	if f.err != nil {
		return nil, f.err
	}
	if info, ok := f.m[a]; ok {
		return &info, nil
	}
	// Addresses not listed in the fixture are treated as plain accounts.
	return &models.ContractInfo{Address: a.Hex(), IsContract: false}, nil
}

// fakeSimulator returns a fixed result.
type fakeSimulator struct {
	res *models.SimulationResult
	err error
}

func (fakeSimulator) Name() string { return "fixture" }
func (fakeSimulator) Capabilities() models.SimulatorCapabilities {
	return models.SimulatorCapabilities{}
}
func (f fakeSimulator) Simulate(context.Context, interfaces.SimulationRequest) (*models.SimulationResult, error) {
	return f.res, f.err
}

func buildFor(t *testing.T, s fixtures.Scenario) (*Analyzer, *models.Transaction, interfaces.DecodeOptions, bool) {
	t.Helper()
	tx, err := models.ParseTransaction(s.Tx, models.ParseLimits{MaxCalldataBytes: 1 << 20})
	if err != nil {
		t.Fatalf("fixture tx invalid: %v", err)
	}
	opts := BuildOptions{EngineVersion: "test"}
	if len(s.Contracts) > 0 {
		m := map[common.Address]models.ContractInfo{}
		for _, c := range s.Contracts {
			m[common.HexToAddress(c.Address)] = c
		}
		opts.Inspector = fakeInspector{m: m}
	}
	if s.Simulation != nil {
		opts.Simulator = fakeSimulator{res: s.Simulation}
	}
	if len(s.Reputation) > 0 {
		opts.ExtraReputation = []interfaces.ReputationProvider{reputation.NewStaticProvider("list:fixture", models.ReputationSourceList, s.Reputation)}
	}
	a, err := Build(opts)
	if err != nil {
		t.Fatal(err)
	}
	var dopts interfaces.DecodeOptions
	if len(s.ABI) > 0 {
		dopts.ABIJSON = s.ABI
	}
	return a, tx, dopts, s.Simulation != nil
}

func TestScenarios(t *testing.T) {
	scenarios, err := fixtures.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(scenarios) < 15 {
		t.Fatalf("only %d scenarios loaded", len(scenarios))
	}
	for _, s := range scenarios {
		t.Run(s.Name, func(t *testing.T) {
			a, tx, dopts, simulate := buildFor(t, s)
			r, err := a.Analyze(context.Background(), Request{Tx: tx, Decode: dopts, Simulate: simulate, RequestID: "req-1", BlockNumber: 19000000})
			if err != nil {
				t.Fatal(err)
			}
			fired := map[string]bool{}
			for _, f := range r.Findings {
				fired[f.RuleID] = true
			}
			for _, id := range s.Expect.Rules {
				if !fired[id] {
					t.Errorf("expected %s to fire; fired: %v", id, keys(fired))
				}
			}
			for _, id := range s.Expect.AbsentRules {
				if fired[id] {
					t.Errorf("%s must not fire (false-positive guard)", id)
				}
			}
			if r.Risk.Score < s.Expect.MinScore || r.Risk.Score > s.Expect.MaxScore {
				t.Errorf("score %d outside [%d,%d]; contributions: %+v", r.Risk.Score, s.Expect.MinScore, s.Expect.MaxScore, r.Risk.Contributions)
			}
			if s.Expect.Category != "" && r.Risk.Category != s.Expect.Category {
				t.Errorf("category %s, want %s", r.Risk.Category, s.Expect.Category)
			}
			if s.Expect.Verdict != "" && r.Verdict != s.Expect.Verdict {
				t.Errorf("verdict %q, want %q", r.Verdict, s.Expect.Verdict)
			}
			assertReportInvariants(t, r)
			t.Logf("score=%d category=%s confidence=%s rules=%v", r.Risk.Score, r.Risk.Category, r.Risk.Confidence, keys(fired))
		})
	}
}

// assertReportInvariants checks properties every report must have.
func assertReportInvariants(t *testing.T, r *models.RiskReport) {
	t.Helper()
	if r.Disclaimer == "" || len(r.Recommendations) == 0 || len(r.EnabledChecks) == 0 || r.ID == "" || r.Simulation == nil {
		t.Errorf("incomplete report: %+v", r)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(r.Verdict), "safe") || strings.Contains(strings.ToLower(string(b)), `"verdict":"safe`) {
		t.Errorf("report must never call a transaction safe: %q", r.Verdict)
	}
	for _, f := range r.Findings {
		if f.Source == "" || f.Fingerprint == "" || f.Mitigation == "" {
			t.Errorf("finding missing provenance: %+v", f)
		}
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

var (
	from = common.HexToAddress("0x1111111111111111111111111111111111111111")
	usdc = common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
)

func simpleTx() *models.Transaction {
	data, _ := new(big.Int).SetString("a9059cbb0000000000000000000000002222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000000a", 16)
	return &models.Transaction{ChainID: 1, From: from, To: &usdc, Value: new(big.Int), Data: data.Bytes()}
}

func TestOfflineAnalysis(t *testing.T) {
	a, err := Build(BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	r, err := a.Analyze(context.Background(), Request{Tx: simpleTx()})
	if err != nil {
		t.Fatal(err)
	}
	if r.Simulation.Status != models.SimNotRun || r.Risk.Confidence != models.ConfidenceMedium {
		t.Fatalf("offline: sim=%s confidence=%s", r.Simulation.Status, r.Risk.Confidence)
	}
	if r.Transaction.ChainName != "Ethereum Mainnet" || !strings.Contains(r.Transaction.Description, "transfer(address,uint256)") {
		t.Fatalf("summary = %+v", r.Transaction)
	}
	joined := strings.Join(r.Warnings, ";") + strings.Join(r.Recommendations, ";")
	if !strings.Contains(joined, "contract facts") || !strings.Contains(joined, "static analysis only") {
		t.Fatalf("offline limitations must be stated: %v / %v", r.Warnings, r.Recommendations)
	}
}

func TestSimulatorFailureDegradesNotFails(t *testing.T) {
	a, _ := Build(BuildOptions{Simulator: fakeSimulator{err: txerrors.New(txerrors.KindUnavailable, "rpc_down", "upstream RPC unavailable")}})
	r, err := a.Analyze(context.Background(), Request{Tx: simpleTx(), Simulate: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Simulation.Status != models.SimError || r.Simulation.Completeness != models.CompletenessNone {
		t.Fatalf("sim = %+v", r.Simulation)
	}
	if !strings.Contains(strings.Join(r.Warnings, ";"), "says nothing about whether the transaction would succeed") {
		t.Fatalf("warnings = %v", r.Warnings)
	}
	for _, f := range r.Findings {
		if f.RuleID == "TXS-SIM-001" {
			t.Fatal("infrastructure failure must not be reported as a revert")
		}
	}
}

func TestInspectorFailureWarns(t *testing.T) {
	a, _ := Build(BuildOptions{Inspector: fakeInspector{err: errors.New("rpc timeout")}})
	r, err := a.Analyze(context.Background(), Request{Tx: simpleTx()})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(r.Warnings, ";"), "contract facts unavailable") {
		t.Fatalf("warnings = %v", r.Warnings)
	}
}

func TestCancelledAndInvalid(t *testing.T) {
	a, _ := Build(BuildOptions{})
	if _, err := a.Analyze(context.Background(), Request{}); txerrors.KindOf(err) != txerrors.KindInvalidInput {
		t.Fatalf("nil tx: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.Analyze(ctx, Request{Tx: simpleTx()}); err == nil {
		t.Fatal("cancelled context must fail")
	}
	if _, err := New(Deps{}); err == nil {
		t.Fatal("missing deps must be rejected")
	}
}

func TestVerdictWording(t *testing.T) {
	low := models.RiskAssessment{Score: 0, Category: models.RiskLow}
	if v := verdict(low, nil); v != models.NoSignificantRisks {
		t.Fatal(v)
	}
	if v := verdict(models.RiskAssessment{Score: 4, Category: models.RiskLow}, []models.Finding{{Severity: models.SeverityLow}}); !strings.HasPrefix(v, "Low observed risk") {
		t.Fatal(v)
	}
	if v := verdict(models.RiskAssessment{Score: 85, Category: models.RiskCritical}, []models.Finding{{Severity: models.SeverityCritical}}); !strings.HasPrefix(v, "Critical risk: 1") {
		t.Fatal(v)
	}
}

func TestNewIDFormat(t *testing.T) {
	id := newID()
	if len(id) != 36 || id[14] != '4' || strings.Count(id, "-") != 4 {
		t.Fatalf("bad uuid %s", id)
	}
}
