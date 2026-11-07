package analyzer

import (
	"context"
	"testing"

	"github.com/pri-3x/txshield/tests/fixtures"
)

// Full analysis pipeline (decode, reputation, contract facts from a fake
// inspector, rules, scoring, report) without network I/O. Simulation results
// come from the scenario fixtures, so this measures TxShield's own overhead,
// not simulation latency (see BenchmarkAnvil* in tests/integration).

func benchScenario(b *testing.B, name string) {
	scenarios, err := fixtures.Load()
	if err != nil {
		b.Fatal(err)
	}
	for _, s := range scenarios {
		if s.Name != name {
			continue
		}
		t := &testing.T{}
		a, tx, dopts, simulate := buildFor(t, s)
		req := Request{Tx: tx, Decode: dopts, Simulate: simulate, BlockNumber: 19000000}
		b.ReportAllocs()
		for b.Loop() {
			if _, err := a.Analyze(context.Background(), req); err != nil {
				b.Fatal(err)
			}
		}
		return
	}
	b.Fatalf("scenario %s not found", name)
}

func BenchmarkAnalyzeUnlimitedApprovalBlocklisted(b *testing.B) {
	benchScenario(b, "malicious-unlimited-approval-blocklisted-spender")
}
func BenchmarkAnalyzeDrainerWithSimulation(b *testing.B) {
	benchScenario(b, "malicious-fake-claim-drainer")
}
func BenchmarkAnalyzeUniversalRouterSwap(b *testing.B) {
	benchScenario(b, "benign-universal-router-swap")
}
