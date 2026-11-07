package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/txshield/txshield/pkg/models"
)

const (
	sender      = "0x1111111111111111111111111111111111111111"
	usdcAddr    = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
	approveBad  = "0x095ea7b3000000000000000000000000dead000000000000000000000000000000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	transferOne = "0xa9059cbb00000000000000000000000022222222222222222222222222222222222222220000000000000000000000000000000000000000000000000000000000000001"
)

func blocklist(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "list.json")
	doc := `{"name":"t","entries":[{"address":"0xdead000000000000000000000000000000000001","status":"blocked","reason":"test"}]}`
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAnalyzeHighRiskExitCode(t *testing.T) {
	code, out, errs := runCLI("analyze", "--json", "--from", sender, "--to", usdcAddr, "--data", approveBad, "--reputation", blocklist(t))
	if code != ExitRiskHigh {
		t.Fatalf("code %d (stderr %s)", code, errs)
	}
	var r models.RiskReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	if r.Risk.Category != models.RiskCritical || r.Simulation.Status != models.SimNotRun || r.Simulation.IncompleteReasons[0] != "no simulation backend configured" {
		t.Fatalf("%+v / %+v", r.Risk, r.Simulation)
	}
	// --fail-on 101 disables risk-based failure for reporting-only CI jobs.
	if code, _, _ := runCLI("analyze", "--fail-on", "101", "--from", sender, "--to", usdcAddr, "--data", approveBad, "--reputation", blocklist(t)); code != ExitOK {
		t.Fatalf("fail-on 101: code %d", code)
	}
}

func TestAnalyzeBenignText(t *testing.T) {
	code, out, errs := runCLI("analyze", "--chain", "sepolia", "--from", sender, "--to", usdcAddr, "--data", transferOne)
	if code != ExitOK {
		t.Fatalf("code %d: %s", code, errs)
	}
	for _, want := range []string{"Risk score: 0/100", models.NoSignificantRisks, "Sepolia", "static analysis only", "cannot guarantee"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(strings.ToLower(strings.ReplaceAll(out, models.Disclaimer, "")), "safe") {
		t.Fatal("output must never claim safety")
	}
}

func TestAnalyzeUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"analyze"}, // missing --from
		{"analyze", "--from", sender, "--to", usdcAddr, "--chain", "narnia"},
		{"analyze", "--from", sender, "--to", usdcAddr, "--fail-on", "500"},
		{"analyze", "--from", sender, "--to", usdcAddr, "--reputation", "/no/such/file.json"},
		{"analyze", "--from", sender, "--to", usdcAddr, "--scoring-config", "/no/such/file.json"},
	} {
		if code, _, _ := runCLI(args...); code != ExitUsage {
			t.Errorf("%v: code %d, want %d", args, code, ExitUsage)
		}
	}
}
