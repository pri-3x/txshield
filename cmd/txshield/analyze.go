package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/txshield/txshield/internal/analyzer"
	"github.com/txshield/txshield/internal/version"
	"github.com/txshield/txshield/pkg/interfaces"
	"github.com/txshield/txshield/pkg/models"
)

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func runAnalyze(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := addTxFlags(fs)
	rpcURL := fs.String("rpc", "", "RPC endpoint (http/https) for contract checks and simulation; omit for offline analysis")
	simKind := fs.String("simulator", "", "simulation backend with --rpc: anvil (default), rpc-trace, or none")
	anvilPath := fs.String("anvil-path", "anvil", "path to the anvil binary")
	abiPath := fs.String("abi", "", "JSON ABI file for the target contract")
	scoringPath := fs.String("scoring-config", "", "JSON file overriding scoring weights")
	failOn := fs.Int("fail-on", 60, "exit with code 3 when the risk score is >= this value (101 disables)")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	var lists stringList
	fs.Var(&lists, "reputation", "reputation list file (JSON); repeatable")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: txshield analyze --from 0x... [--to 0x...] [--data 0x...] [--value wei] [--rpc URL] [flags]")
		fmt.Fprintln(stderr, "\nWithout --rpc: offline static analysis of calldata plus reputation lists.")
		fmt.Fprintln(stderr, "With --rpc: adds on-chain contract checks and a local fork simulation (anvil).")
		fmt.Fprintln(stderr, "Never requires a private key and never broadcasts.")
		fs.PrintDefaults()
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if *failOn < 0 || *failOn > 101 {
		fmt.Fprintln(stderr, "analyze: --fail-on must be between 0 and 101 (101 disables)")
		return ExitUsage
	}
	tx, ch, err := in.parse(fs)
	if err != nil {
		printCLIError(stderr, "analyze", err)
		return ExitUsage
	}
	var dopts interfaces.DecodeOptions
	if *abiPath != "" {
		if dopts.ABIJSON, err = readLimited(*abiPath, cliMaxABIBytes); err != nil {
			fmt.Fprintf(stderr, "analyze: %v\n", err)
			return ExitUsage
		}
	}
	be, err := buildBackends(*rpcURL, ch.ID, *simKind, *anvilPath)
	if err != nil {
		fmt.Fprintf(stderr, "analyze: %v\n", err)
		return ExitUsage
	}
	defer be.close()
	opts := analyzer.BuildOptions{
		EngineVersion:     version.Version,
		ReputationFiles:   lists,
		ScoringConfigPath: *scoringPath,
		Inspector:         be.inspector,
		Simulator:         be.simulator,
	}
	if be.registry != nil {
		opts.Chains = be.registry
	}
	a, err := analyzer.Build(opts)
	if err != nil {
		fmt.Fprintf(stderr, "analyze: %v\n", err)
		return ExitUsage
	}
	// Simulation is always requested; without a backend the report says so
	// explicitly instead of silently skipping it.
	report, err := a.Analyze(ctx, analyzer.Request{Tx: tx, Decode: dopts, Simulate: true})
	if err != nil {
		printCLIError(stderr, "analyze", err)
		return exitFor(err)
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return ExitError
		}
	} else {
		printReport(stdout, report)
	}
	if report.Risk.Score >= *failOn {
		return ExitRiskHigh
	}
	return ExitOK
}

func readLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // user-chosen local file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, max)
	}
	return b, nil
}

func printReport(w io.Writer, r *models.RiskReport) {
	line := strings.Repeat("-", 72)
	fmt.Fprintln(w, line)
	fmt.Fprintf(w, "Risk score: %d/100  (%s, confidence %s)\n", r.Risk.Score, r.Risk.Category, r.Risk.Confidence)
	fmt.Fprintf(w, "Verdict:    %s\n", clean(r.Verdict))
	fmt.Fprintln(w, line)
	t := r.Transaction
	chain := t.ChainName
	if chain == "" {
		chain = fmt.Sprintf("chain %d", t.ChainID)
	}
	fmt.Fprintf(w, "Transaction: %s\n", clean(t.Description))
	fmt.Fprintf(w, "  network %s, from %s, block %s\n", chain, t.From, t.Block)

	fmt.Fprintln(w, "\nSimulation:")
	printSimulation(w, r.Simulation, "  ")

	fmt.Fprintf(w, "\nFindings (%d):\n", len(r.Findings))
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "  none from enabled checks")
	}
	for _, f := range r.Findings {
		fmt.Fprintf(w, "  [%s/%s confidence, %s] %s  %s\n", strings.ToUpper(f.Severity.String()), f.Confidence, f.Source, f.RuleID, clean(f.Title))
		fmt.Fprintf(w, "      %s\n", clean(f.Description))
	}

	if len(r.Approvals) > 0 {
		fmt.Fprintf(w, "\nPermissions in this transaction (%d):\n", len(r.Approvals))
		for _, g := range r.Approvals {
			amount := string(g.Amount)
			switch {
			case g.Revocation:
				amount = "revoked"
			case g.Unlimited:
				amount = "UNLIMITED"
			case g.TokenID != "":
				amount = "token #" + string(g.TokenID)
			}
			owner := g.Owner
			if g.OwnerIsSender {
				owner += " (you)"
			}
			fmt.Fprintf(w, "  %s: token %s, spender %s, owner %s, amount %s\n", g.Kind, g.Token, g.Spender, owner, amount)
		}
	}

	fmt.Fprintln(w, "\nRecommended actions:")
	for _, rec := range r.Recommendations {
		fmt.Fprintf(w, "  - %s\n", clean(rec))
	}
	if len(r.Warnings) > 0 {
		fmt.Fprintln(w, "\nAnalysis limitations:")
		for _, wn := range r.Warnings {
			fmt.Fprintf(w, "  ! %s\n", clean(wn))
		}
	}
	fmt.Fprintf(w, "\n%s\n", r.Disclaimer)
}
