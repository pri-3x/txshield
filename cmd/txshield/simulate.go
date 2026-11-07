package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
)

// ExitReverted: the simulation ran and the transaction reverted.
const ExitReverted = 5

func runSimulate(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("simulate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := addTxFlags(fs)
	rpcURL := fs.String("rpc", "", "RPC endpoint (http/https) to fork from (required)")
	simKind := fs.String("simulator", "anvil", "simulation backend: anvil or rpc-trace")
	anvilPath := fs.String("anvil-path", "anvil", "path to the anvil binary")
	asJSON := fs.Bool("json", false, "print the simulation result as JSON")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: txshield simulate --rpc URL (--tx tx.json | --from 0x... --to 0x... --data 0x...) [flags]")
		fmt.Fprintln(stderr, "\nExecutes the transaction on a private local fork. Nothing is signed or broadcast.")
		fmt.Fprintln(stderr, "Exit codes: 0 executed, 5 reverted, 1 simulation could not run, 2 invalid input.")
		fs.PrintDefaults()
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if *rpcURL == "" {
		fmt.Fprintln(stderr, "simulate: --rpc is required")
		return ExitUsage
	}
	if *simKind == "none" {
		fmt.Fprintln(stderr, "simulate: --simulator must be anvil or rpc-trace")
		return ExitUsage
	}
	tx, ch, err := in.parse(fs)
	if err != nil {
		printCLIError(stderr, "simulate", err)
		return ExitUsage
	}
	be, err := buildBackends(*rpcURL, ch.ID, *simKind, *anvilPath)
	if err != nil {
		fmt.Fprintf(stderr, "simulate: %v\n", err)
		return ExitUsage
	}
	defer be.close()

	var block uint64
	if r, err := be.registry.Client(ctx, ch.ID); err != nil {
		printCLIError(stderr, "simulate", err)
		return exitFor(err)
	} else if info, err := r.ResolveBlock(ctx, tx.Block); err != nil {
		printCLIError(stderr, "simulate", err)
		return exitFor(err)
	} else {
		block = info.Number
	}
	res, err := be.simulator.Simulate(ctx, interfaces.SimulationRequest{Tx: tx, BlockNumber: block})
	if err != nil {
		printCLIError(stderr, "simulate", err)
		fmt.Fprintln(stderr, "The simulation could not run; this says nothing about whether the transaction would succeed.")
		return exitFor(err)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			return ExitError
		}
	} else {
		printSimulation(stdout, res, "")
	}
	if res.Status == models.SimReverted {
		return ExitReverted
	}
	return ExitOK
}

// printSimulation renders a simulation result for terminals. Revert
// reasons and other chain-provided strings are sanitized.
func printSimulation(w io.Writer, s *models.SimulationResult, ind string) {
	fmt.Fprintf(w, "%sStatus:       %s (%s, backend %s)\n", ind, s.Status, s.Completeness, s.Backend)
	if s.Status == models.SimNotRun || s.Status == models.SimError {
		for _, r := range s.IncompleteReasons {
			fmt.Fprintf(w, "%s  - %s\n", ind, clean(r))
		}
		return
	}
	fmt.Fprintf(w, "%sState:        block %d %s\n", ind, s.BlockNumber, s.BlockHash)
	gas := fmt.Sprintf("%d used", s.GasUsed)
	if s.GasEstimate != nil {
		gas += fmt.Sprintf(", estimate %d", *s.GasEstimate)
	}
	fmt.Fprintf(w, "%sGas:          %s\n", ind, gas)
	if s.RevertReason != "" {
		fmt.Fprintf(w, "%sRevert:       %s\n", ind, clean(s.RevertReason))
	}
	if len(s.BalanceChanges) > 0 {
		fmt.Fprintf(w, "%sBalance changes:\n", ind)
		for _, b := range s.BalanceChanges {
			asset := "native"
			if b.Asset.Kind != models.AssetNative {
				asset = string(b.Asset.Kind) + " " + b.Asset.Address
			}
			fmt.Fprintf(w, "%s  %s %s: %s -> %s (delta %s)\n", ind, b.Owner, asset, b.Before, b.After, b.Delta)
		}
	}
	if len(s.AssetTransfers) > 0 {
		fmt.Fprintf(w, "%sAsset transfers (%d):\n", ind, len(s.AssetTransfers))
		for i, t := range s.AssetTransfers {
			if i == 20 {
				fmt.Fprintf(w, "%s  ... %d more\n", ind, len(s.AssetTransfers)-20)
				break
			}
			asset := "native"
			if t.Asset.Kind != models.AssetNative {
				asset = string(t.Asset.Kind) + " " + t.Asset.Address
				if t.Asset.TokenID != "" {
					asset += " #" + string(t.Asset.TokenID)
				}
			}
			fmt.Fprintf(w, "%s  %s  %s -> %s  amount %s\n", ind, asset, t.From, t.To, t.Amount)
		}
	}
	for _, r := range s.IncompleteReasons {
		fmt.Fprintf(w, "%sIncomplete:   %s\n", ind, clean(r))
	}
	for _, n := range s.Notes {
		fmt.Fprintf(w, "%sNote:         %s\n", ind, clean(n))
	}
}
