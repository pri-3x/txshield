// Command txshield is the TxShield CLI and API server.
//
// Implemented in Phase 1:
//
//	txshield serve     start the HTTP API server
//	txshield version   print version information
//
//	txshield decode    decode calldata offline (Phase 2)
//	txshield analyze   offline security analysis (Phase 3; RPC + simulation in Phase 5)
//	txshield simulate        fork simulation
//	txshield approval-check  current on-chain permissions for a spender
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// Exit codes are part of the CLI contract for CI integrations. Risk-based
// codes (for `analyze`) are reserved now so they never collide later.
const (
	ExitOK         = 0
	ExitError      = 1 // runtime or infrastructure failure
	ExitUsage      = 2 // invalid flags or arguments
	ExitRiskHigh   = 3 // reserved: analysis completed, risk >= --fail-on threshold
	ExitIncomplete = 4 // reserved: analysis completed but simulation was partial/none and --require-simulation was set
	// ExitReverted (5) is defined in simulate.go.
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string, stdout, stderr io.Writer) int
}

func commands() []command {
	return []command{
		{"serve", "Start the HTTP API server", runServe},
		{"analyze", "Analyze a transaction for security risks (offline, or with --rpc for contract checks and simulation)", runAnalyze},
		{"simulate", "Simulate a transaction on a private local fork", runSimulate},
		{"approval-check", "Read the token permissions currently in force for a spender", runApprovalCheck},
		{"decode", "Decode transaction calldata offline", runDecode},
		{"version", "Print version information", runVersion},
		{"healthcheck", "Probe a running server's health endpoint (for container health checks)", runHealthcheck},
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage(stderr)
		if len(args) == 0 {
			return ExitUsage
		}
		return ExitOK
	}
	if args[0] == "--version" || args[0] == "-version" {
		args = append([]string{"version"}, args[1:]...)
	}
	for _, c := range commands() {
		if c.name == args[0] {
			return c.run(ctx, args[1:], stdout, stderr)
		}
	}
	fmt.Fprintf(stderr, "txshield: unknown command %q\n\n", args[0])
	usage(stderr)
	return ExitUsage
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "TxShield - EVM transaction security and simulation engine")
	fmt.Fprintln(w, "\nUsage:\n  txshield <command> [flags]\n\nCommands:")
	for _, c := range commands() {
		fmt.Fprintf(w, "  %-15s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(w, "\nRun 'txshield <command> -h' for command flags.")
}

// parseFlags parses fs and maps errors to exit codes. It returns ok=false
// when the caller should exit with code.
func parseFlags(fs *flag.FlagSet, args []string) (code int, ok bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK, false
		}
		return ExitUsage, false
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(fs.Output(), "unexpected arguments: %v\n", fs.Args())
		return ExitUsage, false
	}
	return ExitOK, true
}
