package api

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pri-3x/txshield/internal/analyzer"
	"github.com/pri-3x/txshield/internal/evm"
	"github.com/pri-3x/txshield/internal/netguard"
	"github.com/pri-3x/txshield/internal/simulator"
	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
	"github.com/pri-3x/txshield/pkg/txerrors"
)

// Engine bundles the analysis components the API exposes. Optional parts
// are nil when not configured: Chains/Inspector (no RPC), Simulator
// (TXSHIELD_SIMULATOR=none), Store (no database).
type Engine struct {
	Analyzer     *analyzer.Analyzer
	Chains       *evm.Registry
	Inspector    interfaces.ContractInspector
	Simulator    interfaces.Simulator
	Store        interfaces.AnalysisStore
	AllowUserRPC bool
	// UserRPCSimTimeout bounds rpc-trace simulations on user endpoints.
	UserRPCSimTimeout time.Duration
}

// TxRequest is the transaction part of request bodies.
type TxRequest = models.TransactionRequest

// AnalyzeRequest is the body of POST /api/v1/analyze and
// POST /api/v1/approvals/analyze.
type AnalyzeRequest struct {
	TxRequest
	// ABI optionally provides the target contract's JSON ABI.
	ABI json.RawMessage `json:"abi,omitempty"`
	// Simulate runs a fork simulation (default true for /analyze, false for
	// /approvals/analyze).
	Simulate *bool `json:"simulate,omitempty"`
	// Persist stores the analysis when persistence is enabled (default true).
	Persist *bool `json:"persist,omitempty"`
	// RPCURL is a caller-supplied endpoint; accepted only when the operator
	// enables TXSHIELD_ALLOW_USER_RPC, and always SSRF-checked.
	RPCURL string `json:"rpcUrl,omitempty"`
}

// SimulateRequest is the body of POST /api/v1/simulate.
type SimulateRequest struct {
	TxRequest
	RPCURL string `json:"rpcUrl,omitempty"`
}

// chainSet is the chain-dependent component set for one request.
type chainSet struct {
	chains    *evm.Registry
	inspector interfaces.ContractInspector
	simulator interfaces.Simulator
	userRPC   bool
	warning   string
}

// resolveChain picks components for a request: the operator's configured
// endpoint, a caller-supplied endpoint (if allowed), or offline mode.
func (e *Engine) resolveChain(ctx context.Context, chainID uint64, rpcURL string) (chainSet, error) {
	if rpcURL != "" {
		if !e.AllowUserRPC {
			return chainSet{}, txerrors.Invalid(txerrors.FieldError{Field: "rpcUrl", Message: "caller-supplied RPC endpoints are disabled on this server"})
		}
		if err := netguard.CheckURL(ctx, rpcURL, nil); err != nil {
			return chainSet{}, txerrors.Invalid(txerrors.FieldError{Field: "rpcUrl", Message: err.Error()})
		}
		// Smaller response cap than operator endpoints: the node is untrusted
		// and can return maximum-size responses to every call.
		reg := evm.NewRegistry(map[uint64]string{chainID: rpcURL}, evm.Options{PublicOnly: true, Retry: evm.RetryPolicy{MaxAttempts: 2}, MaxResponseBytes: 8 << 20})
		// Anvil would make its own connections (bypassing the dial-time SSRF
		// check), so caller-supplied endpoints only get the rpc-trace backend.
		return chainSet{
			chains: reg, inspector: evm.NewInspector(reg, 256), simulator: simulator.NewRPCTrace(reg, e.UserRPCSimTimeout),
			userRPC: true, warning: "caller-supplied RPC endpoint: simulation limited to rpc-trace (partial)",
		}, nil
	}
	if e.Chains != nil {
		if _, err := e.Chains.RPCURL(chainID); err == nil {
			return chainSet{chains: e.Chains, inspector: e.Inspector, simulator: e.Simulator}, nil
		}
	}
	return chainSet{warning: "no RPC endpoint is configured for this chain: offline analysis only (no contract checks, no simulation)"}, nil
}

// analyzerFor returns an analyzer bound to cs.
func (e *Engine) analyzerFor(cs chainSet) *analyzer.Analyzer {
	var chains interfaces.ChainRegistry
	if cs.chains != nil {
		chains = cs.chains
	}
	return e.Analyzer.With(chains, cs.inspector, cs.simulator)
}
