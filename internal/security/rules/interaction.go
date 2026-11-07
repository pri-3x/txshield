package rules

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/txshield/txshield/internal/security/approvals"
	"github.com/txshield/txshield/internal/security/core"
	"github.com/txshield/txshield/internal/security/reputation"
	"github.com/txshield/txshield/pkg/interfaces"
	"github.com/txshield/txshield/pkg/models"
)

// sortedAddrs returns the keys of roles in a stable order.
func sortedAddrs(roles core.AddressRoles) []common.Address {
	out := make([]common.Address, 0, len(roles))
	for a := range roles {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hex() < out[j].Hex() })
	return out
}

// onlySpenderOrSender reports whether an address appears solely as an
// approval spender (covered by TXS-APPROVAL-005) or as the sender.
func onlySpenderOrSender(roles core.AddressRoles, a common.Address) bool {
	for r := range roles[a] {
		if r != core.RoleSpender && r != core.RoleSender {
			return false
		}
	}
	return true
}

func reputationFinding(meta models.RuleMetadata, ac *interfaces.AnalysisContext, status models.ReputationStatus) []models.Finding {
	roles := core.CollectAddresses(ac.Tx, ac.Decoded, ac.Approvals, ac.Simulation)
	var out []models.Finding
	for _, a := range sortedAddrs(roles) {
		recs := ac.Reputation[a]
		if reputation.Effective(recs) != status || onlySpenderOrSender(roles, a) {
			continue
		}
		f := core.NewFinding(meta, a.Hex())
		f.Source, f.Confidence = approvals.ReputationSource(recs, status)
		f.Description = fmt.Sprintf("%s (%s) is %s according to %s.", a.Hex(), roles.Roles(a), status, approvals.SourcesOf(recs, status))
		f.Evidence = approvals.ReputationEvidence(recs)
		f.Subjects = []string{a.Hex()}
		out = append(out, f)
	}
	return out
}

// --- TXS-INTERACT-001 -------------------------------------------------------

type blocklistedRule struct{}

func (blocklistedRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-INTERACT-001", Name: "Interaction with a blocklisted address",
		Description:        "The transaction calls, pays, or references an address that a configured reputation source blocklists.",
		Category:           models.CategoryReputation,
		DefaultSeverity:    models.SeverityCritical,
		DefaultConfidence:  models.ConfidenceHigh,
		Mitigation:         "Do not sign. Verify the site or application that produced this transaction.",
		FalsePositiveNotes: "Reputation lists can be stale or wrong. The finding names the list and reason; operator allowlists override external opinions.",
	}
}

func (r blocklistedRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	return reputationFinding(r.Metadata(), ac, models.ReputationBlocked), nil
}

// --- TXS-INTERACT-002 -------------------------------------------------------

type suspiciousRule struct{}

func (suspiciousRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-INTERACT-002", Name: "Interaction with a suspicious address",
		Description:        "The transaction involves an address that a configured reputation source marks as suspicious.",
		Category:           models.CategoryReputation,
		DefaultSeverity:    models.SeverityHigh,
		DefaultConfidence:  models.ConfidenceMedium,
		Mitigation:         "Investigate the address and the reason given before signing.",
		FalsePositiveNotes: "Suspicious is weaker than blocked and often reflects heuristics by the source.",
	}
}

func (r suspiciousRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	return reputationFinding(r.Metadata(), ac, models.ReputationSuspicious), nil
}

// --- TXS-INTERACT-003 -------------------------------------------------------

type unknownTargetRule struct{}

func (unknownTargetRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-INTERACT-003", Name: "Target contract has no reputation record",
		Description:        "None of the configured reputation sources knows the contract being called. This requires investigation, not alarm.",
		Category:           models.CategoryInteraction,
		DefaultSeverity:    models.SeverityLow,
		DefaultConfidence:  models.ConfidenceLow,
		Mitigation:         "Confirm the contract address through the project's official channels.",
		FalsePositiveNotes: "Most legitimate contracts are not on any list. Only reported when reputation sources are configured; plain transfers to accounts are not reported.",
	}
}

func (r unknownTargetRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	if len(ac.ReputationSources) == 0 || ac.Tx.To == nil || ac.Decoded == nil || ac.Decoded.Kind == models.CallNativeTransfer {
		return nil, nil
	}
	to := *ac.Tx.To
	if len(ac.Reputation[to]) > 0 {
		return nil, nil
	}
	if info := ac.Contracts[to]; ac.ContractsKnown && info != nil && !info.IsContract {
		return nil, nil // TXS-INTERACT-005 covers calldata to accounts
	}
	f := core.NewFinding(r.Metadata(), to.Hex())
	f.Source = models.SourceHeuristic
	f.Description = fmt.Sprintf("No reputation record for target %s in %d source(s).", to.Hex(), len(ac.ReputationSources))
	f.Subjects = []string{to.Hex()}
	return []models.Finding{f}, nil
}

// --- TXS-INTERACT-004 -------------------------------------------------------

type unverifiedRule struct{}

func (unverifiedRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-INTERACT-004", Name: "Unverified contract",
		Description:        "A called contract has no verified source code according to the configured verification source, so its behavior cannot be reviewed.",
		Category:           models.CategoryInteraction,
		DefaultSeverity:    models.SeverityMedium,
		DefaultConfidence:  models.ConfidenceMedium,
		Mitigation:         "Prefer contracts with verified source code; review the simulation results carefully.",
		FalsePositiveNotes: "New deployments, some MEV and account-abstraction contracts are legitimately unverified. Silent when no verification source is configured.",
	}
}

func (r unverifiedRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	var out []models.Finding
	seen := map[common.Address]bool{}
	core.Walk(ac.Tx, ac.Decoded, func(fr core.Frame) {
		if fr.Call.CallType != models.CallTypeCall || fr.Call.Target == "" {
			return
		}
		a := common.HexToAddress(fr.Call.Target)
		info := ac.Contracts[a]
		if seen[a] || info == nil || !info.IsContract || info.Verified == nil || *info.Verified {
			return
		}
		seen[a] = true
		f := core.NewFinding(r.Metadata(), a.Hex())
		f.Description = fmt.Sprintf("Contract %s has no verified source code.", a.Hex())
		f.Subjects = []string{a.Hex()}
		out = append(out, f)
	})
	return out, nil
}

// --- TXS-INTERACT-005 -------------------------------------------------------

type calldataToEOARule struct{}

func (calldataToEOARule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-INTERACT-005", Name: "Function call sent to an account without code",
		Description:        "The transaction carries calldata but the target has no contract code. The data will be ignored and any value goes to the account. This often means the wrong address was used.",
		Category:           models.CategoryInteraction,
		DefaultSeverity:    models.SeverityMedium,
		DefaultConfidence:  models.ConfidenceHigh,
		Mitigation:         "Check the target address. If you meant to interact with a contract, it is not deployed at this address on this chain.",
		FalsePositiveNotes: "Some users attach notes as calldata to plain transfers, and counterfactual smart accounts have no code until deployed.",
	}
}

func (r calldataToEOARule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	if !ac.ContractsKnown || ac.Tx.To == nil || len(ac.Tx.Data) == 0 {
		return nil, nil
	}
	info := ac.Contracts[*ac.Tx.To]
	if info == nil || info.IsContract {
		return nil, nil
	}
	f := core.NewFinding(r.Metadata(), ac.Tx.To.Hex())
	f.Description = fmt.Sprintf("%s has no code at block %d, but %d bytes of calldata are attached.", ac.Tx.To.Hex(), info.AtBlock, len(ac.Tx.Data))
	f.Subjects = []string{ac.Tx.To.Hex()}
	return []models.Finding{f}, nil
}

// --- TXS-INTERACT-006 -------------------------------------------------------

type unexpectedCallsRule struct{}

func (unexpectedCallsRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-INTERACT-006", Name: "Execution reaches contracts not named in the calldata",
		Description:        "The simulated call trace shows state-changing calls to contracts that do not appear anywhere in the transaction's calldata.",
		Category:           models.CategoryInteraction,
		DefaultSeverity:    models.SeverityInfo,
		DefaultConfidence:  models.ConfidenceLow,
		Mitigation:         "Review the listed contracts in the trace; they are where your transaction's effects actually happen.",
		FalsePositiveNotes: "Routers routinely call pools and pairs that are derived on-chain rather than passed in calldata. Informational only.",
	}
}

func (r unexpectedCallsRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	if ac.Simulation == nil || ac.Simulation.Trace == nil {
		return nil, nil
	}
	referenced := core.CollectAddresses(ac.Tx, ac.Decoded, ac.Approvals, nil)
	for a := range referenced {
		if info := ac.Contracts[a]; info != nil && info.Implementation != "" {
			referenced[common.HexToAddress(info.Implementation)] = map[core.Role]bool{core.RoleTarget: true}
		}
	}
	var unexpected []string
	seen := map[string]bool{}
	core.WalkTrace(ac.Simulation.Trace, func(fr *models.CallFrame, _ []*models.CallFrame) {
		if fr.Type != "CALL" && fr.Type != "DELEGATECALL" && fr.Type != "CALLCODE" {
			return
		}
		if !common.IsHexAddress(fr.To) {
			return
		}
		a := common.HexToAddress(fr.To)
		if referenced[a] != nil || seen[a.Hex()] || isPrecompile(a) {
			return
		}
		seen[a.Hex()] = true
		unexpected = append(unexpected, a.Hex())
	})
	if len(unexpected) == 0 {
		return nil, nil
	}
	sort.Strings(unexpected)
	f := core.NewFinding(r.Metadata())
	f.Source = models.SourceHeuristic
	shown := unexpected
	if len(shown) > 10 {
		shown = shown[:10]
	}
	f.Description = fmt.Sprintf("%d contract(s) called during execution are not referenced in calldata: %s", len(unexpected), strings.Join(shown, ", "))
	f.Subjects = shown
	f.Evidence = []models.Evidence{core.Evidence("simulation_trace", "calls observed in simulated trace", models.SourceFact, map[string]string{"count": fmt.Sprint(len(unexpected))})}
	return []models.Finding{f}, nil
}

func isPrecompile(a common.Address) bool {
	b := a.Bytes()
	for _, x := range b[:18] {
		if x != 0 {
			return false
		}
	}
	return b[18] == 0 && b[19] <= 0x11
}
