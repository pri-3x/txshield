package rules

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/pri-3x/txshield/internal/logging"
	"github.com/pri-3x/txshield/internal/security/core"
	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
)

// --- TXS-PATTERN-001 --------------------------------------------------------

type delegatecallRule struct{}

func (delegatecallRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-PATTERN-001", Name: "Delegatecall execution",
		Description:        "Code from another contract runs with the calling contract's storage and balance (DELEGATECALL). Malicious delegatecalls can take over a wallet or contract completely.",
		Category:           models.CategoryDangerousPattern,
		DefaultSeverity:    models.SeverityHigh,
		DefaultConfidence:  models.ConfidenceHigh,
		Mitigation:         "Only approve delegatecalls to audited, well-known libraries (e.g. official Safe MultiSend). Verify the target address.",
		FalsePositiveNotes: "Safe MultiSend batches, proxy initialization, and module libraries use delegatecall legitimately. Proxy-to-implementation delegatecalls in traces are not reported.",
	}
}

func (r delegatecallRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	var out []models.Finding
	core.Walk(ac.Tx, ac.Decoded, func(fr core.Frame) {
		if fr.Call.CallType != models.CallTypeDelegateCall {
			return
		}
		f := core.NewFinding(r.Metadata(), "decoded", fr.Path)
		f.Description = fmt.Sprintf("The calldata requests a DELEGATECALL (%s) executing in the context of %s.", fr.Path, fr.Self.Hex())
		f.Subjects = []string{fr.Call.Target, fr.Self.Hex()}
		f.Evidence = []models.Evidence{core.Evidence("calldata_call", "decoded call type delegatecall", models.SourceFact, map[string]string{"via": fr.Path, "context": fr.Self.Hex()})}
		out = append(out, f)
	})

	if ac.Simulation != nil && ac.Simulation.Trace != nil && ac.ContractsKnown {
		fromCalldata := map[common.Address]bool{}
		if len(ac.Tx.Data) > 4 && ac.Tx.To != nil {
			for _, a := range core.AddressWords(ac.Tx.Data[4:]) {
				fromCalldata[a] = true
			}
		}
		core.WalkTrace(ac.Simulation.Trace, func(fr *models.CallFrame, _ []*models.CallFrame) {
			if fr.Type != "DELEGATECALL" || !common.IsHexAddress(fr.From) || !common.IsHexAddress(fr.To) {
				return
			}
			caller := ac.Contracts[common.HexToAddress(fr.From)]
			if caller == nil || strings.EqualFold(caller.Implementation, fr.To) {
				return // unknown caller, or the expected proxy -> implementation hop
			}
			f := core.NewFinding(r.Metadata(), "trace", fr.From, fr.To)
			f.Source = models.SourceHeuristic
			if fromCalldata[common.HexToAddress(fr.To)] {
				// The delegatecall target was supplied by the caller: arbitrary
				// code runs with the contract's storage and funds.
				f.Severity, f.Confidence = models.SeverityHigh, models.ConfidenceMedium
				f.Description = fmt.Sprintf("%s delegatecalls into %s, an address taken from this transaction's calldata (arbitrary delegatecall).", fr.From, fr.To)
			} else {
				f.Severity, f.Confidence = models.SeverityLow, models.ConfidenceLow
				f.Description = fmt.Sprintf("Execution delegatecalls from %s into %s, which is not %s's known implementation.", fr.From, fr.To, fr.From)
			}
			f.Subjects = []string{fr.From, fr.To}
			out = append(out, f)
		})
	}
	return out, nil
}

// --- TXS-PATTERN-002 --------------------------------------------------------

type signedPermitRule struct{}

func (signedPermitRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-PATTERN-002", Name: "Off-chain signature permit used",
		Description:        "The transaction submits a permit signature (EIP-2612, DAI, or Permit2). The permission it grants was authorized off-chain by the owner's signature.",
		Category:           models.CategoryDangerousPattern,
		DefaultSeverity:    models.SeverityInfo,
		DefaultConfidence:  models.ConfidenceHigh,
		Mitigation:         "Permit signatures are as powerful as approvals. Never sign permit messages for sites you do not trust.",
		FalsePositiveNotes: "Routers routinely bundle Permit2 signatures with swaps. Informational; the amount and spender are judged by approval rules.",
	}
}

func (r signedPermitRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	var out []models.Finding
	for _, g := range ac.Approvals {
		if !g.Signed {
			continue
		}
		f := core.NewFinding(r.Metadata(), g.Owner, g.Token, g.Spender)
		f.Description = fmt.Sprintf("%s permit: owner %s, spender %s, token %s.", g.Kind, g.Owner, g.Spender, g.Token)
		f.Subjects = []string{g.Owner, g.Spender, g.Token}
		out = append(out, f)
	}
	return out, nil
}

// --- TXS-PATTERN-003 --------------------------------------------------------

type batchRule struct{}

func (batchRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-PATTERN-003", Name: "Batched execution",
		Description:        "One transaction executes several calls (multicall, Multicall3, Universal Router, or similar). Each sub-call has its own effects.",
		Category:           models.CategoryDangerousPattern,
		DefaultSeverity:    models.SeverityInfo,
		DefaultConfidence:  models.ConfidenceHigh,
		Mitigation:         "Review each sub-call in the decoded call tree, not only the first one.",
		FalsePositiveNotes: "Batching is normal for swaps and DeFi interactions. Informational only.",
	}
}

func (r batchRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	total := 0
	core.Walk(ac.Tx, ac.Decoded, func(fr core.Frame) {
		if fr.Depth > 0 {
			total++
		}
	})
	if total < 2 {
		return nil, nil
	}
	f := core.NewFinding(r.Metadata())
	f.Description = fmt.Sprintf("The transaction contains %d nested calls or router commands.", total)
	return []models.Finding{f}, nil
}

// --- TXS-PATTERN-004 / 005 --------------------------------------------------

type ownershipRule struct{}

func (ownershipRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-PATTERN-004", Name: "Ownership change",
		Description:        "The transaction transfers, accepts, or renounces ownership of a contract.",
		Category:           models.CategoryDangerousPattern,
		DefaultSeverity:    models.SeverityMedium,
		DefaultConfidence:  models.ConfidenceHigh,
		Mitigation:         "Verify the new owner address carefully; renouncing ownership is irreversible.",
		FalsePositiveNotes: "Expected for contract administrators performing planned handovers.",
	}
}

func (r ownershipRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	var out []models.Finding
	core.Walk(ac.Tx, ac.Decoded, func(fr core.Frame) {
		c := fr.Call
		if c.Standard != "ownable" {
			return
		}
		f := core.NewFinding(r.Metadata(), fr.Self.Hex(), c.Method)
		f.Description = fmt.Sprintf("%s on %s.", c.Signature, fr.Self.Hex())
		if v, ok := core.Param(c, "newOwner"); ok {
			f.Description += fmt.Sprintf(" New owner: %v.", v)
		}
		if c.Method == "renounceOwnership" {
			f.Description += " This is irreversible."
		}
		f.Subjects = []string{fr.Self.Hex()}
		out = append(out, f)
	})
	return out, nil
}

type upgradeRule struct{}

func (upgradeRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-PATTERN-005", Name: "Proxy upgrade or admin change",
		Description:        "The transaction replaces a proxy's implementation or admin, changing the logic behind every user of that contract.",
		Category:           models.CategoryDangerousPattern,
		DefaultSeverity:    models.SeverityHigh,
		DefaultConfidence:  models.ConfidenceHigh,
		Mitigation:         "Verify the new implementation's code and audit status; use a timelock for upgrades.",
		FalsePositiveNotes: "Expected for protocol administrators executing planned upgrades.",
	}
}

func (r upgradeRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	var out []models.Finding
	core.Walk(ac.Tx, ac.Decoded, func(fr core.Frame) {
		c := fr.Call
		if c.Standard != "proxy-upgrade" {
			return
		}
		f := core.NewFinding(r.Metadata(), fr.Self.Hex(), c.Signature)
		f.Description = fmt.Sprintf("%s via %s.", c.Signature, fr.Self.Hex())
		for _, name := range []string{"newImplementation", "implementation", "newAdmin", "proxy"} {
			if v, ok := core.Param(c, name); ok {
				f.Description += fmt.Sprintf(" %s: %v.", name, v)
			}
		}
		f.Subjects = []string{fr.Self.Hex()}
		out = append(out, f)
	})
	return out, nil
}

// --- TXS-PATTERN-006 --------------------------------------------------------

type selfdestructRule struct{}

func (selfdestructRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-PATTERN-006", Name: "Self-destruct during execution",
		Description:        "The simulated trace contains a SELFDESTRUCT. Since EIP-6780 it only deletes contracts created in the same transaction, but it still forwards the contract's entire balance.",
		Category:           models.CategoryDangerousPattern,
		DefaultSeverity:    models.SeverityMedium,
		DefaultConfidence:  models.ConfidenceHigh,
		Mitigation:         "Understand why a contract self-destructs in this transaction and where its balance goes.",
		FalsePositiveNotes: "Some gas-token and deployment patterns use SELFDESTRUCT legitimately. Requires a call trace.",
	}
}

func (r selfdestructRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	if ac.Simulation == nil || ac.Simulation.Trace == nil {
		return nil, nil
	}
	var out []models.Finding
	core.WalkTrace(ac.Simulation.Trace, func(fr *models.CallFrame, _ []*models.CallFrame) {
		if fr.Type != "SELFDESTRUCT" {
			return
		}
		f := core.NewFinding(r.Metadata(), fr.From, fr.To)
		f.Description = fmt.Sprintf("%s self-destructs, sending its balance (%s wei) to %s.", fr.From, fr.Value, fr.To)
		f.Subjects = []string{fr.From, fr.To}
		out = append(out, f)
	})
	return out, nil
}

// --- TXS-PATTERN-007 --------------------------------------------------------

type flashLoanRule struct{}

var flashSelectors = map[string]bool{
	"0x42b0b77c": true, "0xab9c4b5d": true, "0x5c38449e": true, "0x490e6cbc": true, "0x5cffe9de": true,
}

func (flashLoanRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-PATTERN-007", Name: "Flash loan",
		Description:        "The transaction takes a flash loan or flash swap (Aave, Balancer, Uniswap, or ERC-3156 interfaces). Flash loans are a building block of most price-manipulation exploits.",
		Category:           models.CategoryDangerousPattern,
		DefaultSeverity:    models.SeverityLow,
		DefaultConfidence:  models.ConfidenceMedium,
		Mitigation:         "Ordinary wallet users rarely need flash loans. Make sure you understand the strategy being executed.",
		FalsePositiveNotes: "Arbitrage, liquidations, collateral swaps, and debt refinancing use flash loans legitimately.",
	}
}

func (r flashLoanRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	var out []models.Finding
	core.Walk(ac.Tx, ac.Decoded, func(fr core.Frame) {
		c := fr.Call
		isFlash := c.Standard == "flash-loan"
		if c.Standard == "uniswap-v2-pair" {
			if v, ok := core.Param(c, "data"); ok && v != "0x" {
				isFlash = true
			}
		}
		if !isFlash {
			return
		}
		f := core.NewFinding(r.Metadata(), "decoded", fr.Path)
		f.Source = models.SourceHeuristic
		f.Description = fmt.Sprintf("%s on %s.", c.Signature, fr.Self.Hex())
		f.Subjects = []string{fr.Self.Hex()}
		out = append(out, f)
	})
	if ac.Simulation != nil && ac.Simulation.Trace != nil {
		core.WalkTrace(ac.Simulation.Trace, func(fr *models.CallFrame, anc []*models.CallFrame) {
			if len(anc) == 0 || len(fr.Input) < 10 || !flashSelectors[strings.ToLower(fr.Input[:10])] {
				return
			}
			f := core.NewFinding(r.Metadata(), "trace", fr.To)
			f.Source = models.SourceHeuristic
			f.Description = fmt.Sprintf("Execution calls flash-loan function %s on %s.", fr.Input[:10], fr.To)
			f.Subjects = []string{fr.To}
			out = append(out, f)
		})
	}
	return out, nil
}

// --- TXS-PATTERN-008 --------------------------------------------------------

type embeddedTransferRule struct{}

// tokenMovingSelectors are calls that move or authorize tokens. Finding one
// inside opaque calldata means some contract will be asked to forward it.
var tokenMovingSelectors = map[string]string{
	"23b872dd": "transferFrom(address,address,uint256)",
	"42842e0e": "safeTransferFrom(address,address,uint256)",
	"b88d4fde": "safeTransferFrom(address,address,uint256,bytes)",
	"f242432a": "safeTransferFrom(address,address,uint256,uint256,bytes)",
	"2eb2c2d6": "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
	"36c78516": "transferFrom(address,address,uint160,address)",
	"095ea7b3": "approve(address,uint256)",
	"a22cb465": "setApprovalForAll(address,bool)",
	"a9059cbb": "transfer(address,uint256)",
	"d505accf": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
}

// fromBasedSelectors take the token owner as their first argument.
var fromBasedSelectors = map[string]bool{"23b872dd": true, "42842e0e": true, "b88d4fde": true, "f242432a": true, "2eb2c2d6": true, "36c78516": true}

func (embeddedTransferRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-PATTERN-008", Name: "Token transfer or approval hidden in forwarded calldata",
		Description:        "Opaque calldata contains an encoded token transferFrom/approve/permit that the target contract would forward to another contract (an arbitrary external call). Drainers use this to move tokens the victim previously approved.",
		Category:           models.CategoryDangerousPattern,
		DefaultSeverity:    models.SeverityHigh,
		DefaultConfidence:  models.ConfidenceMedium,
		Mitigation:         "Do not sign unless you know exactly which contract will execute the embedded call and why. Review your existing token approvals.",
		FalsePositiveNotes: "Generic executors, account-abstraction wallets, and aggregator routers legitimately carry encoded token calls. Confidence is high when the embedded call moves tokens from the sender.",
	}
}

func (r embeddedTransferRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	var out []models.Finding
	seen := map[string]bool{}
	report := func(path string, embedded []byte) {
		sel := hex.EncodeToString(embedded[:4])
		sig, ok := tokenMovingSelectors[sel]
		if !ok || seen[path+sel] {
			return
		}
		seen[path+sel] = true
		f := core.NewFinding(r.Metadata(), path, sel)
		f.Source = models.SourceHeuristic
		f.Description = fmt.Sprintf("Embedded %s found in calldata (%s).", sig, path)
		if fromBasedSelectors[sel] && len(embedded) >= 36 && common.BytesToAddress(embedded[16:36]) == ac.Tx.From {
			f.Confidence = models.ConfidenceHigh
			f.Description += " It moves tokens from the sender's address."
		}
		f.Evidence = []models.Evidence{core.Evidence("calldata_embedded_call", "selector found at an ABI word boundary", models.SourceFact,
			map[string]string{"selector": "0x" + sel, "signature": sig, "via": path})}
		out = append(out, f)
	}
	core.Walk(ac.Tx, ac.Decoded, func(fr core.Frame) {
		c := fr.Call
		if len(c.Children) > 0 || c.CallType == models.CallTypeRouterCommand {
			return // containers are decoded into children and judged there
		}
		if c.Kind == models.CallUnknown && c.RawData != "" {
			if raw, err := hexutil.Decode(c.RawData); err == nil && len(raw) > 4 {
				for _, emb := range scanABIWords(raw[4:]) {
					report(fr.Path, emb)
				}
			}
			return
		}
		walkBytesParams(c.Params, func(b []byte) {
			if len(b) >= 4 {
				report(fr.Path, b)
			}
		})
	})
	return out, nil
}

// scanABIWords finds dynamic `bytes` values in ABI-encoded arguments: a
// 32-byte length word L followed by data starting with a token-moving
// selector. ABI encoding aligns dynamic data to 32-byte words.
func scanABIWords(args []byte) [][]byte {
	var out [][]byte
	for off := 0; off+64 <= len(args); off += 32 {
		l := new(big.Int).SetBytes(args[off : off+32])
		if !l.IsUint64() {
			continue
		}
		n := l.Uint64()
		if n < 4 || n > uint64(len(args)-off-32) { //nolint:gosec // len is non-negative
			continue
		}
		data := args[off+32 : off+32+int(n)] //nolint:gosec // n bounded by len(args)
		if _, ok := tokenMovingSelectors[hex.EncodeToString(data[:4])]; ok {
			out = append(out, data)
		}
	}
	return out
}

func walkBytesParams(ps []models.DecodedParam, fn func([]byte)) {
	for _, p := range ps {
		if p.Type == "derived" {
			continue
		}
		switch v := p.Value.(type) {
		case string:
			if p.Type == "bytes" {
				if b, err := hexutil.Decode(v); err == nil {
					fn(b)
				}
			}
		case []any:
			for _, item := range v {
				walkBytesParams([]models.DecodedParam{{Type: elemType(p.Type), Value: item}}, fn)
			}
		case []models.DecodedParam:
			walkBytesParams(v, fn)
		}
	}
}

// elemType strips one array suffix: "bytes[]" -> "bytes".
func elemType(t string) string {
	if i := strings.LastIndexByte(t, '['); i > 0 {
		return t[:i]
	}
	return t
}

// --- TXS-PATTERN-009 --------------------------------------------------------

type trailingDataRule struct{}

func (trailingDataRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-PATTERN-009", Name: "Extra data after encoded arguments",
		Description:        "Calldata contains bytes beyond the ABI-encoded arguments, or uses a non-canonical encoding. Contracts normally ignore such bytes, but custom code can read them.",
		Category:           models.CategoryDangerousPattern,
		DefaultSeverity:    models.SeverityInfo,
		DefaultConfidence:  models.ConfidenceHigh,
		Mitigation:         "Ask the application why extra calldata is attached.",
		FalsePositiveNotes: "Many frontends and aggregators append referral or tracking tags.",
	}
}

func (r trailingDataRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	var out []models.Finding
	core.Walk(ac.Tx, ac.Decoded, func(fr core.Frame) {
		for _, w := range fr.Call.Warnings {
			if strings.Contains(w, "trailing bytes") || strings.Contains(w, "non-canonical") {
				f := core.NewFinding(r.Metadata(), fr.Path)
				f.Description = fmt.Sprintf("%s: %s", fr.Path, w)
				out = append(out, f)
			}
		}
	})
	return out, nil
}

// --- TXS-PATTERN-010 --------------------------------------------------------

type reentrancyRule struct{}

func (reentrancyRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-PATTERN-010", Name: "Re-entrant call",
		Description:        "During simulation, a contract is called again while an earlier call into it is still executing (re-entrancy).",
		Category:           models.CategoryDangerousPattern,
		DefaultSeverity:    models.SeverityInfo,
		DefaultConfidence:  models.ConfidenceLow,
		Mitigation:         "Re-entrancy is the mechanism behind many exploits; review it if the contracts involved are not well known.",
		FalsePositiveNotes: "Swap callbacks, flash loans, and hooks re-enter by design. Informational only.",
	}
}

func (r reentrancyRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	if ac.Simulation == nil || ac.Simulation.Trace == nil {
		return nil, nil
	}
	var out []models.Finding
	seen := map[string]bool{}
	core.WalkTrace(ac.Simulation.Trace, func(fr *models.CallFrame, anc []*models.CallFrame) {
		if fr.Type != "CALL" {
			return
		}
		target := strings.ToLower(fr.To)
		for i := range anc {
			if contextOf(anc[:i+1]) == target && !seen[target] {
				seen[target] = true
				f := core.NewFinding(r.Metadata(), target)
				f.Source = models.SourceHeuristic
				f.Description = fmt.Sprintf("%s is re-entered at call depth %d.", fr.To, len(anc))
				f.Subjects = []string{fr.To}
				out = append(out, f)
				return
			}
		}
	})
	return out, nil
}

// contextOf returns the storage context address of the last frame in stack:
// a frame's own target for CALL-like frames, its caller's context for
// DELEGATECALL/CALLCODE.
func contextOf(stack []*models.CallFrame) string {
	for i := len(stack) - 1; i >= 0; i-- {
		if t := stack[i].Type; t != "DELEGATECALL" && t != "CALLCODE" {
			return strings.ToLower(stack[i].To)
		}
	}
	if len(stack) > 0 {
		return strings.ToLower(stack[0].From)
	}
	return ""
}

// --- TXS-SIM-001 ------------------------------------------------------------

type revertRule struct{}

func (revertRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-SIM-001", Name: "Transaction is expected to revert",
		Description:        "In simulation the transaction reverted. If broadcast as-is it would most likely fail and still cost gas.",
		Category:           models.CategorySimulation,
		DefaultSeverity:    models.SeverityLow,
		DefaultConfidence:  models.ConfidenceHigh,
		Mitigation:         "Do not broadcast until the cause is understood (insufficient balance or allowance, slippage, expired deadline, wrong parameters).",
		FalsePositiveNotes: "State can change between simulation and inclusion; a transaction that reverts now may succeed later and vice versa. Some contracts behave differently under simulation.",
	}
}

func (r revertRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	if ac.Simulation == nil || ac.Simulation.Status != models.SimReverted {
		return nil, nil
	}
	f := core.NewFinding(r.Metadata())
	reason := ac.Simulation.RevertReason
	if reason == "" {
		reason = "no reason returned"
	}
	// Revert strings are attacker-controlled.
	f.Description = fmt.Sprintf("Reverted at block %d: %s", ac.Simulation.BlockNumber, logging.Sanitize(reason, 200))
	return []models.Finding{f}, nil
}
