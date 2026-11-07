package rules

import (
	"context"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/pri-3x/txshield/internal/security/core"
	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
)

// simUsable reports whether simulation produced executed state changes that
// value rules can rely on.
func simUsable(ac *interfaces.AnalysisContext) bool {
	s := ac.Simulation
	return s != nil && s.Status == models.SimSuccess && s.Completeness != models.CompletenessNone
}

func assetKey(a models.AssetRef) string {
	k := string(a.Kind) + ":" + strings.ToLower(a.Address)
	if a.TokenID != "" {
		k += "#" + string(a.TokenID)
	}
	return k
}

func assetLabel(a models.AssetRef) string {
	if a.Kind == models.AssetNative {
		return "native currency"
	}
	l := fmt.Sprintf("%s %s", a.Kind, a.Address)
	if a.TokenID != "" {
		l += " #" + string(a.TokenID)
	}
	return l
}

// outflows returns simulated transfers leaving the sender.
func outflows(ac *interfaces.AnalysisContext) []models.AssetTransfer {
	var out []models.AssetTransfer
	for _, t := range ac.Simulation.AssetTransfers {
		if common.HexToAddress(t.From) == ac.Tx.From {
			out = append(out, t)
		}
	}
	return out
}

func transferEvidence(t models.AssetTransfer) models.Evidence {
	return core.Evidence("simulation_transfer",
		fmt.Sprintf("%s of %s from %s to %s", t.Amount, assetLabel(t.Asset), t.From, t.To), models.SourceFact,
		map[string]string{"asset": t.Asset.Address, "kind": string(t.Asset.Kind), "from": t.From, "to": t.To, "amount": string(t.Amount)})
}

// --- TXS-VALUE-001 ----------------------------------------------------------

type unexpectedOutflowRule struct{}

func (unexpectedOutflowRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-VALUE-001", Name: "Unexpected asset leaves the wallet",
		Description:       "In simulation, a token leaves the sender's wallet even though that token is not referenced anywhere in the transaction's calldata. Draining contracts typically move tokens the user never mentioned.",
		Category:          models.CategoryValueTransfer,
		DefaultSeverity:   models.SeverityHigh,
		DefaultConfidence: models.ConfidenceMedium,
		Mitigation:        "Do not sign unless you expect this token to leave your wallet. Revoke existing approvals for it if this came from an untrusted site.",
		FalsePositiveNotes: "Protocols that derive tokens on-chain (e.g. vault share redemptions, fee-on-transfer side effects) can move tokens not named in calldata. " +
			"For undecoded calls, any address-shaped argument counts as referenced, so a drainer that receives token addresses as arguments is caught by TXS-VALUE-002/003 instead. Requires simulation.",
	}
}

func (r unexpectedOutflowRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	if !simUsable(ac) {
		return nil, nil
	}
	referenced := core.CollectAddresses(ac.Tx, ac.Decoded, ac.Approvals, nil)
	var out []models.Finding
	seen := map[string]bool{}
	for _, t := range outflows(ac) {
		if t.Asset.Kind == models.AssetNative || referenced[common.HexToAddress(t.Asset.Address)] != nil {
			continue
		}
		key := assetKey(t.Asset) + "|" + strings.ToLower(t.To)
		if seen[key] {
			continue
		}
		seen[key] = true
		f := core.NewFinding(r.Metadata(), assetKey(t.Asset), t.To)
		f.Description = fmt.Sprintf("%s of %s leaves the sender to %s, but the token is not referenced in the calldata.", t.Amount, assetLabel(t.Asset), t.To)
		if referenced[common.HexToAddress(t.To)] == nil {
			f.Description += " The recipient is not referenced either."
		}
		f.Evidence = []models.Evidence{transferEvidence(t)}
		f.Subjects = []string{t.Asset.Address, t.To}
		out = append(out, f)
	}
	return out, nil
}

// --- TXS-VALUE-002 ----------------------------------------------------------

type multiAssetOutflowRule struct{}

const multiAssetThreshold = 3

func (multiAssetOutflowRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-VALUE-002", Name: "Several different assets leave the wallet",
		Description:        "In simulation, three or more distinct assets leave the sender's wallet in one transaction, a common shape of wallet-draining transactions.",
		Category:           models.CategoryValueTransfer,
		DefaultSeverity:    models.SeverityHigh,
		DefaultConfidence:  models.ConfidenceMedium,
		Mitigation:         "Review every outgoing asset in the simulation before signing.",
		FalsePositiveNotes: "Intentional batch payouts, portfolio migrations, and multi-asset deposits also move several assets.",
	}
}

func (r multiAssetOutflowRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	if !simUsable(ac) {
		return nil, nil
	}
	assets := map[string]models.AssetTransfer{}
	for _, t := range outflows(ac) {
		assets[assetKey(t.Asset)] = t
	}
	if ac.Tx.Value != nil && ac.Tx.Value.Sign() > 0 {
		assets["native:"] = models.AssetTransfer{Asset: models.AssetRef{Kind: models.AssetNative}}
	}
	if len(assets) < multiAssetThreshold {
		return nil, nil
	}
	keys := make([]string, 0, len(assets))
	for k := range assets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	f := core.NewFinding(r.Metadata())
	f.Description = fmt.Sprintf("%d distinct assets leave the sender: %s", len(keys), strings.Join(keys, ", "))
	for _, k := range keys {
		if t := assets[k]; t.Asset.Kind != models.AssetNative {
			f.Evidence = append(f.Evidence, transferEvidence(t))
		}
	}
	return []models.Finding{f}, nil
}

// --- TXS-VALUE-003 ----------------------------------------------------------

type netLossRule struct{}

func (netLossRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-VALUE-003", Name: "Assets leave the wallet and nothing comes back",
		Description:        "In simulation, the sender loses assets and receives nothing in return, while the call is not a plain transfer. Fake claim, mint, and airdrop pages produce this shape.",
		Category:           models.CategoryValueTransfer,
		DefaultSeverity:    models.SeverityHigh,
		DefaultConfidence:  models.ConfidenceMedium,
		Mitigation:         "Make sure you intend to give these assets away. Legitimate swaps, mints, and claims return something.",
		FalsePositiveNotes: "Donations, fee payments, repaying loans, bridging (the return arrives on another chain), and deposits into protocols that track balances internally also match.",
	}
}

func isExplicitSend(c *models.DecodedCall) bool {
	if c == nil {
		return false
	}
	switch c.Kind {
	case models.CallNativeTransfer:
		return true
	case models.CallContract:
	default:
		return false
	}
	switch c.Method {
	case "transfer", "transferFrom", "safeTransferFrom", "safeBatchTransferFrom":
		return true
	}
	if len(c.Children) > 0 && (c.Standard == "multicall" || c.Standard == "multicall3") {
		for i := range c.Children {
			if !isExplicitSend(&c.Children[i]) {
				return false
			}
		}
		return true
	}
	return false
}

func (r netLossRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	if !simUsable(ac) || isExplicitSend(ac.Decoded) {
		return nil, nil
	}
	outs := outflows(ac)
	nativeOut := ac.Tx.Value != nil && ac.Tx.Value.Sign() > 0
	if len(outs) == 0 && !nativeOut {
		return nil, nil
	}
	for _, t := range ac.Simulation.AssetTransfers {
		if common.HexToAddress(t.To) == ac.Tx.From {
			return nil, nil
		}
	}
	for _, b := range ac.Simulation.BalanceChanges {
		if common.HexToAddress(b.Owner) == ac.Tx.From && b.Asset.Kind != models.AssetNative {
			if d, ok := new(big.Int).SetString(string(b.Delta), 10); ok && d.Sign() > 0 {
				return nil, nil
			}
		}
	}
	f := core.NewFinding(r.Metadata())
	parts := []string{}
	// The call's value usually also appears as a simulated native transfer
	// from the sender; list it once.
	nativeListed := false
	for _, t := range outs {
		if t.Asset.Kind == models.AssetNative {
			nativeListed = true
		}
	}
	if nativeOut && !nativeListed {
		parts = append(parts, ac.Tx.Value.String()+" wei of native currency")
	}
	for _, t := range outs {
		parts = append(parts, fmt.Sprintf("%s of %s", t.Amount, assetLabel(t.Asset)))
		f.Evidence = append(f.Evidence, transferEvidence(t))
	}
	f.Description = "The sender gives away " + strings.Join(parts, ", ") + " and receives no assets in the simulation."
	return []models.Finding{f}, nil
}

// --- TXS-VALUE-004 ----------------------------------------------------------

type valueToNonPayableRule struct{}

func (valueToNonPayableRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-VALUE-004", Name: "Native currency sent to a non-payable or unrecognized function",
		Description:        "The transaction sends native currency with a call that standard implementations do not accept payment for (token approvals, transfers, permits), or to a function TxShield cannot identify. Fake claim and airdrop contracts use payable functions to collect fees.",
		Category:           models.CategoryValueTransfer,
		DefaultSeverity:    models.SeverityMedium,
		DefaultConfidence:  models.ConfidenceHigh,
		Mitigation:         "Check why this call needs native currency. Token approvals and transfers never require it.",
		FalsePositiveNotes: "Many legitimate unrecognized functions are payable (mints, deposits, bridge fees). Confidence is low for unrecognized functions.",
	}
}

var nonPayableStandards = map[string]bool{
	"erc20": true, "erc20|erc721": true, "erc721": true, "erc721|erc1155": true, "erc1155": true,
	"eip2612-permit": true, "dai-permit": true, "permit2": true, "ownable": true,
}

func (r valueToNonPayableRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	c := ac.Decoded
	if c == nil || ac.Tx.To == nil || ac.Tx.Value == nil || ac.Tx.Value.Sign() == 0 {
		return nil, nil
	}
	f := core.NewFinding(r.Metadata(), ac.Tx.To.Hex())
	switch {
	case c.Kind == models.CallUnknown:
		f.Confidence = models.ConfidenceLow
		f.Source = models.SourceHeuristic
		f.Description = fmt.Sprintf("%s wei sent with unrecognized function %s.", ac.Tx.Value, c.Selector)
	case c.Kind == models.CallContract && nonPayableStandards[c.Standard]:
		f.Description = fmt.Sprintf("%s wei sent with %s, which standard %s contracts do not accept payment for.", ac.Tx.Value, c.Signature, c.Standard)
	default:
		return nil, nil
	}
	f.Subjects = []string{ac.Tx.To.Hex()}
	return []models.Finding{f}, nil
}

// --- TXS-VALUE-005 ----------------------------------------------------------

type fullBalanceRule struct{}

func (fullBalanceRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-VALUE-005", Name: "Entire token balance leaves the wallet",
		Description:        "In simulation, the sender's whole balance of a token goes to zero.",
		Category:           models.CategoryValueTransfer,
		DefaultSeverity:    models.SeverityLow,
		DefaultConfidence:  models.ConfidenceHigh,
		Mitigation:         "Confirm you intend to move your full balance of this token.",
		FalsePositiveNotes: "Selling or moving a full position is common. Combined with other findings it is a draining signal.",
	}
}

func (r fullBalanceRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	if !simUsable(ac) {
		return nil, nil
	}
	var out []models.Finding
	for _, b := range ac.Simulation.BalanceChanges {
		if common.HexToAddress(b.Owner) != ac.Tx.From || b.Asset.Kind == models.AssetNative {
			continue
		}
		before, ok1 := new(big.Int).SetString(string(b.Before), 10)
		after, ok2 := new(big.Int).SetString(string(b.After), 10)
		if !ok1 || !ok2 || before.Sign() <= 0 || after.Sign() != 0 {
			continue
		}
		f := core.NewFinding(r.Metadata(), assetKey(b.Asset))
		f.Description = fmt.Sprintf("Balance of %s goes from %s to 0.", assetLabel(b.Asset), b.Before)
		f.Subjects = []string{b.Asset.Address}
		f.Evidence = []models.Evidence{core.Evidence("simulation_balance", "pre/post balance from simulation", models.SourceFact,
			map[string]string{"asset": b.Asset.Address, "before": string(b.Before), "after": string(b.After)})}
		out = append(out, f)
	}
	return out, nil
}
