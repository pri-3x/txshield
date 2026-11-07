package approvals

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/txshield/txshield/internal/security/core"
	"github.com/txshield/txshield/internal/security/reputation"
	"github.com/txshield/txshield/pkg/interfaces"
	"github.com/txshield/txshield/pkg/models"
)

// Config tunes approval heuristics.
type Config struct {
	// LargeAllowance is the threshold above which a non-unlimited allowance is
	// reported as "very large". Default 2^128: far above any realistic
	// balance for 18-decimal tokens, but below the sentinel values.
	LargeAllowance *big.Int
	// LongExpiry is how far in the future a Permit2 allowance expiry must be
	// to be reported as long-lived. Default 90 days.
	LongExpiry time.Duration
}

// DefaultConfig returns the defaults documented on Config.
func DefaultConfig() Config {
	return Config{LargeAllowance: new(big.Int).Lsh(big.NewInt(1), 128), LongExpiry: 90 * 24 * time.Hour}
}

// Rules returns the approval rules.
func Rules(cfg Config) []interfaces.Rule {
	d := DefaultConfig()
	if cfg.LargeAllowance == nil {
		cfg.LargeAllowance = d.LargeAllowance
	}
	if cfg.LongExpiry <= 0 {
		cfg.LongExpiry = d.LongExpiry
	}
	return []interfaces.Rule{
		unlimitedRule{}, largeRule{cfg.LargeAllowance}, operatorRule{}, eoaSpenderRule{},
		flaggedSpenderRule{}, unknownSpenderRule{}, longExpiryRule{cfg.LongExpiry},
	}
}

// affectsSender reports whether a grant takes effect on assets the signer
// controls:
// their own address, or the Safe they are executing through. Grants made by
// intermediary contracts (Multicall3, routers) on their own balances are
// listed in reports but not scored.
func affectsSender(ac *interfaces.AnalysisContext, g models.ApprovalGrant) bool {
	if g.Revocation {
		return false
	}
	// An approval "executed" on an address without code grants nothing
	// (TXS-INTERACT-005 reports the misdirected call instead).
	if info := ac.Contracts[common.HexToAddress(g.Contract)]; ac.ContractsKnown && info != nil && !info.IsContract {
		return false
	}
	if g.OwnerIsSender {
		return true
	}
	return ac.Tx.To != nil && ac.Decoded != nil && ac.Decoded.Standard == "gnosis-safe" &&
		common.HexToAddress(g.Owner) == *ac.Tx.To
}

func grantEvidence(g models.ApprovalGrant) models.Evidence {
	data := map[string]string{
		"kind": string(g.Kind), "token": g.Token, "owner": g.Owner, "spender": g.Spender, "via": g.Via,
	}
	if g.Amount != "" {
		data["amount"] = string(g.Amount)
	}
	if g.Contract != "" && g.Contract != g.Token {
		data["contract"] = g.Contract
	}
	if g.Expiration != nil {
		data["expiration"] = fmt.Sprint(*g.Expiration)
	}
	detail := fmt.Sprintf("%s grants %s permission over token %s", g.Owner, g.Spender, tokenLabel(g))
	return core.Evidence("calldata_approval", detail, models.SourceFact, data)
}

func tokenLabel(g models.ApprovalGrant) string {
	if g.Token == "" || g.Token == (common.Address{}).Hex() {
		return "(unknown)"
	}
	return g.Token
}

func grantSubjects(g models.ApprovalGrant) []string { return []string{g.Token, g.Spender} }

// --- TXS-APPROVAL-001 -------------------------------------------------------

type unlimitedRule struct{}

func (unlimitedRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-APPROVAL-001", Name: "Unlimited token allowance",
		Description:       "The transaction grants a spender an unlimited allowance (type(uint256).max, or type(uint160).max on Permit2) over the sender's tokens. The spender can move the entire current and future balance of that token until the allowance is revoked.",
		Category:          models.CategoryApproval,
		DefaultSeverity:   models.SeverityMedium,
		DefaultConfidence: models.ConfidenceHigh,
		Mitigation:        "Approve only the amount needed for this transaction, and revoke unused allowances afterwards.",
		FalsePositiveNotes: "Unlimited approvals to well-known routers and protocols are common and often intended to save gas. " +
			"This finding is about exposure if the spender is or becomes malicious, not proof of malice.",
	}
}

func (r unlimitedRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	var out []models.Finding
	for _, g := range ac.Approvals {
		if !affectsSender(ac, g) || !g.Unlimited || g.Kind == models.ApprovalOperator {
			continue
		}
		f := core.NewFinding(r.Metadata(), g.Token, g.Spender)
		f.Description = fmt.Sprintf("Unlimited allowance on token %s to spender %s (%s).", tokenLabel(g), g.Spender, g.Kind)
		if g.Kind == models.ApprovalAmbiguous {
			f.Confidence = models.ConfidenceMedium
			f.Description += " The token standard could not be confirmed (ERC-20 vs ERC-721)."
		}
		f.Evidence = []models.Evidence{grantEvidence(g)}
		f.Subjects = grantSubjects(g)
		out = append(out, f)
	}
	return out, nil
}

// --- TXS-APPROVAL-002 -------------------------------------------------------

type largeRule struct{ threshold *big.Int }

func (largeRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-APPROVAL-002", Name: "Very large token allowance",
		Description:       "The allowance is not the unlimited sentinel but exceeds a very large threshold (default 2^128 base units), which is effectively unlimited for most tokens.",
		Category:          models.CategoryApproval,
		DefaultSeverity:   models.SeverityMedium,
		DefaultConfidence: models.ConfidenceMedium,
		Mitigation:        "Approve only the amount needed for this transaction.",
		FalsePositiveNotes: "Tokens with very small unit values or unusual decimals can legitimately need large raw amounts. " +
			"When the token standard is unresolved, the value may be an ERC-721 token ID (e.g. ENS IDs are 256-bit hashes); confidence is lowered then.",
	}
}

func (r largeRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	var out []models.Finding
	for _, g := range ac.Approvals {
		if !affectsSender(ac, g) || g.Unlimited || g.Amount == "" {
			continue
		}
		amt, ok := new(big.Int).SetString(string(g.Amount), 10)
		if !ok || amt.Cmp(r.threshold) < 0 {
			continue
		}
		f := core.NewFinding(r.Metadata(), g.Token, g.Spender)
		f.Description = fmt.Sprintf("Allowance of %s base units on token %s to %s.", g.Amount, tokenLabel(g), g.Spender)
		f.Source = models.SourceHeuristic
		if g.Kind == models.ApprovalAmbiguous {
			f.Confidence = models.ConfidenceLow
		}
		f.Evidence = []models.Evidence{grantEvidence(g)}
		f.Subjects = grantSubjects(g)
		out = append(out, f)
	}
	return out, nil
}

// --- TXS-APPROVAL-003 -------------------------------------------------------

type operatorRule struct{}

func (operatorRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-APPROVAL-003", Name: "Collection-wide NFT operator approval",
		Description:       "setApprovalForAll(operator, true) lets the operator transfer every token the sender holds in this ERC-721/ERC-1155 collection, including tokens acquired later.",
		Category:          models.CategoryApproval,
		DefaultSeverity:   models.SeverityHigh,
		DefaultConfidence: models.ConfidenceHigh,
		Mitigation:        "Grant operator approval only to marketplace contracts you have verified, and revoke it when no longer needed.",
		FalsePositiveNotes: "NFT marketplaces legitimately require operator approval to list items. " +
			"This is also the most common permission requested by NFT drainers, which is why severity is high.",
	}
}

func (r operatorRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	var out []models.Finding
	for _, g := range ac.Approvals {
		if !affectsSender(ac, g) || g.Kind != models.ApprovalOperator {
			continue
		}
		f := core.NewFinding(r.Metadata(), g.Token, g.Spender)
		f.Description = fmt.Sprintf("Operator %s would control all of the sender's tokens in collection %s.", g.Spender, tokenLabel(g))
		f.Evidence = []models.Evidence{grantEvidence(g)}
		f.Subjects = grantSubjects(g)
		out = append(out, f)
	}
	return out, nil
}

// --- TXS-APPROVAL-004 -------------------------------------------------------

type eoaSpenderRule struct{}

func (eoaSpenderRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-APPROVAL-004", Name: "Approval to an externally owned account",
		Description:       "The spender has no contract code. Protocols receive approvals through contracts; approvals to plain accounts are a common pattern in phishing.",
		Category:          models.CategoryApproval,
		DefaultSeverity:   models.SeverityHigh,
		DefaultConfidence: models.ConfidenceMedium,
		Mitigation:        "Confirm you intend to let this specific account spend your tokens. If a website asked for this approval, treat it as phishing.",
		FalsePositiveNotes: "Approving your own second wallet, or a counterfactual smart account that is not deployed yet, also matches. " +
			"Requires on-chain code lookups; silent when chain access is unavailable.",
	}
}

func (r eoaSpenderRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	if !ac.ContractsKnown {
		return nil, nil
	}
	var out []models.Finding
	for _, g := range ac.Approvals {
		spender := common.HexToAddress(g.Spender)
		info := ac.Contracts[spender]
		if !affectsSender(ac, g) || info == nil || info.IsContract || spender == ac.Tx.From {
			continue
		}
		f := core.NewFinding(r.Metadata(), g.Token, g.Spender)
		f.Description = fmt.Sprintf("Spender %s has no contract code at block %d.", g.Spender, info.AtBlock)
		f.Evidence = []models.Evidence{grantEvidence(g), core.Evidence("chain_state", "eth_getCode returned empty code", models.SourceFact, map[string]string{"address": g.Spender})}
		f.Subjects = grantSubjects(g)
		out = append(out, f)
	}
	return out, nil
}

// --- TXS-APPROVAL-005 -------------------------------------------------------

type flaggedSpenderRule struct{}

func (flaggedSpenderRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-APPROVAL-005", Name: "Approval to a flagged spender",
		Description:       "The spender is blocklisted or marked suspicious by a configured reputation source.",
		Category:          models.CategoryApproval,
		DefaultSeverity:   models.SeverityCritical,
		DefaultConfidence: models.ConfidenceHigh,
		Mitigation:        "Do not sign. If you already granted this approval, revoke it immediately.",
		FalsePositiveNotes: "Reputation data can be wrong or stale. The report names the source of each record; " +
			"operator allowlists override external opinions.",
	}
}

func (r flaggedSpenderRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	var out []models.Finding
	for _, g := range ac.Approvals {
		if !affectsSender(ac, g) {
			continue
		}
		recs := ac.Reputation[common.HexToAddress(g.Spender)]
		status := reputation.Effective(recs)
		if status != models.ReputationBlocked && status != models.ReputationSuspicious {
			continue
		}
		f := core.NewFinding(r.Metadata(), g.Token, g.Spender)
		f.Source, f.Confidence = ReputationSource(recs, status)
		if status == models.ReputationSuspicious {
			f.Severity = models.SeverityHigh
		}
		f.Description = fmt.Sprintf("Spender %s is %s according to %s.", g.Spender, status, SourcesOf(recs, status))
		f.Evidence = append([]models.Evidence{grantEvidence(g)}, ReputationEvidence(recs)...)
		f.Subjects = grantSubjects(g)
		out = append(out, f)
	}
	return out, nil
}

// --- TXS-APPROVAL-006 -------------------------------------------------------

type unknownSpenderRule struct{}

func (unknownSpenderRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-APPROVAL-006", Name: "Approval to a spender with no reputation record",
		Description:        "None of the configured reputation sources has a record for the spender. This requires investigation; it is not evidence of malice.",
		Category:           models.CategoryApproval,
		DefaultSeverity:    models.SeverityLow,
		DefaultConfidence:  models.ConfidenceLow,
		Mitigation:         "Verify the spender address against the protocol's official documentation before approving.",
		FalsePositiveNotes: "Most legitimate contracts are absent from any given list. Only reported when at least one reputation source is configured.",
	}
}

func (r unknownSpenderRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	if len(ac.ReputationSources) == 0 {
		return nil, nil
	}
	var out []models.Finding
	for _, g := range ac.Approvals {
		if !affectsSender(ac, g) || len(ac.Reputation[common.HexToAddress(g.Spender)]) > 0 {
			continue
		}
		f := core.NewFinding(r.Metadata(), g.Token, g.Spender)
		f.Source = models.SourceHeuristic
		f.Description = fmt.Sprintf("No reputation record for spender %s in %d configured source(s).", g.Spender, len(ac.ReputationSources))
		f.Evidence = []models.Evidence{grantEvidence(g)}
		f.Subjects = grantSubjects(g)
		out = append(out, f)
	}
	return out, nil
}

// --- TXS-APPROVAL-007 -------------------------------------------------------

type longExpiryRule struct{ window time.Duration }

func (longExpiryRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "TXS-APPROVAL-007", Name: "Long-lived Permit2 allowance",
		Description:        "A Permit2 allowance expires far in the future, so the spender's permission persists long after this transaction.",
		Category:           models.CategoryApproval,
		DefaultSeverity:    models.SeverityLow,
		DefaultConfidence:  models.ConfidenceHigh,
		Mitigation:         "Prefer short expirations for Permit2 allowances, or revoke via Permit2 lockdown when done.",
		FalsePositiveNotes: "Some applications set long expirations by design to avoid repeated signatures.",
	}
}

func (r longExpiryRule) Evaluate(_ context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
	now := ac.Now
	if now.IsZero() {
		now = time.Now()
	}
	limit := now.Add(r.window).Unix()
	var out []models.Finding
	for _, g := range ac.Approvals {
		if !affectsSender(ac, g) || (g.Kind != models.ApprovalPermit2 && g.Kind != models.ApprovalPermit2Signed) || g.Expiration == nil {
			continue
		}
		if *g.Expiration <= uint64(limit) { //nolint:gosec // limit is a positive unix time
			continue
		}
		f := core.NewFinding(r.Metadata(), g.Token, g.Spender)
		f.Description = fmt.Sprintf("Permit2 allowance for %s on token %s expires at unix time %d (more than %d days away).", g.Spender, tokenLabel(g), *g.Expiration, int(r.window.Hours()/24))
		f.Evidence = []models.Evidence{grantEvidence(g)}
		f.Subjects = grantSubjects(g)
		out = append(out, f)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Reputation helpers shared with interaction rules.

// ReputationEvidence converts records into evidence, labelled by source kind.
func ReputationEvidence(recs []models.ReputationRecord) []models.Evidence {
	out := make([]models.Evidence, 0, len(recs))
	for _, r := range recs {
		src := models.SourceFact // operator list/local: a fact that the operator flagged it
		if r.SourceKind == models.ReputationSourceExternal {
			src = models.SourceExternal
		}
		out = append(out, core.Evidence("reputation_record",
			fmt.Sprintf("%s: %s (%s)", r.Source, r.Status, r.Reason), src,
			map[string]string{"source": r.Source, "sourceKind": string(r.SourceKind), "status": string(r.Status), "confidence": r.Confidence.String()}))
	}
	return out
}

// ReputationSource picks the evidence source and confidence of the records
// that produced status.
func ReputationSource(recs []models.ReputationRecord, status models.ReputationStatus) (models.EvidenceSource, models.Confidence) {
	src, conf := models.SourceExternal, models.ConfidenceLow
	for _, r := range recs {
		if r.Status != status {
			continue
		}
		if r.SourceKind != models.ReputationSourceExternal {
			src = models.SourceFact
		}
		if r.Confidence > conf {
			conf = r.Confidence
		}
	}
	return src, conf
}

// SourcesOf names the sources whose records have the given status.
func SourcesOf(recs []models.ReputationRecord, status models.ReputationStatus) string {
	var names []string
	for _, r := range recs {
		if r.Status == status {
			names = append(names, r.Source)
		}
	}
	if len(names) == 0 {
		return "configured sources"
	}
	return fmt.Sprint(names)
}
