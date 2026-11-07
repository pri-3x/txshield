package analyzer

import (
	"fmt"
	"strings"

	"github.com/pri-3x/txshield/internal/evm"
	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
)

// maxRecommendations bounds the recommendation list.
const maxRecommendations = 8

// verdict never claims safety. Its strongest positive form is
// models.NoSignificantRisks.
func verdict(risk models.RiskAssessment, findings []models.Finding) string {
	significant := 0
	for _, f := range findings {
		if f.Severity >= models.SeverityLow {
			significant++
		}
	}
	switch {
	case significant == 0 && risk.Score < 20:
		return models.NoSignificantRisks
	case risk.Score < 20:
		return fmt.Sprintf("Low observed risk: %d minor finding(s) to review.", significant)
	default:
		cat := string(risk.Category)
		return fmt.Sprintf("%s risk: %d finding(s) require review before signing.", strings.ToUpper(cat[:1])+cat[1:], significant)
	}
}

func recommend(findings []models.Finding, sim *models.SimulationResult, ac *interfaces.AnalysisContext) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] && len(out) < maxRecommendations {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, f := range findings { // already sorted most severe first
		if f.Severity >= models.SeverityLow {
			add(f.Mitigation)
		}
	}
	switch {
	case sim == nil || sim.Completeness == models.CompletenessNone:
		add("This report is based on static analysis only. Run a fork simulation before signing to see the actual asset movements.")
	case sim.Completeness == models.CompletenessPartial:
		add("Simulation data is partial; review the incomplete parts listed in the simulation section.")
	}
	if !ac.ContractsKnown {
		add("Contract facts were not checked. Configure an RPC endpoint so TxShield can verify code presence, proxies, and token standards.")
	}
	add("Verify the destination address, amounts, and network in your wallet's confirmation screen before signing.")
	return out
}

func summarize(tx *models.Transaction, c *models.DecodedCall, block uint64) models.TransactionSummary {
	s := models.TransactionSummary{
		ChainID: tx.ChainID,
		From:    tx.From.Hex(),
		Value:   models.QuantityFromBig(tx.Value),
		Kind:    c.Kind,
		Method:  c.Method,
		Block:   tx.Block.String(),
	}
	if block > 0 {
		s.Block = fmt.Sprint(block)
	}
	if ch, ok := evm.ChainByID(tx.ChainID); ok {
		s.ChainName = ch.DisplayName
	}
	if tx.To != nil {
		s.To = tx.To.Hex()
	}
	value := ""
	if tx.Value != nil && tx.Value.Sign() > 0 {
		value = fmt.Sprintf(", sending %s wei", tx.Value)
	}
	switch c.Kind {
	case models.CallContractCreation:
		s.Description = fmt.Sprintf("Deploy a new contract (%d bytes of init code)%s", len(tx.Data), value)
	case models.CallNativeTransfer:
		s.Description = fmt.Sprintf("Transfer %s wei to %s", tx.Value, s.To)
	case models.CallUnknown:
		s.Description = fmt.Sprintf("Call unrecognized function %s on %s%s", orDash(c.Selector), s.To, value)
	default:
		std := ""
		if c.Standard != "" {
			std = " [" + c.Standard + "]"
		}
		method := c.Signature
		if method == "" {
			method = "function " + c.Selector + " (arguments did not decode)"
		}
		s.Description = fmt.Sprintf("Call %s%s on %s%s", method, std, s.To, value)
		if n := len(c.Children); n > 0 {
			s.Description += fmt.Sprintf(" containing %d sub-call(s)", n)
		}
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
