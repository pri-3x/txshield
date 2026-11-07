// Package rules implements TxShield's pluggable security rule engine and the
// built-in interaction, value-transfer, dangerous-pattern, and simulation
// rules. Approval rules live in package approvals and are included by
// Default.
package rules

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/pri-3x/txshield/internal/security/approvals"
	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
)

// MaxFindingsPerRule bounds the output of a single rule on adversarial
// input (e.g. a multicall with hundreds of approvals).
const MaxFindingsPerRule = 100

// ErrRuleTimeout is returned in RuleResult.Err when a rule exceeds its budget.
var ErrRuleTimeout = errors.New("rule timed out")

// Engine runs rules with isolation: a rule that panics, errors, or times out
// is reported as failed and never aborts the analysis.
type Engine struct {
	rules   []interfaces.Rule
	timeout time.Duration
}

var _ interfaces.RuleEngine = (*Engine)(nil)

// NewEngine validates rule metadata and returns an engine. Every rule must
// have a unique ID and complete metadata (name, description, mitigation,
// false-positive notes, valid category and severity).
func NewEngine(timeout time.Duration, rules ...interfaces.Rule) (*Engine, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	seen := map[string]bool{}
	for _, r := range rules {
		m := r.Metadata()
		if err := validateMetadata(m); err != nil {
			return nil, err
		}
		if seen[m.ID] {
			return nil, fmt.Errorf("rule %s registered twice", m.ID)
		}
		seen[m.ID] = true
	}
	return &Engine{rules: rules, timeout: timeout}, nil
}

func validateMetadata(m models.RuleMetadata) error {
	switch {
	case m.ID == "":
		return errors.New("rule has empty ID")
	case m.Name == "" || m.Description == "" || m.Mitigation == "" || m.FalsePositiveNotes == "":
		return fmt.Errorf("rule %s: name, description, mitigation, and false-positive notes are required", m.ID)
	case m.Category == "":
		return fmt.Errorf("rule %s: category is required", m.ID)
	case m.DefaultSeverity < models.SeverityInfo || m.DefaultSeverity > models.SeverityCritical:
		return fmt.Errorf("rule %s: invalid severity", m.ID)
	case m.DefaultConfidence < models.ConfidenceLow || m.DefaultConfidence > models.ConfidenceHigh:
		return fmt.Errorf("rule %s: invalid confidence", m.ID)
	}
	return nil
}

// Rules returns metadata for every registered rule, in registration order.
func (e *Engine) Rules() []models.RuleMetadata {
	out := make([]models.RuleMetadata, len(e.rules))
	for i, r := range e.rules {
		out[i] = r.Metadata()
	}
	return out
}

// Run evaluates all rules. Results are returned in registration order so
// reports are deterministic.
//
// Rules are pure functions over in-memory data that take microseconds, so
// they run one after another on a single worker goroutine, supervised by
// one reusable timer. (One goroutine and one timer per rule cost more in
// scheduler and timer contention than the rules themselves under parallel
// load; see docs/benchmarks.md.) If a rule exceeds its budget it is reported
// as timed out, its worker is abandoned, and a fresh worker continues with
// the next rule, so a stuck rule costs only its own result.
func (e *Engine) Run(ctx context.Context, ac *interfaces.AnalysisContext) []interfaces.RuleResult {
	n := len(e.rules)
	results := make([]interfaces.RuleResult, n)
	timer := time.NewTimer(e.timeout)
	defer timer.Stop()

	next := 0
	for next < n {
		wctx, cancel := context.WithCancel(ctx)
		// Buffered so an abandoned worker never blocks.
		ch := make(chan interfaces.RuleResult, n-next)
		go func(from int) {
			for i := from; i < n && wctx.Err() == nil; i++ {
				ch <- e.evaluate(wctx, e.rules[i], ac)
			}
		}(next)

	supervise:
		for next < n {
			timer.Reset(e.timeout)
			select {
			case r := <-ch:
				results[next] = r
				next++
			case <-timer.C:
				results[next] = interfaces.RuleResult{RuleID: e.rules[next].Metadata().ID, Err: ErrRuleTimeout, Duration: e.timeout}
				next++
				break supervise
			case <-ctx.Done():
				for ; next < n; next++ {
					results[next] = interfaces.RuleResult{RuleID: e.rules[next].Metadata().ID, Err: ctx.Err()}
				}
			}
		}
		cancel()
	}
	return results
}

// evaluate runs one rule with panic recovery and normalizes its output.
func (e *Engine) evaluate(ctx context.Context, r interfaces.Rule, ac *interfaces.AnalysisContext) (res interfaces.RuleResult) {
	meta := r.Metadata()
	res.RuleID = meta.ID
	start := time.Now()
	func() {
		defer func() {
			if p := recover(); p != nil {
				res.Err = fmt.Errorf("rule panicked: %v", p)
			}
		}()
		res.Findings, res.Err = r.Evaluate(ctx, ac)
	}()
	res.Duration = time.Since(start)
	if res.Err != nil {
		res.Findings = nil
		return res
	}
	if len(res.Findings) > MaxFindingsPerRule {
		res.Findings = res.Findings[:MaxFindingsPerRule]
	}
	for i := range res.Findings {
		f := &res.Findings[i]
		f.RuleID = meta.ID // rules cannot impersonate each other
		if f.Fingerprint == "" {
			f.Fingerprint = meta.ID
		}
		if f.Category == "" {
			f.Category = meta.Category
		}
		if f.Source == "" {
			f.Source = models.SourceHeuristic
		}
	}
	return res
}

// Config tunes the built-in rule set.
type Config struct {
	Approvals approvals.Config
}

// Default returns all built-in rules.
func Default(cfg Config) []interfaces.Rule {
	rs := approvals.Rules(cfg.Approvals)
	rs = append(rs,
		blocklistedRule{}, suspiciousRule{}, unknownTargetRule{}, unverifiedRule{}, calldataToEOARule{}, unexpectedCallsRule{},
		unexpectedOutflowRule{}, multiAssetOutflowRule{}, netLossRule{}, valueToNonPayableRule{}, fullBalanceRule{},
		delegatecallRule{}, signedPermitRule{}, batchRule{}, ownershipRule{}, upgradeRule{}, selfdestructRule{},
		flashLoanRule{}, embeddedTransferRule{}, trailingDataRule{}, reentrancyRule{},
		revertRule{},
	)
	return rs
}
