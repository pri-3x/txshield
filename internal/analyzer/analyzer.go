// Package analyzer orchestrates a full transaction analysis: decode, gather
// context (reputation, contract facts), simulate, evaluate rules, score, and
// assemble the report. It depends only on interfaces, so every stage can be
// replaced or omitted (offline mode runs without RPC, simulation, or DB).
package analyzer

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/txshield/txshield/internal/security/approvals"
	"github.com/txshield/txshield/internal/security/core"
	"github.com/txshield/txshield/internal/security/reputation"
	"github.com/txshield/txshield/internal/security/scoring"
	"github.com/txshield/txshield/pkg/interfaces"
	"github.com/txshield/txshield/pkg/models"
	"github.com/txshield/txshield/pkg/txerrors"
)

// Deps are the analyzer's collaborators. Decoder, Rules, and Scorer are
// required; the rest are optional.
type Deps struct {
	Decoder    interfaces.Decoder
	Rules      interfaces.RuleEngine
	Scorer     interfaces.RiskScorer
	Reputation *reputation.Aggregator
	Inspector  interfaces.ContractInspector
	Simulator  interfaces.Simulator
	// Chains, when set, resolves the transaction's block reference to a
	// concrete block once per analysis so that contract facts and
	// simulation read the same state.
	Chains interfaces.ChainRegistry

	EngineVersion string
	Now           func() time.Time
	// MaxAddresses bounds reputation lookups and contract inspection per
	// analysis (adversarial calldata can reference thousands of addresses).
	MaxAddresses int
	// InspectConcurrency bounds parallel contract inspections.
	InspectConcurrency int
}

// Analyzer runs analyses. It is safe for concurrent use.
type Analyzer struct{ d Deps }

// New validates deps and returns an Analyzer.
func New(d Deps) (*Analyzer, error) {
	if d.Decoder == nil || d.Rules == nil || d.Scorer == nil {
		return nil, errors.New("analyzer: decoder, rules, and scorer are required")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.MaxAddresses <= 0 {
		d.MaxAddresses = 64
	}
	if d.InspectConcurrency <= 0 {
		d.InspectConcurrency = 8
	}
	if d.EngineVersion == "" {
		d.EngineVersion = "dev"
	}
	return &Analyzer{d: d}, nil
}

// Request is one analysis request.
type Request struct {
	Tx        *models.Transaction
	Decode    interfaces.DecodeOptions
	Simulate  bool
	RequestID string
	// BlockNumber is the resolved block state is read at (0 = unknown,
	// offline). Resolving tags to numbers is the caller's job (Phase 4).
	BlockNumber uint64
}

// Analyze produces a report. It returns an error only for invalid input or
// cancellation; dependency failures degrade the report (with warnings and
// lower confidence) instead of failing it.
func (a *Analyzer) Analyze(ctx context.Context, req Request) (*models.RiskReport, error) {
	if req.Tx == nil {
		return nil, txerrors.New(txerrors.KindInvalidInput, "missing_transaction", "transaction is required")
	}
	tx := req.Tx
	var warnings []string

	decoded, err := a.d.Decoder.Decode(ctx, tx, req.Decode)
	if err != nil {
		return nil, err
	}

	if req.BlockNumber == 0 && a.d.Chains != nil {
		if r, err := a.d.Chains.Reader(tx.ChainID); err != nil {
			if txerrors.KindOf(err) == txerrors.KindUnsupported {
				return nil, err // chain not configured or endpoint serves another chain
			}
			warnings = append(warnings, "could not resolve the block to analyze against; chain-dependent checks may be missing")
		} else if info, err := r.ResolveBlock(ctx, tx.Block); err != nil {
			if txerrors.KindOf(err) == txerrors.KindNotFound {
				return nil, err
			}
			warnings = append(warnings, "could not resolve the block to analyze against; chain-dependent checks may be missing")
		} else {
			req.BlockNumber = info.Number
		}
	}

	sim := a.simulate(ctx, req, &warnings)

	// First pass of approval extraction (standards unresolved) only to know
	// which spenders/tokens to look up.
	prelim := approvals.Extract(tx, decoded, nil)
	roles := core.CollectAddresses(tx, decoded, prelim, sim)
	addrs := make([]common.Address, 0, len(roles))
	for addr := range roles {
		addrs = append(addrs, addr)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Hex() < addrs[j].Hex() })
	if len(addrs) > a.d.MaxAddresses {
		warnings = append(warnings, fmt.Sprintf("%d addresses involved; only the first %d were checked for reputation and contract facts", len(addrs), a.d.MaxAddresses))
		addrs = addrs[:a.d.MaxAddresses]
	}

	ac := &interfaces.AnalysisContext{
		Tx: tx, Decoded: decoded, Simulation: sim, BlockNumber: req.BlockNumber, Now: a.d.Now(),
		Contracts: map[common.Address]*models.ContractInfo{}, Reputation: map[common.Address][]models.ReputationRecord{},
	}

	var wg sync.WaitGroup
	var repWarnings, inspWarnings []string
	if a.d.Reputation != nil {
		ac.ReputationSources = a.d.Reputation.Sources()
		wg.Add(1)
		go func() {
			defer wg.Done()
			ac.Reputation, repWarnings = a.d.Reputation.LookupAll(ctx, tx.ChainID, addrs)
		}()
	}
	if a.d.Inspector != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ac.Contracts, inspWarnings = a.inspect(ctx, tx.ChainID, addrs, req.BlockNumber)
		}()
	}
	wg.Wait()
	warnings = append(warnings, repWarnings...)
	warnings = append(warnings, inspWarnings...)
	ac.ContractsKnown = a.d.Inspector != nil && len(inspWarnings) == 0
	if err := ctx.Err(); err != nil {
		return nil, txerrors.Wrap(err, txerrors.KindTimeout, "analysis_timeout", "analysis exceeded its deadline")
	}

	ac.Approvals = approvals.Extract(tx, decoded, ac.Contracts)

	results := a.d.Rules.Run(ctx, ac)
	var findings []models.Finding
	failed := 0
	for _, r := range results {
		if r.Err != nil {
			failed++
			warnings = append(warnings, fmt.Sprintf("rule %s did not complete (%v); its checks are missing from this report", r.RuleID, r.Err))
			continue
		}
		findings = append(findings, r.Findings...)
	}
	if err := ctx.Err(); err != nil {
		return nil, txerrors.Wrap(err, txerrors.KindTimeout, "analysis_timeout", "analysis exceeded its deadline")
	}

	ruleMeta := a.d.Rules.Rules()
	risk := a.d.Scorer.Score(interfaces.ScoringInput{
		Findings: findings, Simulation: sim, FailedRules: failed, EnabledChecks: len(ruleMeta),
	})
	findings = scoring.Deduplicate(findings)
	if findings == nil {
		findings = []models.Finding{}
	}
	if !ac.ContractsKnown && a.d.Inspector == nil {
		warnings = append(warnings, "contract facts (code presence, proxies, token standards) were not checked: no chain access configured")
	}

	report := &models.RiskReport{
		ID:              newID(),
		RequestID:       req.RequestID,
		EngineVersion:   a.d.EngineVersion,
		AnalyzedAt:      a.d.Now().UTC(),
		Transaction:     summarize(tx, decoded, req.BlockNumber),
		Decoded:         decoded,
		Risk:            risk,
		Findings:        findings,
		Approvals:       ac.Approvals,
		Simulation:      sim,
		Recommendations: recommend(findings, sim, ac),
		EnabledChecks:   a.enabledChecks(ruleMeta, sim),
		Warnings:        warnings,
		Disclaimer:      models.Disclaimer,
	}
	if report.Approvals == nil {
		report.Approvals = []models.ApprovalGrant{}
	}
	if sim != nil {
		report.BalanceChanges = sim.BalanceChanges
	}
	report.Verdict = verdict(risk, findings)
	return report, nil
}

func (a *Analyzer) simulate(ctx context.Context, req Request, warnings *[]string) *models.SimulationResult {
	notRun := func(reason string) *models.SimulationResult {
		return &models.SimulationResult{Backend: "none", Status: models.SimNotRun, Completeness: models.CompletenessNone, ChainID: req.Tx.ChainID, IncompleteReasons: []string{reason}}
	}
	switch {
	case !req.Simulate:
		return notRun("simulation not requested")
	case a.d.Simulator == nil:
		return notRun("no simulation backend configured")
	}
	res, err := a.d.Simulator.Simulate(ctx, interfaces.SimulationRequest{Tx: req.Tx, BlockNumber: req.BlockNumber})
	if err != nil || res == nil {
		msg := "simulation backend failed"
		if e, ok := txerrors.As(err); ok {
			msg = e.Message
		}
		*warnings = append(*warnings, "simulation could not be performed ("+msg+"); this says nothing about whether the transaction would succeed")
		r := notRun(msg)
		r.Status, r.Backend = models.SimError, a.d.Simulator.Name()
		return r
	}
	return res
}

func (a *Analyzer) inspect(ctx context.Context, chainID uint64, addrs []common.Address, block uint64) (map[common.Address]*models.ContractInfo, []string) {
	out := make(map[common.Address]*models.ContractInfo, len(addrs))
	var mu sync.Mutex
	var failures int
	sem := make(chan struct{}, a.d.InspectConcurrency)
	var wg sync.WaitGroup
	for _, addr := range addrs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			info, err := a.d.Inspector.Inspect(ctx, chainID, addr, block)
			mu.Lock()
			defer mu.Unlock()
			if err != nil || info == nil {
				failures++
				return
			}
			out[addr] = info
		}()
	}
	wg.Wait()
	if failures > 0 {
		return out, []string{fmt.Sprintf("contract facts unavailable for %d address(es); rules that need them were skipped", failures)}
	}
	return out, nil
}

func (a *Analyzer) enabledChecks(rules []models.RuleMetadata, sim *models.SimulationResult) []string {
	out := make([]string, 0, len(rules)+4)
	for _, r := range rules {
		out = append(out, r.ID)
	}
	if a.d.Reputation != nil {
		for _, s := range a.d.Reputation.Sources() {
			out = append(out, "reputation:"+s)
		}
	}
	if a.d.Inspector != nil {
		out = append(out, "contract-facts")
	}
	if sim != nil && sim.Status != models.SimNotRun && sim.Status != models.SimError {
		out = append(out, "simulation:"+sim.Backend)
	}
	return out
}

// newID returns a random RFC 4122 version 4 UUID.
func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// With returns a copy of the analyzer that uses different chain-dependent
// components (any may be nil for offline analysis). Decoder, rules, scorer,
// and reputation sources are shared.
func (a *Analyzer) With(chains interfaces.ChainRegistry, inspector interfaces.ContractInspector, sim interfaces.Simulator) *Analyzer {
	d := a.d
	d.Chains, d.Inspector, d.Simulator = chains, inspector, sim
	return &Analyzer{d: d}
}

// Scorer returns the risk scorer (used to score finding subsets).
func (a *Analyzer) Scorer() interfaces.RiskScorer { return a.d.Scorer }

// Reputation returns the reputation aggregator (nil when none configured).
func (a *Analyzer) Reputation() *reputation.Aggregator { return a.d.Reputation }

// Rules returns metadata of the enabled rules.
func (a *Analyzer) Rules() []models.RuleMetadata { return a.d.Rules.Rules() }

// Decode exposes the analyzer's decoder (offline, no chain access).
func (a *Analyzer) Decode(ctx context.Context, tx *models.Transaction, opts interfaces.DecodeOptions) (*models.DecodedCall, error) {
	return a.d.Decoder.Decode(ctx, tx, opts)
}
