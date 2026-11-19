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
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/pri-3x/txshield/internal/security/approvals"
	"github.com/pri-3x/txshield/internal/security/core"
	"github.com/pri-3x/txshield/internal/security/reputation"
	"github.com/pri-3x/txshield/internal/security/scoring"
	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
	"github.com/pri-3x/txshield/pkg/txerrors"
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
type Analyzer struct {
	d      Deps
	tokens *tokenCache
}

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
	return &Analyzer{d: d, tokens: newTokenCache(4096)}, nil
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
	// Timings, when non-nil, receives how long each stage took.
	Timings *Timings
}

// Timings records the wall-clock duration of each analysis stage. Context
// gathering overlaps simulation, so stages do not add up to Total.
type Timings struct {
	Decode   time.Duration // calldata decoding (offline)
	Block    time.Duration // resolving the block to analyze against
	Simulate time.Duration // simulation backend
	Context  time.Duration // reputation and contract lookups, summed (the first part overlaps Simulate)
	Rules    time.Duration // rule evaluation and scoring
	Tokens   time.Duration // token symbol/decimals lookups (overlaps Context)
	Total    time.Duration
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
	tm := req.Timings
	if tm == nil {
		tm = &Timings{}
	}
	began := time.Now()
	defer func() { tm.Total = time.Since(began) }()

	decoded, err := a.d.Decoder.Decode(ctx, tx, req.Decode)
	if err != nil {
		return nil, err
	}
	tm.Decode = time.Since(began)

	stage := time.Now()
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
	tm.Block = time.Since(stage)

	// Simulation and context gathering for the addresses named in calldata
	// run at the same time; addresses that only appear in the simulation
	// (traced contracts, asset recipients) are looked up afterwards.
	var sim *models.SimulationResult
	var simWarnings []string
	simDone := make(chan struct{})
	go func() {
		defer close(simDone)
		// A panicking backend must not take the server down (this goroutine
		// is outside the HTTP handler's recovery); it degrades like an
		// infrastructure failure.
		defer func() {
			if p := recover(); p != nil {
				sim = &models.SimulationResult{Backend: "none", Status: models.SimError, Completeness: models.CompletenessNone, ChainID: tx.ChainID,
					IncompleteReasons: []string{"simulation backend failed"}}
				simWarnings = append(simWarnings, "simulation could not be performed (internal error); this says nothing about whether the transaction would succeed")
			}
		}()
		t := time.Now()
		sim = a.simulate(ctx, req, &simWarnings)
		tm.Simulate = time.Since(t)
	}()

	// First pass of approval extraction (standards unresolved) only to know
	// which spenders/tokens to look up.
	prelim := approvals.Extract(tx, decoded, nil)
	pre := a.limitAddresses(core.CollectAddresses(tx, decoded, prelim, nil))
	preCh := make(chan gathered, 1)
	var preDur time.Duration
	go func() {
		g := gathered{contracts: map[common.Address]*models.ContractInfo{}, reputation: map[common.Address][]models.ReputationRecord{}, inspectFailures: len(pre)}
		t := time.Now()
		defer func() {
			preDur = time.Since(t)
			if p := recover(); p != nil {
				g.repWarnings = []string{"reputation and contract checks failed (internal error)"}
			}
			preCh <- g
		}()
		g = a.gather(ctx, tx.ChainID, pre, req.BlockNumber)
	}()

	<-simDone
	warnings = append(warnings, simWarnings...)
	roles := core.CollectAddresses(tx, decoded, prelim, sim)
	if len(roles) > a.d.MaxAddresses {
		warnings = append(warnings, fmt.Sprintf("%d addresses involved; only the first %d were checked for reputation and contract facts", len(roles), a.d.MaxAddresses))
	}
	all := a.limitAddresses(roles)

	// Token display metadata only reads the simulation result; it is applied
	// after the rules have run.
	var meta map[common.Address]tokenMeta
	metaDone := make(chan struct{})
	go func() {
		defer close(metaDone)
		defer func() {
			if recover() != nil {
				meta = nil // display hints only
			}
		}()
		t := time.Now()
		meta = a.fetchTokenMeta(ctx, tx.ChainID, sim)
		tm.Tokens = time.Since(t)
	}()

	g := <-preCh
	tm.Context = preDur
	if extra := missing(all, pre); len(extra) > 0 {
		t := time.Now()
		g.merge(a.gather(ctx, tx.ChainID, extra, req.BlockNumber))
		tm.Context += time.Since(t)
	}

	ac := &interfaces.AnalysisContext{
		Tx: tx, Decoded: decoded, Simulation: sim, BlockNumber: req.BlockNumber, Now: a.d.Now(),
		Contracts: g.contracts, Reputation: g.reputation,
	}
	if a.d.Reputation != nil {
		ac.ReputationSources = a.d.Reputation.Sources()
	}
	warnings = append(warnings, g.warnings()...)
	ac.ContractsKnown = a.d.Inspector != nil && g.inspectFailures == 0
	if err := ctx.Err(); err != nil {
		<-metaDone
		return nil, txerrors.Wrap(err, txerrors.KindTimeout, "analysis_timeout", "analysis exceeded its deadline")
	}

	stage = time.Now()
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
		<-metaDone
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
	tm.Rules = time.Since(stage)
	<-metaDone

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
		applyTokenMeta(sim, meta)
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

func (a *Analyzer) inspect(ctx context.Context, chainID uint64, addrs []common.Address, block uint64) (map[common.Address]*models.ContractInfo, int) {
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
	return out, failures
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
// and reputation sources are shared. The token metadata cache is shared only
// when the copy reads the same chains: data from another endpoint (such as a
// caller-supplied RPC, which the caller controls) must not reach other
// callers' reports.
func (a *Analyzer) With(chains interfaces.ChainRegistry, inspector interfaces.ContractInspector, sim interfaces.Simulator) *Analyzer {
	d := a.d
	sameChains := d.Chains == chains
	d.Chains, d.Inspector, d.Simulator = chains, inspector, sim
	cache := a.tokens
	if !sameChains || cache == nil {
		cache = newTokenCache(maxTokenMetadata)
	}
	return &Analyzer{d: d, tokens: cache}
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
