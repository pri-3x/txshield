package api

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/txshield/txshield/internal/analyzer"
	"github.com/txshield/txshield/internal/logging"
	"github.com/txshield/txshield/internal/security/approvals"
	"github.com/txshield/txshield/internal/security/scoring"
	"github.com/txshield/txshield/pkg/interfaces"
	"github.com/txshield/txshield/pkg/models"
	"github.com/txshield/txshield/pkg/txerrors"
)

func (s *Server) engineOr503(w http.ResponseWriter, r *http.Request) *Engine {
	if s.engine == nil || s.engine.Analyzer == nil {
		writeError(w, r, txerrors.New(txerrors.KindUnavailable, "engine_unavailable", "analysis engine is not configured"))
		return nil
	}
	return s.engine
}

func (s *Server) parseTx(req models.TransactionRequest) (*models.Transaction, error) {
	return models.ParseTransaction(req, models.ParseLimits{MaxCalldataBytes: s.cfg.Limits.MaxCalldataBytes})
}

// runAnalysis performs an analysis for the analyze and approvals endpoints.
func (s *Server) runAnalysis(r *http.Request, req AnalyzeRequest, simulateDefault bool) (*models.RiskReport, *models.Transaction, chainSet, error) {
	e := s.engine
	tx, err := s.parseTx(req.TxRequest)
	if err != nil {
		return nil, nil, chainSet{}, err
	}
	cs, err := e.resolveChain(r.Context(), tx.ChainID, req.RPCURL)
	if err != nil {
		return nil, nil, cs, err
	}
	simulate := simulateDefault
	if req.Simulate != nil {
		simulate = *req.Simulate
	}
	start := time.Now()
	report, err := e.analyzerFor(cs).Analyze(r.Context(), analyzer.Request{
		Tx: tx, Decode: interfaces.DecodeOptions{ABIJSON: req.ABI}, Simulate: simulate, RequestID: RequestIDFrom(r.Context()),
	})
	if err != nil {
		return nil, nil, cs, err
	}
	if cs.warning != "" {
		report.Warnings = append([]string{cs.warning}, report.Warnings...)
	}
	s.metrics.AnalysisDuration.Observe(time.Since(start).Seconds())
	s.metrics.Analyses.WithLabelValues(string(report.Risk.Category)).Inc()
	if sim := report.Simulation; sim != nil && sim.Status != models.SimNotRun {
		s.metrics.Simulations.WithLabelValues(sim.Backend, string(sim.Status), string(sim.Completeness)).Inc()
	}
	return report, tx, cs, nil
}

// persist stores a report; failures degrade to a warning (the analysis
// itself succeeded and must still be returned).
//
// Reports built from a caller-supplied RPC endpoint are never stored: their
// contract facts and simulation come from a node the caller controls, and
// history is shared (dashboard, /stats, address history).
func (s *Server) persist(ctx context.Context, report *models.RiskReport, tx *models.Transaction, want *bool, cs chainSet) {
	if s.engine.Store == nil || (want != nil && !*want) {
		return
	}
	if cs.userRPC {
		report.Warnings = append(report.Warnings, "analyses that use a caller-supplied RPC endpoint are not stored in history")
		return
	}
	// Use a detached context: the client may disconnect after the response.
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := s.engine.Store.SaveReport(sctx, report, tx); err != nil {
		s.metrics.StoreErrors.Inc()
		logging.FromContext(ctx).Error("persisting analysis failed", "err", err)
		report.Warnings = append(report.Warnings, "analysis could not be stored; it will not appear in history")
	}
}

// handleAnalyze serves POST /api/v1/analyze.
func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if s.engineOr503(w, r) == nil {
		return
	}
	var req AnalyzeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	report, tx, cs, err := s.runAnalysis(r, req, true)
	if err != nil {
		writeError(w, r, err)
		return
	}
	s.persist(r.Context(), report, tx, req.Persist, cs)
	writeJSON(w, http.StatusOK, report)
}

// handleSimulate serves POST /api/v1/simulate.
func (s *Server) handleSimulate(w http.ResponseWriter, r *http.Request) {
	e := s.engineOr503(w, r)
	if e == nil {
		return
	}
	var req SimulateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	tx, err := s.parseTx(req.TxRequest)
	if err != nil {
		writeError(w, r, err)
		return
	}
	cs, err := e.resolveChain(r.Context(), tx.ChainID, req.RPCURL)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if cs.chains == nil || cs.simulator == nil {
		writeError(w, r, txerrors.New(txerrors.KindUnsupported, "simulation_unavailable", "simulation is not available for this chain on this server"))
		return
	}
	reader, err := cs.chains.Client(r.Context(), tx.ChainID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	block, err := reader.ResolveBlock(r.Context(), tx.Block)
	if err != nil {
		writeError(w, r, err)
		return
	}
	res, err := cs.simulator.Simulate(r.Context(), interfaces.SimulationRequest{Tx: tx, BlockNumber: block.Number})
	if err != nil {
		writeError(w, r, err)
		return
	}
	s.metrics.Simulations.WithLabelValues(res.Backend, string(res.Status), string(res.Completeness)).Inc()
	writeJSON(w, http.StatusOK, res)
}

// ApprovalWithState pairs a grant with the permission currently in force.
type ApprovalWithState struct {
	models.ApprovalGrant
	Current *models.ApprovalState `json:"current,omitempty"`
}

// ApprovalAnalysis is the response of POST /api/v1/approvals/analyze.
type ApprovalAnalysis struct {
	Transaction     models.TransactionSummary `json:"transaction"`
	Approvals       []ApprovalWithState       `json:"approvals"`
	Findings        []models.Finding          `json:"findings"`
	Risk            models.RiskAssessment     `json:"risk"`
	Recommendations []string                  `json:"recommendations"`
	Warnings        []string                  `json:"warnings,omitempty"`
	Disclaimer      string                    `json:"disclaimer"`
}

// handleApprovals serves POST /api/v1/approvals/analyze: the permissions a
// transaction grants, their current on-chain values, and approval-related
// findings scored on their own.
// maxCurrentStateReads caps the RPC reads one approvals request may cause
// (nested multicalls can carry hundreds of approvals).
const maxCurrentStateReads = 20

func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request) {
	e := s.engineOr503(w, r)
	if e == nil {
		return
	}
	var req AnalyzeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	report, tx, cs, err := s.runAnalysis(r, req, false)
	if err != nil {
		writeError(w, r, err)
		return
	}
	out := ApprovalAnalysis{
		Transaction: report.Transaction, Approvals: []ApprovalWithState{}, Findings: []models.Finding{},
		Warnings: report.Warnings, Disclaimer: models.Disclaimer,
	}
	var reader interfaces.ChainReader
	if cs.chains != nil {
		reader, _ = cs.chains.Reader(tx.ChainID)
	}
	var block uint64
	if report.Simulation != nil {
		block = report.Simulation.BlockNumber
	}
	for i, g := range report.Approvals {
		aws := ApprovalWithState{ApprovalGrant: g}
		if reader != nil && i < maxCurrentStateReads {
			st := approvals.ReadCurrent(r.Context(), reader, g, block)
			aws.Current = &st
		}
		out.Approvals = append(out.Approvals, aws)
	}
	if reader != nil && len(report.Approvals) > maxCurrentStateReads {
		out.Warnings = append(out.Warnings, fmt.Sprintf("current on-chain allowance was read for the first %d of %d approvals only", maxCurrentStateReads, len(report.Approvals)))
	}
	for _, f := range report.Findings {
		if f.Category == models.CategoryApproval || f.RuleID == "TXS-PATTERN-002" {
			out.Findings = append(out.Findings, f)
		}
	}
	out.Risk = e.Analyzer.Scorer().Score(interfaces.ScoringInput{Findings: out.Findings, Simulation: report.Simulation, EnabledChecks: len(e.Analyzer.Rules())})
	out.Findings = scoring.Deduplicate(out.Findings)
	seen := map[string]bool{}
	for _, f := range out.Findings {
		if f.Severity >= models.SeverityLow && !seen[f.Mitigation] {
			seen[f.Mitigation] = true
			out.Recommendations = append(out.Recommendations, f.Mitigation)
		}
	}
	if len(out.Approvals) == 0 {
		out.Recommendations = append(out.Recommendations, "This transaction grants no token permissions that TxShield recognizes.")
	}
	out.Recommendations = slices.Clip(append(out.Recommendations, "Review and revoke allowances you no longer need."))
	writeJSON(w, http.StatusOK, out)
}
