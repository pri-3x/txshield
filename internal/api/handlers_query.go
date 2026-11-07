package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/pri-3x/txshield/internal/security/reputation"
	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
	"github.com/pri-3x/txshield/pkg/txerrors"
)

const (
	defaultPageSize = 20
	maxPageSize     = 100
	maxOffset       = 10_000
)

// PageResponse wraps paginated listings.
type PageResponse[T any] struct {
	Items  []T   `json:"items"`
	Total  int64 `json:"total"`
	Limit  int   `json:"limit"`
	Offset int   `json:"offset"`
}

func parsePage(r *http.Request) (interfaces.Page, error) {
	p := interfaces.Page{Limit: defaultPageSize}
	q := r.URL.Query()
	var errs []txerrors.FieldError
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxPageSize {
			errs = append(errs, txerrors.FieldError{Field: "limit", Message: "must be between 1 and 100"})
		}
		p.Limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > maxOffset {
			errs = append(errs, txerrors.FieldError{Field: "offset", Message: "must be between 0 and 10000"})
		}
		p.Offset = n
	}
	if len(errs) > 0 {
		return p, txerrors.Invalid(errs...)
	}
	return p, nil
}

func parseChainParam(r *http.Request, required bool) (*uint64, error) {
	v := r.URL.Query().Get("chainId")
	if v == "" {
		if required {
			return nil, txerrors.Invalid(txerrors.FieldError{Field: "chainId", Message: "is required"})
		}
		return nil, nil
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil || n == 0 || n > models.MaxChainID {
		return nil, txerrors.Invalid(txerrors.FieldError{Field: "chainId", Message: "must be a positive integer"})
	}
	return &n, nil
}

func parseSince(r *http.Request) (*time.Time, error) {
	v := r.URL.Query().Get("since")
	if v == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return nil, txerrors.Invalid(txerrors.FieldError{Field: "since", Message: "must be an RFC 3339 timestamp"})
	}
	return &t, nil
}

func (s *Server) storeOr503(w http.ResponseWriter, r *http.Request) interfaces.AnalysisStore {
	if s.engine == nil || s.engine.Store == nil {
		writeError(w, r, txerrors.New(txerrors.KindUnavailable, "persistence_disabled", "analysis history is not available: persistence is disabled on this server"))
		return nil
	}
	return s.engine.Store
}

// handleListAnalyses serves GET /api/v1/analyses.
func (s *Server) handleListAnalyses(w http.ResponseWriter, r *http.Request) {
	st := s.storeOr503(w, r)
	if st == nil {
		return
	}
	page, err := parsePage(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	var f interfaces.AnalysisFilter
	if f.ChainID, err = parseChainParam(r, false); err != nil {
		writeError(w, r, err)
		return
	}
	if f.Since, err = parseSince(r); err != nil {
		writeError(w, r, err)
		return
	}
	q := r.URL.Query()
	if v := q.Get("minScore"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 100 {
			writeError(w, r, txerrors.Invalid(txerrors.FieldError{Field: "minScore", Message: "must be between 0 and 100"}))
			return
		}
		f.MinScore = &n
	}
	if v := q.Get("address"); v != "" {
		a, err := models.ParseAddress(v)
		if err != nil {
			writeError(w, r, txerrors.Invalid(txerrors.FieldError{Field: "address", Message: err.Error()}))
			return
		}
		f.Address = &a
	}
	items, total, err := st.ListReports(r.Context(), f, page)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, PageResponse[models.AnalysisSummary]{Items: items, Total: total, Limit: page.Limit, Offset: page.Offset})
}

// handleGetAnalysis serves GET /api/v1/analyses/{id}.
func (s *Server) handleGetAnalysis(w http.ResponseWriter, r *http.Request) {
	st := s.storeOr503(w, r)
	if st == nil {
		return
	}
	rep, err := st.GetReport(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// handleStats serves GET /api/v1/stats.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	st := s.storeOr503(w, r)
	if st == nil {
		return
	}
	since, err := parseSince(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	stats, err := st.Stats(r.Context(), since)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// AddressReport is the response of GET /api/v1/address/{address}.
type AddressReport struct {
	Address    string                                `json:"address"`
	ChainID    uint64                                `json:"chainId"`
	Contract   *models.ContractInfo                  `json:"contract,omitempty"`
	Reputation AddressReputation                     `json:"reputation"`
	History    *PageResponse[models.AnalysisSummary] `json:"history,omitempty"`
	Warnings   []string                              `json:"warnings,omitempty"`
}

// AddressReputation is the resolved status and every underlying record.
type AddressReputation struct {
	Status  models.ReputationStatus   `json:"status"`
	Sources []string                  `json:"sources"`
	Records []models.ReputationRecord `json:"records"`
}

// handleAddress serves GET /api/v1/address/{address}?chainId=: on-chain facts
// (when an RPC endpoint is configured), reputation, and analyses involving
// the address known to this server.
func (s *Server) handleAddress(w http.ResponseWriter, r *http.Request) {
	e := s.engineOr503(w, r)
	if e == nil {
		return
	}
	addr, err := models.ParseAddress(r.PathValue("address"))
	if err != nil {
		writeError(w, r, txerrors.Invalid(txerrors.FieldError{Field: "address", Message: err.Error()}))
		return
	}
	chainID, err := parseChainParam(r, true)
	if err != nil {
		writeError(w, r, err)
		return
	}
	page, err := parsePage(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	out := AddressReport{Address: addr.Hex(), ChainID: *chainID, Reputation: AddressReputation{Status: models.ReputationUnknown, Sources: []string{}, Records: []models.ReputationRecord{}}}

	cs, _ := e.resolveChain(r.Context(), *chainID, "")
	if cs.inspector != nil {
		info, err := cs.inspector.Inspect(r.Context(), *chainID, addr, 0)
		if err != nil {
			if txerrors.KindOf(err) == txerrors.KindUnsupported {
				writeError(w, r, err)
				return
			}
			out.Warnings = append(out.Warnings, "on-chain contract facts are temporarily unavailable")
		} else {
			out.Contract = info
		}
	} else {
		out.Warnings = append(out.Warnings, "no RPC endpoint is configured for this chain: on-chain facts unavailable")
	}

	if agg := e.Analyzer.Reputation(); agg != nil {
		recs, warns := agg.LookupAll(r.Context(), *chainID, []common.Address{addr})
		out.Reputation.Sources = agg.Sources()
		if rs := recs[addr]; len(rs) > 0 {
			out.Reputation.Records = rs
			out.Reputation.Status = reputation.Effective(rs)
		}
		out.Warnings = append(out.Warnings, warns...)
	}

	if e.Store != nil {
		items, total, err := e.Store.ListReports(r.Context(), interfaces.AnalysisFilter{ChainID: chainID, Address: &addr}, page)
		if err != nil {
			out.Warnings = append(out.Warnings, "analysis history is temporarily unavailable")
		} else {
			out.History = &PageResponse[models.AnalysisSummary]{Items: items, Total: total, Limit: page.Limit, Offset: page.Offset}
		}
	}
	writeJSON(w, http.StatusOK, out)
}
