package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/txshield/txshield/internal/analyzer"
	"github.com/txshield/txshield/internal/config"
	"github.com/txshield/txshield/internal/decoder"
	"github.com/txshield/txshield/internal/evm"
	"github.com/txshield/txshield/internal/metrics"
	"github.com/txshield/txshield/internal/security/reputation"
	"github.com/txshield/txshield/pkg/interfaces"
	"github.com/txshield/txshield/pkg/models"
	"github.com/txshield/txshield/pkg/txerrors"
)

// memStore is an in-memory AnalysisStore.
type memStore struct {
	mu      sync.Mutex
	reports []models.RiskReport
	failErr error
}

func (m *memStore) SaveReport(_ context.Context, r *models.RiskReport, _ *models.Transaction) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failErr != nil {
		return m.failErr
	}
	m.reports = append(m.reports, *r)
	return nil
}

func (m *memStore) GetReport(_ context.Context, id string) (*models.RiskReport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.reports {
		if r.ID == id {
			return &r, nil
		}
	}
	return nil, txerrors.New(txerrors.KindNotFound, "analysis_not_found", "analysis not found")
}

func (m *memStore) ListReports(_ context.Context, f interfaces.AnalysisFilter, p interfaces.Page) ([]models.AnalysisSummary, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []models.AnalysisSummary{}
	for _, r := range m.reports {
		if f.MinScore != nil && r.Risk.Score < *f.MinScore {
			continue
		}
		out = append(out, models.AnalysisSummary{ID: r.ID, Score: r.Risk.Score, Category: r.Risk.Category, ChainID: r.Transaction.ChainID})
	}
	total := int64(len(out))
	if p.Offset < len(out) {
		out = out[p.Offset:]
	} else {
		out = out[:0]
	}
	if len(out) > p.Limit {
		out = out[:p.Limit]
	}
	return out, total, nil
}

func (m *memStore) Stats(context.Context, *time.Time) (*interfaces.AnalysisStats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return &interfaces.AnalysisStats{Total: int64(len(m.reports)), ByCategory: map[models.RiskCategory]int64{}, ByChain: map[uint64]int64{}}, nil
}

func (m *memStore) PurgeExpired(context.Context, time.Time) (int64, error) { return 0, nil }

const (
	sender = "0x1111111111111111111111111111111111111111"
	usdc   = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
	// approve(0xdead...0001, max)
	approveMax = "0x095ea7b3000000000000000000000000dead000000000000000000000000000000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

func engineServer(t *testing.T, store interfaces.AnalysisStore, mutate func(*config.Config, *Engine)) *Server {
	t.Helper()
	list, err := reputation.ParseList(strings.NewReader(`{"name":"t","entries":[{"address":"0xdead000000000000000000000000000000000001","status":"blocked","reason":"test"}]}`), "t")
	if err != nil {
		t.Fatal(err)
	}
	a, err := analyzer.Build(analyzer.BuildOptions{ExtraReputation: []interfaces.ReputationProvider{list}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.API.RateLimitRPS = 0
	e := &Engine{Analyzer: a}
	if store != nil {
		e.Store = store
	}
	if mutate != nil {
		mutate(&cfg, e)
	}
	return New(Deps{Config: cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Metrics: metrics.New("t", "t"), Engine: e})
}

func post(t *testing.T, s http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	switch b := body.(type) {
	case string:
		buf.WriteString(b)
	default:
		_ = json.NewEncoder(&buf).Encode(b)
	}
	return do(t, s, "POST", path, &buf, map[string]string{"Content-Type": "application/json"})
}

func errBody(t *testing.T, rr *httptest.ResponseRecorder) ErrorDetail {
	t.Helper()
	var eb ErrorBody
	if err := json.Unmarshal(rr.Body.Bytes(), &eb); err != nil {
		t.Fatalf("not an error body: %s", rr.Body)
	}
	return eb.Error
}

func TestAnalyzeEndpoint(t *testing.T) {
	store := &memStore{}
	s := engineServer(t, store, nil)
	rr := post(t, s, "/api/v1/analyze", map[string]any{"chainId": 1, "from": sender, "to": usdc, "data": approveMax})
	if rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	var rep models.RiskReport
	if err := json.Unmarshal(rr.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Risk.Category != models.RiskCritical || rep.RequestID == "" || len(store.reports) != 1 {
		t.Fatalf("risk=%+v requestId=%q stored=%d", rep.Risk, rep.RequestID, len(store.reports))
	}
	if !strings.Contains(strings.Join(rep.Warnings, ";"), "offline analysis only") {
		t.Fatalf("unconfigured chain must be stated: %v", rep.Warnings)
	}

	// persist=false
	rr = post(t, s, "/api/v1/analyze", map[string]any{"chainId": 1, "from": sender, "to": usdc, "data": approveMax, "persist": false})
	if rr.Code != 200 || len(store.reports) != 1 {
		t.Fatalf("persist=false stored anyway (%d)", len(store.reports))
	}

	// Store failure degrades to a warning.
	store.failErr = errors.New("db down")
	rr = post(t, s, "/api/v1/analyze", map[string]any{"chainId": 1, "from": sender, "to": usdc, "data": approveMax})
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "could not be stored") {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
}

func TestAnalyzeValidation(t *testing.T) {
	s := engineServer(t, nil, nil)
	cases := map[string]struct {
		body  any
		code  int
		field string
	}{
		"missing from":   {map[string]any{"chainId": 1, "to": usdc}, 400, "from"},
		"bad address":    {map[string]any{"chainId": 1, "from": "0x12", "to": usdc}, 400, "from"},
		"bad data":       {map[string]any{"chainId": 1, "from": sender, "to": usdc, "data": "0xzz"}, 400, "data"},
		"unknown field":  {`{"chainId":1,"from":"` + sender + `","maxFeePerGass":"1"}`, 400, ""},
		"malformed json": {`{"chainId":`, 400, ""},
		"bad abi":        {map[string]any{"chainId": 1, "from": sender, "to": usdc, "data": approveMax, "abi": "x"}, 400, ""},
		"user rpc off":   {map[string]any{"chainId": 1, "from": sender, "to": usdc, "rpcUrl": "https://8.8.8.8"}, 400, "rpcUrl"},
	}
	for name, c := range cases {
		rr := post(t, s, "/api/v1/analyze", c.body)
		if rr.Code != c.code {
			t.Errorf("%s: code %d %s", name, rr.Code, rr.Body)
			continue
		}
		e := errBody(t, rr)
		if c.field != "" && (len(e.Fields) == 0 || e.Fields[0].Field != c.field) {
			t.Errorf("%s: fields %+v", name, e.Fields)
		}
	}
	rr := do(t, s, "POST", "/api/v1/analyze", strings.NewReader("{}"), map[string]string{"Content-Type": "text/plain"})
	if rr.Code != 400 {
		t.Fatalf("content type: %d", rr.Code)
	}
}

func TestUserRPCGuard(t *testing.T) {
	s := engineServer(t, nil, func(_ *config.Config, e *Engine) { e.AllowUserRPC = true })
	for _, u := range []string{"http://8.8.8.8", "https://127.0.0.1:8545", "https://169.254.169.254", "https://localhost"} {
		rr := post(t, s, "/api/v1/analyze", map[string]any{"chainId": 1, "from": sender, "to": usdc, "rpcUrl": u})
		if rr.Code != 400 || errBody(t, rr).Fields[0].Field != "rpcUrl" {
			t.Errorf("%s: %d %s", u, rr.Code, rr.Body)
		}
	}
}

func TestSimulateUnavailable(t *testing.T) {
	s := engineServer(t, nil, nil)
	rr := post(t, s, "/api/v1/simulate", map[string]any{"chainId": 1, "from": sender, "to": usdc})
	if rr.Code != 422 || errBody(t, rr).Code != "simulation_unavailable" {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
}

func TestApprovalsEndpoint(t *testing.T) {
	s := engineServer(t, nil, nil)
	rr := post(t, s, "/api/v1/approvals/analyze", map[string]any{"chainId": 1, "from": sender, "to": usdc, "data": approveMax})
	if rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	var out ApprovalAnalysis
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Approvals) != 1 || !out.Approvals[0].Unlimited || out.Approvals[0].Current != nil {
		t.Fatalf("approvals %+v", out.Approvals)
	}
	for _, f := range out.Findings {
		if f.Category != models.CategoryApproval && f.RuleID != "TXS-PATTERN-002" {
			t.Fatalf("non-approval finding leaked: %s", f.RuleID)
		}
	}
	if out.Risk.Score < 80 || len(out.Recommendations) == 0 || out.Disclaimer == "" {
		t.Fatalf("risk %+v recs %v", out.Risk, out.Recommendations)
	}

	rr = post(t, s, "/api/v1/approvals/analyze", map[string]any{"chainId": 1, "from": sender, "to": usdc, "data": "0xa9059cbb00000000000000000000000022222222222222222222222222222222222222220000000000000000000000000000000000000000000000000000000000000001"})
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || len(out.Approvals) != 0 || out.Risk.Score != 0 {
		t.Fatalf("no-approval tx: %s", rr.Body)
	}
}

func TestHistoryEndpoints(t *testing.T) {
	store := &memStore{}
	s := engineServer(t, store, nil)
	for i := 0; i < 3; i++ {
		post(t, s, "/api/v1/analyze", map[string]any{"chainId": 1, "from": sender, "to": usdc, "data": approveMax})
	}
	rr := do(t, s, "GET", "/api/v1/analyses?limit=2&offset=1", nil, nil)
	var page PageResponse[models.AnalysisSummary]
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &page) != nil || page.Total != 3 || len(page.Items) != 2 || page.Limit != 2 || page.Offset != 1 {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	for _, q := range []string{"limit=0", "limit=101", "offset=-1", "minScore=500", "chainId=abc", "since=yesterday", "address=0x12"} {
		if rr := do(t, s, "GET", "/api/v1/analyses?"+q, nil, nil); rr.Code != 400 {
			t.Errorf("%s: %d", q, rr.Code)
		}
	}
	id := store.reports[0].ID
	if rr := do(t, s, "GET", "/api/v1/analyses/"+id, nil, nil); rr.Code != 200 {
		t.Fatalf("get: %d", rr.Code)
	}
	if rr := do(t, s, "GET", "/api/v1/analyses/00000000-0000-4000-8000-000000000000", nil, nil); rr.Code != 404 {
		t.Fatalf("missing analysis: %d", rr.Code)
	}
	if rr := do(t, s, "GET", "/api/v1/stats", nil, nil); rr.Code != 200 || !strings.Contains(rr.Body.String(), `"total":3`) {
		t.Fatalf("stats: %s", rr.Body)
	}
}

func TestPersistenceDisabled(t *testing.T) {
	s := engineServer(t, nil, nil)
	for _, p := range []string{"/api/v1/analyses", "/api/v1/analyses/123", "/api/v1/stats"} {
		rr := do(t, s, "GET", p, nil, nil)
		if rr.Code != 503 || errBody(t, rr).Code != "persistence_disabled" {
			t.Errorf("%s: %d %s", p, rr.Code, rr.Body)
		}
	}
}

func TestAddressEndpoint(t *testing.T) {
	s := engineServer(t, &memStore{}, nil)
	if rr := do(t, s, "GET", "/api/v1/address/0xdead000000000000000000000000000000000001", nil, nil); rr.Code != 400 {
		t.Fatalf("missing chainId: %d", rr.Code)
	}
	if rr := do(t, s, "GET", "/api/v1/address/0x12?chainId=1", nil, nil); rr.Code != 400 {
		t.Fatalf("bad address: %d", rr.Code)
	}
	rr := do(t, s, "GET", "/api/v1/address/0xdead000000000000000000000000000000000001?chainId=1", nil, nil)
	var ar AddressReport
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &ar) != nil {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	if ar.Reputation.Status != models.ReputationBlocked || len(ar.Reputation.Records) != 1 || ar.History == nil || ar.Contract != nil || len(ar.Warnings) == 0 {
		t.Fatalf("%+v", ar)
	}
}

func TestEngineMissingAndMethods(t *testing.T) {
	s := newTestServer(t, nil)
	if rr := post(t, s, "/api/v1/analyze", map[string]any{}); rr.Code != 503 {
		t.Fatalf("engine missing: %d", rr.Code)
	}
	if rr := do(t, s, "GET", "/api/v1/analyze", nil, nil); rr.Code != 405 {
		t.Fatalf("GET analyze: %d", rr.Code)
	}
	if rr := do(t, s, "POST", "/api/v1/analyses/abc", nil, nil); rr.Code != 405 {
		t.Fatalf("POST analyses/{id}: %d", rr.Code)
	}
	if rr := do(t, s, "GET", "/api/v1/analyses/abc/def", nil, nil); rr.Code != 404 {
		t.Fatalf("nested unknown path: %d", rr.Code)
	}
}

func TestDecodeEndpoint(t *testing.T) {
	s := engineServer(t, nil, nil)
	rr := post(t, s, "/api/v1/decode", map[string]any{"data": approveMax})
	var c models.DecodedCall
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &c) != nil || c.Method != "approve" || c.Target != "" || c.Kind != models.CallContract {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	rr = post(t, s, "/api/v1/decode", map[string]any{"data": approveMax, "to": usdc})
	if json.Unmarshal(rr.Body.Bytes(), &c) != nil || c.Target != usdc {
		t.Fatalf("target: %s", rr.Body)
	}
	for name, body := range map[string]any{
		"missing data":  map[string]any{"to": usdc},
		"bad hex":       map[string]any{"data": "0xzz"},
		"unknown field": `{"data":"0x","from":"x"}`,
		"bad abi":       map[string]any{"data": approveMax, "to": usdc, "abi": "x"},
	} {
		if rr := post(t, s, "/api/v1/decode", body); rr.Code != 400 {
			t.Errorf("%s: %d %s", name, rr.Code, rr.Body)
		}
	}
}

func TestTransactionEndpointValidation(t *testing.T) {
	s := engineServer(t, nil, nil)
	hash := "0x" + strings.Repeat("ab", 32)
	if rr := do(t, s, "GET", "/api/v1/transactions/0x1234?chainId=1", nil, nil); rr.Code != 400 {
		t.Fatalf("bad hash: %d", rr.Code)
	}
	if rr := do(t, s, "GET", "/api/v1/transactions/"+hash, nil, nil); rr.Code != 400 {
		t.Fatalf("missing chainId: %d", rr.Code)
	}
	if rr := do(t, s, "GET", "/api/v1/transactions/"+hash+"?chainId=1", nil, nil); rr.Code != 422 {
		t.Fatalf("no RPC configured: %d", rr.Code)
	}
}

// One approvals request must not fan out into an unbounded number of
// upstream RPC reads (nested multicalls can carry hundreds of approvals).
func TestApprovalsCapsCurrentStateReads(t *testing.T) {
	var calls atomic.Int64
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		result := `"0x0000000000000000000000000000000000000000000000000000000000000000"`
		switch req.Method {
		case "eth_chainId":
			result = `"0x1"`
		case "eth_blockNumber":
			result = `"0x10"`
		case "eth_getCode":
			result = `"0x"`
		case "eth_call":
			calls.Add(1)
		}
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(req.ID)+`,"result":`+result+`}`)
	}))
	defer node.Close()
	s := engineServer(t, nil, func(_ *config.Config, e *Engine) {
		e.Chains = evm.NewRegistry(map[uint64]string{1: node.URL}, evm.Options{})
	})

	approve := approveMax[2:]
	var inner []string
	for range 30 {
		inner = append(inner, approve)
	}
	data := multicallHex(t, inner)
	rr := post(t, s, "/api/v1/approvals/analyze", map[string]any{"chainId": 1, "from": sender, "to": usdc, "data": data, "simulate": false})
	if rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	var out ApprovalAnalysis
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Approvals) != 30 {
		t.Fatalf("got %d approvals", len(out.Approvals))
	}
	withState := 0
	for _, a := range out.Approvals {
		if a.Current != nil {
			withState++
		}
	}
	if withState != maxCurrentStateReads || !strings.Contains(strings.Join(out.Warnings, " "), "first 20 of 30") {
		t.Fatalf("withState=%d warnings=%q", withState, out.Warnings)
	}
	if n := calls.Load(); n > maxCurrentStateReads {
		t.Fatalf("%d eth_call reads for one request", n)
	}
}

func multicallHex(t *testing.T, calls []string) string {
	t.Helper()
	bs := make([][]byte, len(calls))
	for i, c := range calls {
		b, err := hex.DecodeString(c)
		if err != nil {
			t.Fatal(err)
		}
		bs[i] = b
	}
	m, err := decoder.ParseSignature("multicall(bytes[])")
	if err != nil {
		t.Fatal(err)
	}
	enc, err := m.Inputs.Pack(bs)
	if err != nil {
		t.Fatal(err)
	}
	return "0x" + hex.EncodeToString(append(append([]byte{}, m.ID...), enc...))
}

// Reports built from a caller-controlled RPC node must not enter the shared
// history, where they would look like operator-verified facts.
func TestUserRPCAnalysesAreNotPersisted(t *testing.T) {
	store := &memStore{}
	s := engineServer(t, store, nil)
	report := &models.RiskReport{}
	s.persist(context.Background(), report, &models.Transaction{}, nil, chainSet{userRPC: true})
	if len(store.reports) != 0 || !strings.Contains(strings.Join(report.Warnings, " "), "not stored") {
		t.Fatalf("stored=%d warnings=%q", len(store.reports), report.Warnings)
	}
	s.persist(context.Background(), &models.RiskReport{}, &models.Transaction{}, nil, chainSet{})
	if len(store.reports) != 1 {
		t.Fatal("operator-RPC analysis not stored")
	}
}
