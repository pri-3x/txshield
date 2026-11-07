//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pri-3x/txshield/internal/analyzer"
	"github.com/pri-3x/txshield/internal/api"
	"github.com/pri-3x/txshield/internal/config"
	"github.com/pri-3x/txshield/internal/evm"
	"github.com/pri-3x/txshield/internal/metrics"
	"github.com/pri-3x/txshield/internal/security/reputation"
	"github.com/pri-3x/txshield/internal/storage"
	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
	"github.com/pri-3x/txshield/pkg/txerrors"
)

// schemaPool applies the migrations in an isolated schema and returns a pool
// bound to it.
func schemaPool(t *testing.T, schema string) *pgxpool.Pool {
	t.Helper()
	conn := connect(t)
	ctx := context.Background()
	if _, err := conn.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE; CREATE SCHEMA `+schema+`; SET search_path TO `+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`) })
	execFile(t, conn, "000001_init.up.sql")
	cfg, err := pgxpool.ParseConfig(os.Getenv("TXSHIELD_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func offlineReport(t *testing.T, x *models.Transaction) *models.RiskReport {
	t.Helper()
	a, err := analyzer.Build(analyzer.BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	r, err := a.Analyze(context.Background(), analyzer.Request{Tx: x})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAnalysisStorePrivacyAndQueries(t *testing.T) {
	pool := schemaPool(t, "txshield_store")
	ctx := context.Background()
	sender := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	token := common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	spender := common.HexToAddress("0xdead000000000000000000000000000000000001")
	maxU := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	x := &models.Transaction{ChainID: 1, From: sender, To: &token, Value: new(big.Int), Data: cd("approve(address,uint256)", spender, maxU)}

	// Defaults: no sender, no calldata.
	private := storage.NewAnalysisStore(pool, storage.StoreOptions{Retention: time.Hour})
	r1 := offlineReport(t, x)
	if err := private.SaveReport(ctx, r1, x); err != nil {
		t.Fatal(err)
	}
	var doc string
	var from, calldata []byte
	if err := pool.QueryRow(ctx, `SELECT report::text, from_address, calldata FROM analyzed_transactions WHERE id = $1::uuid`, r1.ID).Scan(&doc, &from, &calldata); err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(sender.Hex()[2:])
	if from != nil || calldata != nil || strings.Contains(strings.ToLower(doc), lower) {
		t.Fatalf("sender or calldata persisted: from=%x calldata=%x senderInDoc=%v", from, calldata, strings.Contains(strings.ToLower(doc), lower))
	}
	if !strings.Contains(doc, "[redacted-sender]") || strings.Contains(doc, `"params"`) || strings.Contains(doc, `"rawData"`) {
		t.Fatalf("stored doc not reduced: %.400s", doc)
	}
	var findings, history int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM security_findings`).Scan(&findings)
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM analysis_history WHERE role = 'sender'`).Scan(&history)
	if findings != len(r1.Findings) || history != 0 {
		t.Fatalf("findings rows %d (want %d), sender ledger rows %d (want 0)", findings, len(r1.Findings), history)
	}
	var fdocs string
	_ = pool.QueryRow(ctx, `SELECT string_agg(finding::text, ' ') FROM security_findings`).Scan(&fdocs)
	if strings.Contains(strings.ToLower(fdocs), lower) {
		t.Fatal("sender leaked into stored findings")
	}

	got, err := private.GetReport(ctx, r1.ID)
	if err != nil || got.Risk.Score != r1.Risk.Score || got.Transaction.From != "[redacted-sender]" {
		t.Fatalf("get: %v %+v", err, got.Transaction)
	}
	if _, err := private.GetReport(ctx, "not-a-uuid"); txerrors.KindOf(err) != txerrors.KindNotFound {
		t.Fatalf("bad id: %v", err)
	}

	// Opt-in storage keeps sender and calldata.
	full := storage.NewAnalysisStore(pool, storage.StoreOptions{StoreSender: true, StoreCalldata: true})
	r2 := offlineReport(t, x)
	if err := full.SaveReport(ctx, r2, x); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT from_address, calldata FROM analyzed_transactions WHERE id = $1::uuid`, r2.ID).Scan(&from, &calldata); err != nil || len(from) != 20 || len(calldata) != len(x.Data) {
		t.Fatalf("opt-in not stored: %v %x %d", err, from, len(calldata))
	}

	// Queries.
	chain := uint64(1)
	items, total, err := full.ListReports(ctx, interfaces.AnalysisFilter{ChainID: &chain, Address: &spender}, interfaces.Page{Limit: 10})
	if err != nil || total != 2 || len(items) != 2 || items[0].ID != r2.ID || items[0].From != sender.Hex() || items[1].From != "" {
		t.Fatalf("list by spender: %v total=%d %+v", err, total, items)
	}
	min := 101
	if _, total, _ := full.ListReports(ctx, interfaces.AnalysisFilter{MinScore: &min}, interfaces.Page{Limit: 10}); total != 0 {
		t.Fatal("minScore filter")
	}
	stats, err := full.Stats(ctx, nil)
	if err != nil || stats.Total != 2 || stats.ByChain[1] != 2 || stats.HighRisk != 0 && stats.HighRisk > 2 {
		t.Fatalf("stats %+v %v", stats, err)
	}

	// Retention: r1 expires in an hour; purge as of two hours from now.
	n, err := private.PurgeExpired(ctx, time.Now().Add(2*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("purge: %d %v", n, err)
	}
	if _, err := private.GetReport(ctx, r1.ID); txerrors.KindOf(err) != txerrors.KindNotFound {
		t.Fatal("purged report still readable")
	}
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM security_findings`).Scan(&findings)
	if findings != len(r2.Findings) {
		t.Fatalf("cascade left %d findings", findings)
	}
}

// apiServer builds the full HTTP API against the fixture chain and Postgres.
func apiServer(t *testing.T, w *world) (*httptest.Server, interfaces.AnalysisStore) {
	t.Helper()
	pool := schemaPool(t, "txshield_api")
	reg := w.registry()
	sim := newAnvil(t, w)
	insp := evm.NewInspector(reg, 0)
	list, err := reputation.ParseList(strings.NewReader(`{"name":"test","entries":[{"address":"`+strings.ToLower(w.drainer.Hex())+`","status":"blocked","reason":"fixture drainer"}]}`), "t")
	if err != nil {
		t.Fatal(err)
	}
	a, err := analyzer.Build(analyzer.BuildOptions{Chains: reg, Inspector: insp, Simulator: sim,
		ExtraReputation: []interfaces.ReputationProvider{list, reputation.NewPostgresProvider(pool)}})
	if err != nil {
		t.Fatal(err)
	}
	store := storage.NewAnalysisStore(pool, storage.StoreOptions{Retention: time.Hour})
	cfg := config.Defaults()
	cfg.Chains.RPCURLs = map[uint64]string{chainID: w.url}
	cfg.API.RateLimitRPS = 0
	srv := api.New(api.Deps{Config: cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Metrics: metrics.New("t", "t"),
		Engine: &api.Engine{Analyzer: a, Chains: reg, Inspector: insp, Simulator: sim, Store: store}})
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts, store
}

func postJSON(t *testing.T, url string, body any, out any) int {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b)) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("decode %s: %v\n%s", url, err, raw)
		}
	}
	return resp.StatusCode
}

func getJSON(t *testing.T, url string, out any) int {
	t.Helper()
	resp, err := http.Get(url) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func txBody(from, to common.Address, value *big.Int, data []byte) map[string]any {
	return map[string]any{"chainId": chainID, "from": from.Hex(), "to": to.Hex(), "value": value.String(), "data": hexutil.Encode(data)}
}

func TestAPIEndToEnd(t *testing.T) {
	w := getWorld(t)
	ts, _ := apiServer(t, w)

	var rep models.RiskReport
	if code := postJSON(t, ts.URL+"/api/v1/analyze", txBody(victim, w.drainer, oneEther, cd("claim()")), &rep); code != 200 {
		t.Fatalf("analyze: %d", code)
	}
	if rep.Risk.Category != models.RiskCritical || rep.Simulation.Backend != "anvil" || rep.Risk.Confidence != models.ConfidenceHigh {
		t.Fatalf("report %+v sim %s", rep.Risk, rep.Simulation.Backend)
	}
	fired := map[string]bool{}
	for _, f := range rep.Findings {
		fired[f.RuleID] = true
	}
	if !fired["TXS-INTERACT-001"] || !fired["TXS-VALUE-001"] {
		t.Fatalf("expected blocklist and value findings: %v", fired)
	}

	// Stored and listed.
	var page api.PageResponse[models.AnalysisSummary]
	if code := getJSON(t, ts.URL+"/api/v1/analyses?minScore=80", &page); code != 200 || page.Total != 1 || page.Items[0].ID != rep.ID || page.Items[0].From != "" {
		t.Fatalf("list: %d %+v", code, page)
	}
	var stored models.RiskReport
	if code := getJSON(t, ts.URL+"/api/v1/analyses/"+rep.ID, &stored); code != 200 || stored.Risk.Score != rep.Risk.Score {
		t.Fatalf("get: %d", code)
	}

	// Address inspector: contract facts, blocklist, history.
	var ar api.AddressReport
	if code := getJSON(t, ts.URL+"/api/v1/address/"+w.drainer.Hex()+"?chainId=31337", &ar); code != 200 {
		t.Fatalf("address: %d", code)
	}
	if ar.Contract == nil || !ar.Contract.IsContract || ar.Reputation.Status != models.ReputationBlocked || ar.History == nil || ar.History.Total != 1 {
		t.Fatalf("address report %+v", ar)
	}
	if code := getJSON(t, ts.URL+"/api/v1/address/"+w.token.Hex()+"?chainId=31337", &ar); code != 200 || len(ar.Contract.Standards) != 1 || ar.Contract.Standards[0] != "erc20" {
		t.Fatalf("token address report %+v", ar.Contract)
	}

	// Approvals: the victim already granted the drainer an unlimited allowance.
	maxU := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	var appr api.ApprovalAnalysis
	if code := postJSON(t, ts.URL+"/api/v1/approvals/analyze", txBody(victim, w.token, new(big.Int), cd("approve(address,uint256)", w.drainer, maxU)), &appr); code != 200 {
		t.Fatalf("approvals: %d", code)
	}
	if len(appr.Approvals) != 1 || appr.Approvals[0].Kind != models.ApprovalERC20 || appr.Approvals[0].Current == nil || !appr.Approvals[0].Current.Unlimited {
		t.Fatalf("approvals %+v", appr.Approvals)
	}
	if appr.Risk.Category != models.RiskCritical {
		t.Fatalf("approval risk %+v", appr.Risk)
	}

	// Simulation endpoint: revert is a 200 with status reverted.
	var sim models.SimulationResult
	if code := postJSON(t, ts.URL+"/api/v1/simulate", txBody(victim, w.reverter, new(big.Int), cd("swap(uint256)", big.NewInt(1))), &sim); code != 200 || sim.Status != models.SimReverted || !strings.Contains(sim.RevertReason, "EXPIRED") {
		t.Fatalf("simulate: %d %+v", code, sim)
	}

	// Chain without an RPC endpoint: offline analysis, not an error.
	body := txBody(victim, w.token, new(big.Int), cd("transfer(address,uint256)", attacker, big.NewInt(1)))
	body["chainId"] = 1
	if code := postJSON(t, ts.URL+"/api/v1/analyze", body, &rep); code != 200 || rep.Simulation.Status != models.SimNotRun || !strings.Contains(strings.Join(rep.Warnings, ";"), "offline") {
		t.Fatalf("unconfigured chain: %d %+v", code, rep.Warnings)
	}
	if code := postJSON(t, ts.URL+"/api/v1/simulate", body, nil); code != 422 {
		t.Fatalf("simulate unconfigured chain: %d", code)
	}

	// Stats.
	var st interfaces.AnalysisStats
	// Two /analyze calls were persisted (approvals and simulate never persist).
	if code := getJSON(t, ts.URL+"/api/v1/stats", &st); code != 200 || st.Total != 2 || st.ByChain[31337] != 1 || st.ByChain[1] != 1 || st.HighRisk != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestCLIApprovalCheck(t *testing.T) {
	w := getWorld(t)
	bin := filepath.Join(t.TempDir(), "txshield")
	if out, err := exec.CommandContext(context.Background(), "go", "build", "-o", bin, filepath.Join(repoRoot(), "cmd", "txshield")).CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	run := func(args ...string) (int, string) {
		out, err := exec.CommandContext(context.Background(), bin, args...).CombinedOutput()
		if ee, ok := err.(*exec.ExitError); ok { //nolint:errorlint // direct ExitError from CombinedOutput
			return ee.ExitCode(), string(out)
		}
		return 0, string(out)
	}
	base := []string{"approval-check", "--chain", "31337", "--rpc", w.url, "--owner", victim.Hex()}

	code, out := run(append(base, "--token", w.token.Hex(), "--spender", w.drainer.Hex())...)
	if code != 3 || !strings.Contains(out, "UNLIMITED") {
		t.Fatalf("unlimited allowance: %d %s", code, out)
	}
	code, out = run(append(base, "--token", w.nft.Hex(), "--spender", w.drainer.Hex(), "--json")...)
	var res struct {
		Risky       bool `json:"risky"`
		Permissions []struct {
			Kind   string `json:"kind"`
			Active bool   `json:"active"`
		} `json:"permissions"`
	}
	if code != 3 || json.Unmarshal([]byte(out), &res) != nil || !res.Risky || res.Permissions[0].Kind != "operator_approval" || !res.Permissions[0].Active {
		t.Fatalf("operator approval: %d %s", code, out)
	}
	code, out = run(append(base, "--token", w.token.Hex(), "--spender", attacker.Hex())...)
	if code != 0 || !strings.Contains(out, "no active permission") {
		t.Fatalf("no approval: %d %s", code, out)
	}
	if code, _ := run(append(base, "--token", "0x12", "--spender", attacker.Hex())...); code != 2 {
		t.Fatalf("bad token: %d", code)
	}
}

func TestTransactionLookupAndReplay(t *testing.T) {
	w := getWorld(t)
	ts, _ := apiServer(t, w)
	var blk struct {
		Number       hexutil.Uint64 `json:"number"`
		Transactions []common.Hash  `json:"transactions"`
	}
	if err := w.node.Call(context.Background(), &blk, "eth_getBlockByNumber", "latest", false); err != nil || len(blk.Transactions) == 0 {
		t.Fatalf("latest block: %v %+v", err, blk)
	}
	hash := blk.Transactions[0].Hex()

	var lk api.TransactionLookup
	if code := getJSON(t, ts.URL+"/api/v1/transactions/"+hash+"?chainId=31337", &lk); code != 200 {
		t.Fatalf("lookup: %d", code)
	}
	if lk.BlockNumber == nil || *lk.BlockNumber != uint64(blk.Number) || lk.Transaction.Block != fmt.Sprint(uint64(blk.Number)-1) ||
		lk.Transaction.From != deployer.Hex() || lk.Transaction.Data == "" || len(lk.Notes) == 0 {
		t.Fatalf("lookup %+v", lk)
	}
	// The lookup result is directly usable as an /analyze request.
	var rep models.RiskReport
	if code := postJSON(t, ts.URL+"/api/v1/analyze", lk.Transaction, &rep); code != 200 || rep.Simulation.BlockNumber != uint64(blk.Number)-1 {
		t.Fatalf("replay analyze: %d sim block %d", code, rep.Simulation.BlockNumber)
	}
	if code := getJSON(t, ts.URL+"/api/v1/transactions/0x"+strings.Repeat("00", 32)+"?chainId=31337", nil); code != 404 {
		t.Fatalf("unknown hash: %d", code)
	}
}
