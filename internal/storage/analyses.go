package storage

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/txshield/txshield/internal/security/core"
	"github.com/txshield/txshield/pkg/interfaces"
	"github.com/txshield/txshield/pkg/models"
	"github.com/txshield/txshield/pkg/txerrors"
)

// StoreOptions controls what is persisted.
type StoreOptions struct {
	// StoreSender keeps the sender address. When false it is removed from
	// every column and replaced in the stored report text.
	StoreSender bool
	// StoreCalldata keeps raw calldata, decoded parameters, traces, and logs.
	// When false only the selector, a keyed calldata hash (see
	// calldataHash), decoded method names, findings, approvals, and asset
	// movements are stored.
	StoreCalldata bool
	// Retention sets expires_at; 0 keeps analyses forever.
	Retention time.Duration
}

// AnalysisStore implements interfaces.AnalysisStore on PostgreSQL.
type AnalysisStore struct {
	pool    *pgxpool.Pool
	opts    StoreOptions
	now     func() time.Time
	hashKey []byte // per-process HMAC key for calldata_hash
}

var _ interfaces.AnalysisStore = (*AnalysisStore)(nil)

// NewAnalysisStore returns a store using pool.
func NewAnalysisStore(pool *pgxpool.Pool, opts StoreOptions) *AnalysisStore {
	key := make([]byte, 32)
	_, _ = rand.Read(key) // never fails (crypto/rand panics on failure)
	return &AnalysisStore{pool: pool, opts: opts, now: time.Now, hashKey: key}
}

// calldataHash is the value of the calldata_hash column. With calldata
// storage enabled it is keccak256(calldata). Otherwise it is an HMAC under a
// random per-process key: a plain hash of mined calldata could be matched
// to the public on-chain transaction (revealing the sender) and lets anyone
// confirm guesses of low-entropy calldata such as approve(spender, max).
func (s *AnalysisStore) calldataHash(data []byte) []byte {
	if s.opts.StoreCalldata {
		return crypto.Keccak256(data)
	}
	m := hmac.New(sha256.New, s.hashKey)
	m.Write(data)
	return m.Sum(nil)
}

const redactedSender = "[redacted-sender]"

// storedCopy returns the JSON that is persisted, applying privacy options.
func (s *AnalysisStore) storedCopy(r *models.RiskReport, sender common.Address) ([]byte, error) {
	cp := *r
	if !s.opts.StoreCalldata {
		if r.Decoded != nil {
			d := stripCall(*r.Decoded)
			cp.Decoded = &d
		}
		if r.Simulation != nil {
			sim := *r.Simulation
			sim.Trace, sim.Logs, sim.ReturnData = nil, nil, ""
			cp.Simulation = &sim
		}
		cp.Warnings = append(append([]string{}, r.Warnings...), "stored copy omits calldata, decoded parameters, traces, and logs (TXSHIELD_STORE_CALLDATA=false)")
	}
	b, err := json.Marshal(&cp)
	if err != nil {
		return nil, err
	}
	if !s.opts.StoreSender {
		b = redactAddress(b, sender)
	}
	return b, nil
}

// stripCall keeps the shape of the call tree (kinds, methods, targets) and
// drops argument values and raw data.
func stripCall(c models.DecodedCall) models.DecodedCall {
	c.Params, c.RawData = nil, ""
	if len(c.Children) > 0 {
		kids := make([]models.DecodedCall, len(c.Children))
		for i := range c.Children {
			kids[i] = stripCall(c.Children[i])
		}
		c.Children = kids
	}
	return c
}

// redactAddress replaces every occurrence of addr's 40 hex digits (any case,
// with or without 0x, including 32-byte left-padded topics) in JSON text.
func redactAddress(b []byte, addr common.Address) []byte {
	if addr == (common.Address{}) {
		return b
	}
	body := strings.TrimPrefix(strings.ToLower(addr.Hex()), "0x")
	re := regexp.MustCompile(`(?i)(0x)?(0{24})?` + body)
	return re.ReplaceAllLiteral(b, []byte(redactedSender))
}

// SaveReport persists a report atomically: analysis row, simulation result,
// findings, and the address ledger used by the Address Inspector.
func (s *AnalysisStore) SaveReport(ctx context.Context, r *models.RiskReport, tx *models.Transaction) error {
	var id pgtype.UUID
	if err := id.Scan(r.ID); err != nil {
		return fmt.Errorf("report id: %w", err)
	}
	doc, err := s.storedCopy(r, tx.From)
	if err != nil {
		return err
	}
	var expires *time.Time
	if s.opts.Retention > 0 {
		e := s.now().Add(s.opts.Retention)
		expires = &e
	}
	var from, to, selector, calldata []byte
	if s.opts.StoreSender {
		from = tx.From.Bytes()
	}
	if tx.To != nil {
		to = tx.To.Bytes()
	}
	if sel, ok := tx.Selector(); ok {
		selector = sel[:]
	}
	if s.opts.StoreCalldata {
		calldata = tx.Data
	}
	completeness := models.CompletenessNone
	var block *int64
	if r.Simulation != nil {
		completeness = r.Simulation.Completeness
		if r.Simulation.BlockNumber > 0 {
			b := int64(r.Simulation.BlockNumber) //nolint:gosec // block numbers fit int64
			block = &b
		}
	}
	method := ""
	kind := models.CallUnknown
	if r.Decoded != nil {
		method, kind = trunc(r.Decoded.Signature, 256), r.Decoded.Kind
	}

	return pgx.BeginFunc(ctx, s.pool, func(dbtx pgx.Tx) error {
		_, err := dbtx.Exec(ctx, `
			INSERT INTO analyzed_transactions (id, request_id, chain_id, from_address, to_address, value_wei, selector,
			  calldata_hash, calldata, block_number, decoded_method, call_kind, risk_score, risk_category, confidence,
			  simulation_completeness, finding_count, report, engine_version, created_at, expires_at)
			VALUES ($1, nullif($2, ''), $3, $4, $5, $6::numeric, $7, $8, $9, $10, nullif($11, ''), $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)`,
			id, trunc(r.RequestID, 64), int64(tx.ChainID), from, to, //nolint:gosec // chain IDs are bounded by models.MaxChainID
			tx.Value.String(), selector, s.calldataHash(tx.Data), calldata, block, method, string(kind),
			r.Risk.Score, string(r.Risk.Category), r.Risk.Confidence.String(), string(completeness), len(r.Findings),
			doc, trunc(r.EngineVersion, 64), r.AnalyzedAt, expires)
		if err != nil {
			return fmt.Errorf("insert analysis: %w", err)
		}
		if sim := r.Simulation; sim != nil && sim.Status != models.SimNotRun {
			simDoc, err := json.Marshal(sim)
			if err != nil {
				return err
			}
			if !s.opts.StoreSender {
				simDoc = redactAddress(simDoc, tx.From)
			}
			var gasEst *int64
			if sim.GasEstimate != nil {
				g := int64(*sim.GasEstimate) //nolint:gosec // gas fits int64
				gasEst = &g
			}
			var blockHash []byte
			if sim.BlockHash != "" {
				blockHash = common.HexToHash(sim.BlockHash).Bytes()
			}
			if _, err := dbtx.Exec(ctx, `
				INSERT INTO simulation_results (analysis_id, backend, status, completeness, incomplete_reasons, chain_id,
				  block_number, block_hash, gas_used, gas_estimate, revert_reason, duration_ms, result)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, nullif($11, ''), $12, $13)`,
				id, trunc(sim.Backend, 64), string(sim.Status), string(sim.Completeness), nonNil(sim.IncompleteReasons),
				int64(tx.ChainID), int64(sim.BlockNumber), blockHash, int64(sim.GasUsed), gasEst, //nolint:gosec // bounded values
				trunc(sim.RevertReason, 1024), sim.DurationMs, simDoc); err != nil {
				return fmt.Errorf("insert simulation: %w", err)
			}
		}
		for _, f := range r.Findings {
			fDoc, err := json.Marshal(f)
			if err != nil {
				return err
			}
			if !s.opts.StoreSender {
				fDoc = redactAddress(fDoc, tx.From)
			}
			if _, err := dbtx.Exec(ctx, `
				INSERT INTO security_findings (analysis_id, rule_id, fingerprint, category, severity, confidence, source, title, finding)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (analysis_id, fingerprint) DO NOTHING`,
				id, trunc(f.RuleID, 64), trunc(f.Fingerprint, 256), string(f.Category), f.Severity.String(),
				f.Confidence.String(), string(f.Source), trunc(f.Title, 256), fDoc); err != nil {
				return fmt.Errorf("insert finding: %w", err)
			}
		}
		for addr, role := range ledger(r, tx, s.opts.StoreSender) {
			if _, err := dbtx.Exec(ctx, `
				INSERT INTO analysis_history (analysis_id, chain_id, address, role, created_at)
				VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
				id, int64(tx.ChainID), addr.a.Bytes(), role, r.AnalyzedAt); err != nil { //nolint:gosec // bounded chain ID
				return fmt.Errorf("insert history: %w", err)
			}
		}
		return nil
	})
}

type ledgerKey struct {
	a    common.Address
	role string
}

// ledger maps every involved address to its roles for the Address Inspector.
func ledger(r *models.RiskReport, tx *models.Transaction, storeSender bool) map[ledgerKey]string {
	out := map[ledgerKey]string{}
	add := func(a common.Address, role string) {
		if a == (common.Address{}) || (!storeSender && a == tx.From) {
			return
		}
		out[ledgerKey{a, role}] = role
	}
	roles := core.CollectAddresses(tx, r.Decoded, r.Approvals, r.Simulation)
	for a, rs := range roles {
		for role := range rs {
			switch role {
			case core.RoleSender:
				add(a, "sender")
			case core.RoleTarget:
				add(a, "target")
			case core.RoleSpender:
				add(a, "spender")
			case core.RoleRecipient:
				add(a, "recipient")
			case core.RoleToken:
				add(a, "token")
			default:
				add(a, "interacted")
			}
		}
	}
	if r.Simulation != nil {
		for _, t := range r.Simulation.AssetTransfers {
			if common.IsHexAddress(t.To) {
				add(common.HexToAddress(t.To), "recipient")
			}
			if t.Asset.Address != "" {
				add(common.HexToAddress(t.Asset.Address), "token")
			}
		}
	}
	return out
}

// GetReport returns a stored report (as stored, i.e. with privacy options
// applied).
func (s *AnalysisStore) GetReport(ctx context.Context, id string) (*models.RiskReport, error) {
	var uid pgtype.UUID
	if err := uid.Scan(id); err != nil {
		return nil, txerrors.New(txerrors.KindNotFound, "analysis_not_found", "analysis not found")
	}
	var doc []byte
	err := s.pool.QueryRow(ctx, `SELECT report FROM analyzed_transactions WHERE id = $1 AND (expires_at IS NULL OR expires_at > now())`, uid).Scan(&doc)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, txerrors.New(txerrors.KindNotFound, "analysis_not_found", "analysis not found")
	}
	if err != nil {
		return nil, txerrors.Wrap(err, txerrors.KindUnavailable, "store_unavailable", "analysis storage unavailable")
	}
	var r models.RiskReport
	if err := json.Unmarshal(doc, &r); err != nil {
		return nil, fmt.Errorf("decode stored report: %w", err)
	}
	return &r, nil
}

// ListReports returns summaries, newest first, plus the total match count.
func (s *AnalysisStore) ListReports(ctx context.Context, f interfaces.AnalysisFilter, p interfaces.Page) ([]models.AnalysisSummary, int64, error) {
	var where []string
	var args []any
	arg := func(v any) string { args = append(args, v); return fmt.Sprintf("$%d", len(args)) }
	where = append(where, "(a.expires_at IS NULL OR a.expires_at > now())")
	if f.ChainID != nil {
		where = append(where, "a.chain_id = "+arg(int64(*f.ChainID))) //nolint:gosec // bounded chain ID
	}
	if f.MinScore != nil {
		where = append(where, "a.risk_score >= "+arg(*f.MinScore))
	}
	if f.Since != nil {
		where = append(where, "a.created_at >= "+arg(*f.Since))
	}
	if f.Address != nil {
		where = append(where, "EXISTS (SELECT 1 FROM analysis_history h WHERE h.analysis_id = a.id AND h.address = "+arg(f.Address.Bytes())+")")
	}
	q := `SELECT a.id, a.created_at, a.chain_id, a.from_address, a.to_address, a.call_kind, coalesce(a.decoded_method, ''),
	        a.risk_score, a.risk_category, a.confidence, a.finding_count, a.simulation_completeness, count(*) OVER()
	      FROM analyzed_transactions a WHERE ` + strings.Join(where, " AND ") +
		` ORDER BY a.created_at DESC, a.id LIMIT ` + arg(p.Limit) + ` OFFSET ` + arg(p.Offset)
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, txerrors.Wrap(err, txerrors.KindUnavailable, "store_unavailable", "analysis storage unavailable")
	}
	defer rows.Close()
	out := []models.AnalysisSummary{}
	var total int64
	for rows.Next() {
		var (
			sm                         models.AnalysisSummary
			id                         pgtype.UUID
			chain                      int64
			from, to                   []byte
			kind, cat, conf, completed string
		)
		if err := rows.Scan(&id, &sm.AnalyzedAt, &chain, &from, &to, &kind, &sm.Method, &sm.Score, &cat, &conf, &sm.FindingCount, &completed, &total); err != nil {
			return nil, 0, err
		}
		sm.ID = uuidString(id)
		sm.ChainID = uint64(chain) //nolint:gosec // stored chain IDs are positive
		if len(from) == 20 {
			sm.From = common.BytesToAddress(from).Hex()
		}
		if len(to) == 20 {
			sm.To = common.BytesToAddress(to).Hex()
		}
		sm.Kind, sm.Category, sm.Completeness = models.CallKind(kind), models.RiskCategory(cat), models.Completeness(completed)
		sm.Confidence, _ = models.ParseConfidence(conf)
		out = append(out, sm)
	}
	return out, total, rows.Err()
}

// Stats aggregates stored analyses for the dashboard.
func (s *AnalysisStore) Stats(ctx context.Context, since *time.Time) (*interfaces.AnalysisStats, error) {
	cond, args := "(expires_at IS NULL OR expires_at > now())", []any{}
	if since != nil {
		cond += " AND created_at >= $1"
		args = append(args, *since)
	}
	st := &interfaces.AnalysisStats{ByCategory: map[models.RiskCategory]int64{}, ByChain: map[uint64]int64{}}
	rows, err := s.pool.Query(ctx, `SELECT chain_id, risk_category, count(*), count(*) FILTER (WHERE risk_score >= 60)
		FROM analyzed_transactions WHERE `+cond+` GROUP BY chain_id, risk_category`, args...)
	if err != nil {
		return nil, txerrors.Wrap(err, txerrors.KindUnavailable, "store_unavailable", "analysis storage unavailable")
	}
	defer rows.Close()
	for rows.Next() {
		var chain, n, high int64
		var cat string
		if err := rows.Scan(&chain, &cat, &n, &high); err != nil {
			return nil, err
		}
		st.Total += n
		st.HighRisk += high
		st.ByCategory[models.RiskCategory(cat)] += n
		st.ByChain[uint64(chain)] += n //nolint:gosec // positive chain IDs
	}
	return st, rows.Err()
}

// PurgeExpired deletes analyses past retention (cascading to derived rows).
func (s *AnalysisStore) PurgeExpired(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM analyzed_transactions WHERE expires_at IS NOT NULL AND expires_at <= $1`, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func uuidString(u pgtype.UUID) string {
	b := u.Bytes
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// trunc limits s to n bytes without splitting a UTF-8 sequence.
func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
