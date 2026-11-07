//go:build integration

// Package integration contains tests that need real infrastructure.
// Run with: TXSHIELD_TEST_DATABASE_URL=postgres://... go test -tags integration ./tests/integration/...
package integration

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func migrationsDir(t *testing.T) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "migrations")
}

func connect(t *testing.T) *pgx.Conn {
	t.Helper()
	dsn := os.Getenv("TXSHIELD_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TXSHIELD_TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

func execFile(t *testing.T, conn *pgx.Conn, name string) {
	t.Helper()
	sql, err := os.ReadFile(filepath.Join(migrationsDir(t), name))
	if err != nil {
		t.Fatal(err)
	}
	// Simple protocol (no args) allows multi-statement files.
	if _, err := conn.Exec(context.Background(), string(sql)); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

// TestMigrationsUpDown applies the schema, exercises key constraints, and
// rolls back. It uses a dedicated schema so it does not touch real data.
func TestMigrationsUpDown(t *testing.T) {
	conn := connect(t)
	ctx := context.Background()

	if _, err := conn.Exec(ctx, `DROP SCHEMA IF EXISTS txshield_it CASCADE; CREATE SCHEMA txshield_it; SET search_path TO txshield_it`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(context.Background(), `DROP SCHEMA IF EXISTS txshield_it CASCADE`) })

	execFile(t, conn, "000001_init.up.sql")

	for _, table := range []string{
		"analyzed_transactions", "simulation_results", "security_findings",
		"contract_metadata", "contract_reputation", "token_metadata", "analysis_history",
	} {
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT to_regclass('txshield_it.' || $1) IS NOT NULL`, table).Scan(&exists); err != nil || !exists {
			t.Fatalf("table %s missing (err=%v)", table, err)
		}
	}

	// A valid analysis row with dependent rows.
	var id string
	err := conn.QueryRow(ctx, `
		INSERT INTO analyzed_transactions
		  (chain_id, to_address, value_wei, selector, calldata_hash, call_kind, risk_score,
		   risk_category, confidence, simulation_completeness, report, engine_version, expires_at)
		VALUES (1, decode(repeat('ab', 20), 'hex'), 115792089237316195423570985008687907853269984665640564039457584007913129639935,
		        decode('095ea7b3', 'hex'), decode(repeat('00', 32), 'hex'), 'contract_call', 72,
		        'high', 'medium', 'partial', '{}'::jsonb, 'test', now() - interval '1 day')
		RETURNING id`).Scan(&id)
	if err != nil {
		t.Fatalf("insert analysis (uint256 max value must fit): %v", err)
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO security_findings (analysis_id, rule_id, fingerprint, category, severity, confidence, source, title, finding)
		VALUES ($1, 'TXS-APPROVAL-001', 'fp', 'approval', 'high', 'high', 'fact', 'Unlimited approval', '{}')`, id); err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO analysis_history (analysis_id, chain_id, address, role)
		VALUES ($1, 1, decode(repeat('ab', 20), 'hex'), 'spender')`, id); err != nil {
		t.Fatalf("insert history: %v", err)
	}

	// Constraints reject malformed data.
	bad := map[string]string{
		"short address": `INSERT INTO contract_metadata (chain_id, address, is_contract, observed_block) VALUES (1, decode('abcd', 'hex'), true, 1)`,
		"score > 100": `INSERT INTO analyzed_transactions (chain_id, calldata_hash, call_kind, risk_score, risk_category, confidence, simulation_completeness, report, engine_version)
		                VALUES (1, decode(repeat('00', 32), 'hex'), 'unknown', 101, 'critical', 'low', 'none', '{}', 't')`,
		"bad severity": `INSERT INTO security_findings (analysis_id, rule_id, fingerprint, category, severity, confidence, source, title, finding)
		                 VALUES ('` + id + `', 'X', 'fp2', 'c', 'apocalyptic', 'high', 'fact', 't', '{}')`,
		"duplicate fingerprint": `INSERT INTO security_findings (analysis_id, rule_id, fingerprint, category, severity, confidence, source, title, finding)
		                          VALUES ('` + id + `', 'X', 'fp', 'c', 'low', 'high', 'fact', 't', '{}')`,
	}
	for name, q := range bad {
		if _, err := conn.Exec(ctx, q); err == nil {
			t.Errorf("%s: expected constraint violation", name)
		}
	}

	// Retention: deleting expired analyses cascades to derived rows.
	tag, err := conn.Exec(ctx, `DELETE FROM analyzed_transactions WHERE expires_at < now()`)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("purge: %v rows=%d", err, tag.RowsAffected())
	}
	var remaining int
	if err := conn.QueryRow(ctx, `SELECT (SELECT count(*) FROM security_findings) + (SELECT count(*) FROM analysis_history)`).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("cascade failed: remaining=%d err=%v", remaining, err)
	}

	execFile(t, conn, "000001_init.down.sql")
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('txshield_it.analyzed_transactions') IS NOT NULL`).Scan(&exists); err != nil || exists {
		t.Fatalf("down migration did not drop tables (err=%v)", err)
	}
}
