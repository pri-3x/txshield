//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/txshield/txshield/internal/security/reputation"
	"github.com/txshield/txshield/pkg/models"
)

// TestPostgresReputationProvider applies the schema in an isolated schema and
// exercises upsert, lookup, chain scoping, and expiry.
func TestPostgresReputationProvider(t *testing.T) {
	conn := connect(t)
	ctx := context.Background()
	if _, err := conn.Exec(ctx, `DROP SCHEMA IF EXISTS txshield_rep CASCADE; CREATE SCHEMA txshield_rep; SET search_path TO txshield_rep`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(context.Background(), `DROP SCHEMA IF EXISTS txshield_rep CASCADE`) })
	execFile(t, conn, "000001_init.up.sql")

	cfg, err := pgxpool.ParseConfig(os.Getenv("TXSHIELD_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = "txshield_rep"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	p := reputation.NewPostgresProvider(pool)
	a := common.HexToAddress("0x1111111111111111111111111111111111111111")
	past := time.Now().Add(-time.Hour)

	for _, r := range []models.ReputationRecord{
		{ChainID: 1, Address: a.Hex(), Status: models.ReputationSuspicious, Source: "local", Reason: "first", Confidence: models.ConfidenceMedium},
		{ChainID: 1, Address: a.Hex(), Status: models.ReputationBlocked, Source: "local", Reason: "updated", Labels: []string{"drainer"}, Confidence: models.ConfidenceHigh},
		{ChainID: 1, Address: a.Hex(), Status: models.ReputationAllowed, Source: "old", Confidence: models.ConfidenceLow, ExpiresAt: &past},
		{ChainID: 10, Address: a.Hex(), Status: models.ReputationAllowed, Source: "local", Confidence: models.ConfidenceHigh},
	} {
		if err := p.Upsert(ctx, r); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}

	recs, err := p.Lookup(ctx, 1, a)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("want 1 live record on chain 1 (upsert replaces, expired hidden), got %+v", recs)
	}
	r := recs[0]
	if r.Status != models.ReputationBlocked || r.Reason != "updated" || r.Confidence != models.ConfidenceHigh || len(r.Labels) != 1 || r.SourceKind != models.ReputationSourceLocal {
		t.Fatalf("record = %+v", r)
	}
	if err := p.Upsert(ctx, models.ReputationRecord{ChainID: 1, Address: "0xbad"}); err == nil {
		t.Fatal("invalid address must be rejected")
	}
}
