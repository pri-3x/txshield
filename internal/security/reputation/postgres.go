package reputation

import (
	"context"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/txshield/txshield/pkg/models"
)

// PostgresProvider reads locally maintained records from the
// contract_reputation table. Expired records are ignored.
type PostgresProvider struct {
	pool *pgxpool.Pool
}

// NewPostgresProvider returns a provider backed by pool.
func NewPostgresProvider(pool *pgxpool.Pool) *PostgresProvider { return &PostgresProvider{pool: pool} }

func (p *PostgresProvider) Name() string                      { return "local" }
func (p *PostgresProvider) Kind() models.ReputationSourceKind { return models.ReputationSourceLocal }

// Lookup implements interfaces.ReputationProvider.
func (p *PostgresProvider) Lookup(ctx context.Context, chainID uint64, addr common.Address) ([]models.ReputationRecord, error) {
	if chainID > models.MaxChainID {
		return nil, nil
	}
	rows, err := p.pool.Query(ctx, `
		SELECT status, source, source_kind, coalesce(reason, ''), labels, confidence, updated_at, expires_at
		FROM contract_reputation
		WHERE chain_id = $1 AND address = $2 AND (expires_at IS NULL OR expires_at > now())
		ORDER BY source`, int64(chainID), addr.Bytes()) //nolint:gosec // bounded by models.MaxChainID above
	if err != nil {
		return nil, fmt.Errorf("query reputation: %w", err)
	}
	defer rows.Close()
	var out []models.ReputationRecord
	for rows.Next() {
		var (
			r                  models.ReputationRecord
			status, kind, conf string
			updatedAt          time.Time
			expiresAt          *time.Time
		)
		if err := rows.Scan(&status, &r.Source, &kind, &r.Reason, &r.Labels, &conf, &updatedAt, &expiresAt); err != nil {
			return nil, fmt.Errorf("scan reputation: %w", err)
		}
		c, err := models.ParseConfidence(conf)
		if err != nil {
			return nil, err
		}
		r.ChainID, r.Address, r.Status, r.SourceKind = chainID, addr.Hex(), models.ReputationStatus(status), models.ReputationSourceKind(kind)
		r.Confidence, r.UpdatedAt, r.ExpiresAt = c, updatedAt, expiresAt
		out = append(out, r)
	}
	return out, rows.Err()
}

// Upsert stores or replaces a record (keyed by chain, address, source).
func (p *PostgresProvider) Upsert(ctx context.Context, r models.ReputationRecord) error {
	addr, err := models.ParseAddress(r.Address)
	if err != nil {
		return fmt.Errorf("address: %w", err)
	}
	if r.ChainID == 0 || r.ChainID > models.MaxChainID {
		return fmt.Errorf("chainId must be between 1 and 2^53-1")
	}
	if r.SourceKind == "" {
		r.SourceKind = models.ReputationSourceLocal
	}
	if r.Labels == nil {
		r.Labels = []string{}
	}
	_, err = p.pool.Exec(ctx, `
		INSERT INTO contract_reputation (chain_id, address, status, source, source_kind, reason, labels, confidence, expires_at)
		VALUES ($1, $2, $3, $4, $5, nullif($6, ''), $7, $8, $9)
		ON CONFLICT (chain_id, address, source) DO UPDATE SET
		  status = EXCLUDED.status, source_kind = EXCLUDED.source_kind, reason = EXCLUDED.reason,
		  labels = EXCLUDED.labels, confidence = EXCLUDED.confidence, expires_at = EXCLUDED.expires_at,
		  updated_at = now()`,
		int64(r.ChainID), addr.Bytes(), string(r.Status), r.Source, string(r.SourceKind), r.Reason, r.Labels, r.Confidence.String(), r.ExpiresAt) //nolint:gosec // bounded by models.MaxChainID above
	return err
}
