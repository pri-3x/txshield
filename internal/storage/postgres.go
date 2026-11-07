// Package storage implements PostgreSQL persistence. Persistence is optional:
// TxShield runs statelessly when no database is configured.
//
// Phase 1 provides connection management and health checking. Repository
// implementations of interfaces.AnalysisStore arrive in Phase 5.
package storage

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// OpenPostgres creates a connection pool. The pool connects lazily; callers
// should Ping to verify reachability.
func OpenPostgres(ctx context.Context, dsn string, maxConns int32) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		// pgx parse errors can echo the DSN, which contains the password.
		return nil, fmt.Errorf("invalid database URL")
	}
	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = "txshield"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create postgres pool: %w", err)
	}
	return pool, nil
}

// PostgresHealth checks database reachability. It is critical: when
// persistence is configured, the operator expects it to work.
type PostgresHealth struct{ Pool *pgxpool.Pool }

func (PostgresHealth) Name() string                      { return "postgres" }
func (PostgresHealth) Critical() bool                    { return true }
func (h PostgresHealth) Check(ctx context.Context) error { return h.Pool.Ping(ctx) }
