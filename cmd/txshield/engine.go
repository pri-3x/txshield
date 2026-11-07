package main

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pri-3x/txshield/internal/analyzer"
	"github.com/pri-3x/txshield/internal/api"
	"github.com/pri-3x/txshield/internal/config"
	"github.com/pri-3x/txshield/internal/evm"
	"github.com/pri-3x/txshield/internal/security/reputation"
	"github.com/pri-3x/txshield/internal/simulator"
	"github.com/pri-3x/txshield/internal/storage"
	"github.com/pri-3x/txshield/internal/version"
	"github.com/pri-3x/txshield/pkg/interfaces"
)

// buildEngine wires the analysis engine from configuration. pool may be nil
// (no persistence). The returned closer releases simulator processes.
func buildEngine(cfg config.Config, pool *pgxpool.Pool) (*api.Engine, []interfaces.HealthChecker, func(), error) {
	e := &api.Engine{AllowUserRPC: cfg.Chains.AllowUserRPC, UserRPCSimTimeout: cfg.Simulation.Timeout}
	var checks []interfaces.HealthChecker
	closer := func() {}

	var extra []interfaces.ReputationProvider
	if pool != nil {
		extra = append(extra, reputation.NewPostgresProvider(pool))
		retention := time.Duration(cfg.Storage.RetentionDays) * 24 * time.Hour
		e.Store = storage.NewAnalysisStore(pool, storage.StoreOptions{
			StoreSender: cfg.Storage.StoreSender, StoreCalldata: cfg.Storage.StoreCalldata, Retention: retention,
		})
	}

	if len(cfg.Chains.RPCURLs) > 0 {
		e.Chains = evm.NewRegistry(cfg.Chains.RPCURLs, evm.Options{})
		e.Inspector = evm.NewInspector(e.Chains, 0)
		for _, id := range e.Chains.Chains() {
			checks = append(checks, rpcHealth{reg: e.Chains, chainID: id})
		}
		switch cfg.Simulation.Backend {
		case "anvil":
			sim := simulator.NewAnvil(e.Chains, simulator.AnvilOptions{
				Path: cfg.Simulation.AnvilPath, Workers: cfg.Simulation.MaxConcurrent, Timeout: cfg.Simulation.Timeout,
			})
			e.Simulator = sim
			closer = sim.Close
			checks = append(checks, binaryHealth{name: "anvil", path: cfg.Simulation.AnvilPath})
		case "rpc-trace":
			e.Simulator = simulator.NewRPCTrace(e.Chains, cfg.Simulation.Timeout)
		}
	}

	opts := analyzer.BuildOptions{
		EngineVersion:     version.Version,
		ReputationFiles:   cfg.Security.ReputationFiles,
		ExtraReputation:   extra,
		ScoringConfigPath: cfg.Security.ScoringConfigPath,
		Inspector:         e.Inspector,
		Simulator:         e.Simulator,
	}
	if e.Chains != nil {
		opts.Chains = e.Chains
	}
	a, err := analyzer.Build(opts)
	if err != nil {
		closer()
		return nil, nil, func() {}, fmt.Errorf("analysis engine: %w", err)
	}
	e.Analyzer = a
	return e, checks, closer, nil
}

// retentionWorker purges expired analyses periodically until ctx ends.
func retentionWorker(ctx context.Context, store interfaces.AnalysisStore, every time.Duration, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	purge := func() {
		pctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		n, err := store.PurgeExpired(pctx, time.Now())
		if err != nil {
			log.Warn("retention purge failed", "err", err)
			return
		}
		if n > 0 {
			log.Info("retention purge", "deleted", n)
		}
	}
	purge()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			purge()
		}
	}
}

// rpcHealth checks a configured chain endpoint (non-critical: analysis
// still works offline when an endpoint is down).
type rpcHealth struct {
	reg     *evm.Registry
	chainID uint64
}

func (h rpcHealth) Name() string   { return fmt.Sprintf("rpc:%d", h.chainID) }
func (h rpcHealth) Critical() bool { return false }
func (h rpcHealth) Check(ctx context.Context) error {
	c, err := h.reg.Client(ctx, h.chainID)
	if err != nil {
		return err
	}
	_, err = c.BlockNumber(ctx)
	return err
}

// binaryHealth checks that a required executable is present.
type binaryHealth struct{ name, path string }

func (h binaryHealth) Name() string   { return "simulator:" + h.name }
func (h binaryHealth) Critical() bool { return false }
func (h binaryHealth) Check(context.Context) error {
	_, err := exec.LookPath(h.path)
	return err
}
