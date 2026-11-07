package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pri-3x/txshield/internal/api"
	"github.com/pri-3x/txshield/internal/cache"
	"github.com/pri-3x/txshield/internal/config"
	"github.com/pri-3x/txshield/internal/logging"
	"github.com/pri-3x/txshield/internal/metrics"
	"github.com/pri-3x/txshield/internal/storage"
	"github.com/pri-3x/txshield/internal/version"
	"github.com/pri-3x/txshield/pkg/interfaces"
)

func runVersion(_ context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print as JSON")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if *asJSON {
		_ = json.NewEncoder(stdout).Encode(map[string]string{"version": version.Version, "commit": version.Commit})
	} else {
		fmt.Fprintf(stdout, "txshield %s (%s)\n", version.Version, version.Commit)
	}
	return ExitOK
}

func runServe(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: txshield serve\n\nAll configuration is read from TXSHIELD_* environment variables; see .env.example.")
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(stderr, "configuration error:\n%v\n", err)
		return ExitUsage
	}
	log := logging.New(stdout, cfg.Log.Level, cfg.Log.Format)
	slog.SetDefault(log)

	if err := serve(ctx, cfg, log); err != nil {
		log.Error("server exited with error", "err", err)
		return ExitError
	}
	return ExitOK
}

// serve wires dependencies (constructor injection, no globals) and runs the
// HTTP server until ctx is cancelled, then shuts down gracefully.
func serve(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	m := metrics.New(version.Version, version.Commit)
	var checks []interfaces.HealthChecker
	var closers []func()
	var pool *pgxpool.Pool

	if cfg.Storage.DatabaseURL != "" {
		var err error
		pool, err = storage.OpenPostgres(ctx, cfg.Storage.DatabaseURL, cfg.Storage.MaxConns)
		if err != nil {
			return err
		}
		closers = append(closers, pool.Close)
		checks = append(checks, storage.PostgresHealth{Pool: pool})
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if err := pool.Ping(pingCtx); err != nil {
			// Not fatal: /health reports it and orchestrators can restart us.
			log.Warn("postgres not reachable at startup", "err", err)
		}
		cancel()
	} else {
		log.Info("persistence disabled (TXSHIELD_DATABASE_URL not set)")
	}

	if cfg.Redis.URL != "" {
		r, err := cache.OpenRedis(cfg.Redis.URL)
		if err != nil {
			return err
		}
		closers = append(closers, func() { _ = r.Close() })
		checks = append(checks, cache.RedisHealth{R: r})
	}
	defer func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}()

	chains := cfg.Chains.ConfiguredChains()
	redacted := make(map[uint64]string, len(chains))
	for _, id := range chains {
		redacted[id] = config.RedactURL(cfg.Chains.RPCURLs[id])
	}
	log.Info("chains configured", "count", len(chains), "endpoints", redacted, "simulator", cfg.Simulation.Backend)

	engine, engineChecks, closeEngine, err := buildEngine(cfg, pool)
	if err != nil {
		return err
	}
	// Stopped after the HTTP server drains (deferred closers run in reverse).
	closers = append(closers, closeEngine)
	checks = append(checks, engineChecks...)
	if engine.Store != nil && cfg.Storage.RetentionDays > 0 {
		go retentionWorker(ctx, engine.Store, time.Hour, log)
	}

	srv := &http.Server{
		Addr:              cfg.HTTP.Addr,
		Handler:           api.New(api.Deps{Config: cfg, Logger: log, Metrics: m, Checks: checks, Engine: engine}),
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		BaseContext:       func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("http server listening", "addr", cfg.HTTP.Addr, "version", version.Version)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("http server: %w", err)
		}
		return nil
	case <-ctx.Done():
	}

	log.Info("shutting down", "timeout", cfg.HTTP.ShutdownTimeout.String())
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	log.Info("shutdown complete")
	return nil
}
