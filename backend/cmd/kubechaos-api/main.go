// Command kubechaos-api is the KubeChaos control plane.
//
//	kubechaos-api serve            run the HTTP API (app DB role)
//	kubechaos-api migrate up       apply database migrations (migrator DB role)
//	kubechaos-api migrate status   show migration state
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kubechaos/kubechaos/backend/internal/api"
	"github.com/kubechaos/kubechaos/backend/internal/auth"
	"github.com/kubechaos/kubechaos/backend/internal/config"
	"github.com/kubechaos/kubechaos/backend/internal/repository"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	bootLogger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: kubechaos-api serve | migrate up | migrate status")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch {
	case args[0] == "serve":
		err = serve(ctx)
	case args[0] == "migrate" && len(args) == 2 && (args[1] == "up" || args[1] == "status"):
		err = migrate(ctx, args[1])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args)
		return 2
	}
	if err != nil {
		bootLogger.Error("fatal", slog.Any("error", err))
		return 1
	}
	return 0
}

func newLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})).
		With(slog.String("service", "kubechaos-api"), slog.String("version", version))
}

func serve(ctx context.Context) error {
	cfg, err := config.LoadServer(os.Getenv)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	logger := newLogger(cfg.LogLevel)

	pool, err := repository.Connect(ctx, cfg.DatabaseURL, repository.PoolOptions{
		MaxConns:        cfg.DBMaxConns,
		ApplicationName: "kubechaos-api",
		RequireTLS:      cfg.Environment != config.EnvDevelopment,
	})
	if err != nil {
		return err
	}
	defer pool.Close()

	// Fail closed: never serve with a role that could rewrite audit history or the schema.
	if err := repository.VerifyLeastPrivilege(ctx, pool); err != nil {
		return err
	}

	sessions := repository.NewSessionStore(pool)
	authSvc := auth.NewService(auth.Config{
		PublicURL:   cfg.PublicURL,
		SessionIdle: 30 * time.Minute,
		SessionMax:  8 * time.Hour,
		LoginTTL:    10 * time.Minute,
	}, sessions, auth.NewOIDC(auth.OIDCConfig{
		Issuer:       cfg.OIDCIssuer,
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		RedirectURL:  cfg.PublicURL.String() + "/auth/callback",
	}), logger)
	go purgeExpiredSessions(ctx, sessions, logger)

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           api.NewRouter(api.Deps{Logger: logger, DB: pool, Auth: authSvc, MaxBodyBytes: cfg.MaxBodyBytes, Version: version}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second, // SSE handlers will extend per-request via http.ResponseController
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", slog.String("addr", cfg.HTTPAddr), slog.String("environment", string(cfg.Environment)))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// purgeExpiredSessions removes expired sessions and login requests every 10 minutes.
// Lookups already ignore expired rows; this only bounds table growth.
func purgeExpiredSessions(ctx context.Context, store auth.Store, logger *slog.Logger) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := store.DeleteExpired(ctx); err != nil {
				logger.Warn("purge expired sessions", slog.Any("error", err))
			}
		}
	}
}

func migrate(ctx context.Context, sub string) error {
	cfg, err := config.LoadMigrate(os.Getenv)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	logger := newLogger(cfg.LogLevel)
	opts := repository.PoolOptions{ApplicationName: "kubechaos-migrate", RequireTLS: cfg.Environment != config.EnvDevelopment}
	if sub == "status" {
		return repository.MigrationStatus(ctx, cfg.DatabaseURL, opts, logger)
	}
	return repository.MigrateUp(ctx, cfg.DatabaseURL, opts, logger)
}
