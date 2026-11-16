// Command kubechaos-approver is the Approval Service (architecture §15): a separate trust
// domain with its own database, its own OIDC client and the only attestation signing key.
//
//	kubechaos-approver serve        run the approver UI API and the internal control-plane API
//	kubechaos-approver migrate up   apply the approval database migrations (approver_migrator)
//	kubechaos-approver pubkey       print the ChaosPolicy trustedKeys entry for the signing key
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kubechaos/kubechaos/backend/internal/approval"
	"github.com/kubechaos/kubechaos/backend/internal/approvalapi"
	"github.com/kubechaos/kubechaos/backend/internal/auth"
	"github.com/kubechaos/kubechaos/backend/internal/config"
	"github.com/kubechaos/kubechaos/backend/internal/logging"
	"github.com/kubechaos/kubechaos/backend/internal/repository"
)

var version = "dev"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	boot := logging.New(os.Stderr, slog.LevelInfo)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch {
	case len(args) == 1 && args[0] == "serve":
		err = serve(ctx)
	case len(args) == 2 && args[0] == "migrate" && args[1] == "up":
		err = migrate(ctx)
	case len(args) == 1 && args[0] == "pubkey":
		err = pubkey()
	default:
		fmt.Fprintln(os.Stderr, "usage: kubechaos-approver serve | migrate up | pubkey")
		return 2
	}
	if err != nil {
		boot.Error("fatal", slog.Any("error", err))
		return 1
	}
	return 0
}

func newLogger(level slog.Level) *slog.Logger {
	return logging.New(os.Stdout, level).With(slog.String("service", "kubechaos-approver"), slog.String("version", version))
}

func pubkey() error {
	key, kid, err := config.LoadApproverKey(os.Getenv)
	if err != nil {
		return err
	}
	pub := key.Public().(ed25519.PublicKey)
	fmt.Printf("- kid: %s\n  publicKey: %s\n", kid, base64.StdEncoding.EncodeToString(pub))
	return nil
}

func migrate(ctx context.Context) error {
	cfg, err := config.LoadApproverMigrate(os.Getenv)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	return repository.MigrateUpFS(ctx, cfg.MigrateDatabaseURL, repository.PoolOptions{ApplicationName: "kubechaos-approver-migrate",
		RequireTLS: cfg.Environment != config.EnvDevelopment}, approval.Migrations(), newLogger(cfg.LogLevel))
}

func serve(ctx context.Context) error {
	cfg, err := config.LoadApprover(os.Getenv)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	logger := newLogger(cfg.LogLevel)
	pool, err := repository.Connect(ctx, cfg.DatabaseURL, repository.PoolOptions{MaxConns: 10, ApplicationName: "kubechaos-approver",
		RequireTLS: cfg.Environment != config.EnvDevelopment})
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := repository.VerifyServiceRole(ctx, pool, "app", "approval"); err != nil {
		return err
	}

	sessions := repository.NewSessionStore(pool)
	// Every approver session is high privilege: short idle and absolute lifetimes.
	authSvc := auth.NewService(auth.Config{PublicURL: cfg.PublicURL, SessionIdle: 10 * time.Minute, SessionMax: time.Hour,
		LoginTTL: 10 * time.Minute}, sessions, auth.NewOIDC(auth.OIDCConfig{
		Issuer: cfg.OIDCIssuer, ClientID: cfg.OIDCClientID, ClientSecret: cfg.OIDCClientSecret,
		RedirectURL: cfg.PublicURL.String() + "/auth/callback",
	}), logger)

	svc := &approval.Service{Cfg: approval.Config{ClusterID: cfg.ClusterID, Environment: cfg.ClusterEnv, Routes: cfg.Routes,
		MinApprovals: cfg.MinApprovals, RequestTTL: 24 * time.Hour, AttestationTTL: time.Hour, StepUpMaxAge: 5 * time.Minute,
		KID: cfg.KID, Key: cfg.SigningKey}, Store: approval.PGStore{Pool: pool}, Log: logger}

	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := sessions.DeleteExpired(ctx); err != nil {
					logger.Warn("purge expired sessions", slog.Any("error", err))
				}
			}
		}
	}()

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           approvalapi.NewRouter(approvalapi.Deps{Logger: logger, DB: pool, Auth: authSvc, Service: svc, ServiceToken: cfg.ServiceToken}),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 64 << 10, ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", slog.String("addr", cfg.HTTPAddr), slog.String("cluster", cfg.ClusterID), slog.String("kid", cfg.KID))
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
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}
