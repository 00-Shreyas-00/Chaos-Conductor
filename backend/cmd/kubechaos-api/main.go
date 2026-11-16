// Command kubechaos-api is the KubeChaos control plane.
//
//	kubechaos-api serve            run the HTTP API (app DB role)
//	kubechaos-api migrate up       apply database migrations (migrator DB role)
//	kubechaos-api migrate status   show migration state
//	kubechaos-api sessions revoke (--email E | --subject S | --role R | --all --yes)
//	                               break-glass session revocation (app DB role; no IdP needed)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kubechaos/kubechaos/backend/internal/api"
	"github.com/kubechaos/kubechaos/backend/internal/approval"
	"github.com/kubechaos/kubechaos/backend/internal/audit"
	"github.com/kubechaos/kubechaos/backend/internal/auth"
	"github.com/kubechaos/kubechaos/backend/internal/clusters"
	"github.com/kubechaos/kubechaos/backend/internal/config"
	"github.com/kubechaos/kubechaos/backend/internal/events"
	"github.com/kubechaos/kubechaos/backend/internal/experiments"
	"github.com/kubechaos/kubechaos/backend/internal/logging"
	"github.com/kubechaos/kubechaos/backend/internal/repository"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	bootLogger := logging.New(os.Stderr, slog.LevelInfo)
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: kubechaos-api serve | migrate up | migrate status | sessions revoke ...")
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
	case args[0] == "audit" && len(args) == 2 && args[1] == "verify":
		err = verifyAudit(ctx)
	case args[0] == "sessions" && len(args) >= 2 && args[1] == "revoke":
		var usage bool
		usage, err = revokeSessions(ctx, args[2:])
		if usage {
			return 2
		}
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
	// All logs pass through the redaction layer (no tokens, codes, secrets or cookies).
	return logging.New(os.Stdout, level).
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
		// admin/approver: much shorter sessions; also revocable via back-channel logout
		// and `kubechaos-api sessions revoke`.
		HighPrivilegeRoles:  auth.DefaultHighPrivilegeRoles,
		HighPrivSessionIdle: 10 * time.Minute,
		HighPrivSessionMax:  1 * time.Hour,
	}, sessions, auth.NewOIDC(auth.OIDCConfig{
		Issuer:       cfg.OIDCIssuer,
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		RedirectURL:  cfg.PublicURL.String() + "/auth/callback",
	}), logger)
	auditWriter := audit.NewWriter(pool)
	authSvc.Auditor = auditWriter
	go purgeExpiredSessions(ctx, sessions, logger)

	deps := api.Deps{Logger: logger, DB: pool, Auth: authSvc, Audit: api.PGAuditReader{Pool: pool},
		MaxBodyBytes: cfg.MaxBodyBytes, Version: version}
	if cfg.KubeconfigPath != "" {
		conn, err := clusters.NewCRDConnector(cfg.KubeconfigPath, cfg.ClusterID, logger)
		if err != nil {
			return fmt.Errorf("cluster connector: %w", err)
		}
		store := repository.NewExperimentStore(pool, auditWriter)
		env := "development"
		if pol, err := conn.Policy(ctx); err == nil && pol != nil {
			env = pol.Spec.Environment
		}
		if err := store.EnsureCluster(ctx, cfg.ClusterID, cfg.ClusterName, env); err != nil {
			return fmt.Errorf("register cluster: %w", err)
		}
		deps.Broker = events.NewBroker(5)
		deps.Experiments = &experiments.Service{Store: store, Conn: conn, Audit: auditWriter, Broker: deps.Broker, Log: logger}
		if cfg.ApproverURL != "" {
			deps.Experiments.Approvals = approvalAdapter{c: &approval.Client{BaseURL: cfg.ApproverURL, Token: cfg.ApproverToken}}
			go deps.Experiments.RunApprovals(ctx, 3*time.Second)
			logger.Info("approval service enabled", slog.String("url", cfg.ApproverURL))
		}
		go deps.Experiments.Run(ctx) // mirror cluster status into the DB and to SSE subscribers
		logger.Info("cluster connector enabled", slog.String("cluster", cfg.ClusterID))
	} else {
		logger.Warn("no KUBECHAOS_KUBECONFIG: experiment endpoints are disabled (503)")
	}

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           api.NewRouter(deps),
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

// approvalAdapter adapts the approval service client to the experiments service's interface.
type approvalAdapter struct{ c *approval.Client }

func (a approvalAdapter) Request(ctx context.Context, in experiments.ApprovalInput) (string, error) {
	return a.c.Request(ctx, approval.SubmitInput{ExperimentID: in.ExperimentID, ClusterID: in.ClusterID,
		Environment: in.Environment, Spec: in.Spec, RequesterName: in.RequesterName})
}

func (a approvalAdapter) Status(ctx context.Context, id string) (experiments.ApprovalStatus, error) {
	st, err := a.c.Status(ctx, id)
	return experiments.ApprovalStatus{ID: st.ID, State: st.State, Attestation: st.Attestation}, err
}

// verifyAudit walks the whole audit hash chain (break-glass / control node).
func verifyAudit(ctx context.Context) error {
	cfg, err := config.LoadAdmin(os.Getenv)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	pool, err := repository.Connect(ctx, cfg.DatabaseURL, repository.PoolOptions{
		MaxConns: 1, ApplicationName: "kubechaos-audit-verify", RequireTLS: cfg.Environment != config.EnvDevelopment})
	if err != nil {
		return err
	}
	defer pool.Close()
	res, err := audit.Verify(ctx, pool)
	if err != nil {
		return err
	}
	fmt.Printf("audit chain OK: %d event(s), head %s\n", res.Events, res.Head)
	return nil
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

// revokeSessions implements `sessions revoke`. It returns usage=true for invalid arguments.
func revokeSessions(ctx context.Context, args []string) (usage bool, err error) {
	fs := flag.NewFlagSet("sessions revoke", flag.ContinueOnError)
	email := fs.String("email", "", "revoke all sessions of the identity with this e-mail")
	subject := fs.String("subject", "", "revoke all sessions of this IdP subject")
	role := fs.String("role", "", "revoke all sessions holding this role (e.g. admin)")
	all := fs.Bool("all", false, "revoke every session (requires --yes)")
	yes := fs.Bool("yes", false, "confirm --all")
	if err := fs.Parse(args); err != nil {
		return true, nil
	}
	selected := 0
	for _, set := range []bool{*email != "", *subject != "", *role != "", *all} {
		if set {
			selected++
		}
	}
	if selected != 1 || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "sessions revoke: specify exactly one of --email, --subject, --role, --all")
		return true, nil
	}
	if *all && !*yes {
		fmt.Fprintln(os.Stderr, "sessions revoke: --all revokes every session; add --yes to confirm")
		return true, nil
	}
	if *role != "" && len(auth.RolesFromGroups([]string{auth.GroupPrefix + *role})) != 1 {
		fmt.Fprintf(os.Stderr, "sessions revoke: unknown role %q\n", *role)
		return true, nil
	}

	cfg, err := config.LoadAdmin(os.Getenv)
	if err != nil {
		return false, fmt.Errorf("config: %w", err)
	}
	logger := newLogger(cfg.LogLevel)
	pool, err := repository.Connect(ctx, cfg.DatabaseURL, repository.PoolOptions{
		MaxConns: 1, ApplicationName: "kubechaos-admin", RequireTLS: cfg.Environment != config.EnvDevelopment,
	})
	if err != nil {
		return false, err
	}
	defer pool.Close()

	n, err := repository.NewSessionStore(pool).RevokeSessions(ctx, repository.RevokeSelector{
		Email: *email, Subject: *subject, Role: *role, All: *all,
	})
	if err != nil {
		return false, fmt.Errorf("revoke sessions: %w", err)
	}
	selector := map[string]string{"email": *email, "subject": *subject, "role": *role}
	if *all {
		selector = map[string]string{"all": "true"}
	}
	// TODO(step 14): emit audit event auth.session.revoked (actor: OS user on control node).
	logger.Info("sessions revoked", slog.Any("selector", selector), slog.Int64("sessions_revoked", n),
		slog.String("os_user", os.Getenv("USER")))
	fmt.Printf("revoked %d session(s)\n", n)
	return false, nil
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
