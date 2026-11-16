//go:build integration

// Integration tests against a real PostgreSQL initialised by deploy/postgres/init.
// Run with `make test-integration` (inside the devcontainer, after `make dev`).
package repository

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kubechaos/kubechaos/backend/internal/audit"
	"github.com/kubechaos/kubechaos/backend/internal/experiments"
	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
)

func TestExperimentStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	app := pool(t, "KUBECHAOS_TEST_APP_URL")
	store := NewExperimentStore(app, audit.NewWriter(app))
	if err := store.EnsureCluster(ctx, "it-cluster", "Integration", "development"); err != nil {
		t.Fatal(err)
	}
	var identity string
	if err := app.QueryRow(ctx, `INSERT INTO app.identities (issuer, subject) VALUES ('https://idp.it', $1) RETURNING id::text`, randHashHex(t)).Scan(&identity); err != nil {
		t.Fatal(err)
	}
	id := "11111111-2222-4333-8444-" + randHashHex(t)[:12]
	exp := &experiments.Experiment{ID: id, Name: "exp-" + randHashHex(t)[:12], ClusterID: "it-cluster", RequesterID: identity,
		Spec: chaosv1.ChaosExperimentSpec{ClusterID: "it-cluster", MaxDuration: "1m"}, SpecSHA256: strings.Repeat("a", 64),
		Risk: chaosv1.RiskMedium, State: experiments.StateSubmitting}
	if err := store.CreateWithAudit(ctx, exp, audit.Event{Action: "experiment.create", ExperimentID: id, Decision: "allow"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	score := int32(80)
	evs, err := store.ApplyClusterStatus(ctx, id, &chaosv1.ChaosExperimentStatus{Phase: chaosv1.PhaseCompleted, Result: "Passed", Score: &score},
		[]experiments.TimelineEvent{{Type: "Started", Message: "started"}, {Type: "Completed", Message: "done"}})
	if err != nil || len(evs) != 2 || evs[0].ID == 0 {
		t.Fatalf("apply: %v %+v", err, evs)
	}
	got, err := store.Get(ctx, id)
	if err != nil || got.Phase != "Completed" || *got.Score != 80 || got.Status == nil || got.RequesterIssuer != "https://idp.it" {
		t.Fatalf("get: %+v %v", got, err)
	}
	if _, err := store.Get(ctx, "not-a-uuid"); err != experiments.ErrNotFound {
		t.Fatalf("invalid id must be not found: %v", err)
	}
	// Atomicity: an invalid audit event aborts the experiment insert too.
	bad := *exp
	bad.ID, bad.Name = "11111111-2222-4333-8444-"+randHashHex(t)[:12], "exp-"+randHashHex(t)[:12]
	if err := store.CreateWithAudit(ctx, &bad, audit.Event{Action: "INVALID ACTION"}); err == nil {
		t.Fatal("invalid audit event must fail")
	}
	if _, err := store.Get(ctx, bad.ID); err != experiments.ErrNotFound {
		t.Fatal("experiment must not exist when its audit event failed")
	}
	if _, err := app.Exec(ctx, `DELETE FROM app.experiments WHERE id = $1`, id); err == nil {
		t.Fatal("app role must not delete experiment history")
	}
}

func dsn(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Fatalf("%s not set", key)
	}
	return v
}

func pool(t *testing.T, key string) *pgxpool.Pool {
	t.Helper()
	p, err := Connect(context.Background(), dsn(t, key), PoolOptions{ApplicationName: "integration-test"})
	if err != nil {
		t.Fatalf("connect %s: %v", key, err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestMain(m *testing.M) {
	// Apply migrations once, as the migrator, before any test (idempotent).
	ctx := context.Background()
	if err := MigrateUp(ctx, os.Getenv("KUBECHAOS_TEST_MIGRATOR_URL"), PoolOptions{ApplicationName: "integration-test"},
		slog.New(slog.NewJSONHandler(io.Discard, nil))); err != nil {
		slog.Error("migrate", slog.Any("error", err))
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func insertAudit(ctx context.Context, p *pgxpool.Pool, prev, hash []byte) error {
	_, err := p.Exec(ctx, `INSERT INTO audit.events (action, prev_hash, hash) VALUES ('test.event', $1, $2)`, prev, hash)
	return err
}

func randHash(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := io.ReadFull(randReader, b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAppRolePassesLeastPrivilegeCheck(t *testing.T) {
	if err := VerifyLeastPrivilege(context.Background(), pool(t, "KUBECHAOS_TEST_APP_URL")); err != nil {
		t.Fatalf("app role should pass: %v", err)
	}
}

func TestMigratorRoleFailsLeastPrivilegeCheck(t *testing.T) {
	err := VerifyLeastPrivilege(context.Background(), pool(t, "KUBECHAOS_TEST_MIGRATOR_URL"))
	if err == nil || !strings.Contains(err.Error(), "owns the database") {
		t.Fatalf("migrator must be refused, got %v", err)
	}
}

// appendEvent appends a valid chained event with the real writer and returns its hash.
func appendEvent(t *testing.T, app *pgxpool.Pool, action string) []byte {
	t.Helper()
	if err := audit.NewWriter(app).Append(context.Background(), audit.Event{Action: action, ActorSubject: "integration-test"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	var h []byte
	if err := app.QueryRow(context.Background(), `SELECT hash FROM audit.events ORDER BY seq DESC LIMIT 1`).Scan(&h); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestAuditChainVerifies(t *testing.T) {
	ctx := context.Background()
	app := pool(t, "KUBECHAOS_TEST_APP_URL")
	for i := 0; i < 3; i++ {
		appendEvent(t, app, "test.chain")
	}
	res, err := audit.Verify(ctx, app)
	if err != nil || res.Events < 3 {
		t.Fatalf("chain must verify: %+v %v", res, err)
	}
	recs, err := audit.List(ctx, app, 2, 0)
	if err != nil || len(recs) != 2 || recs[0].Seq <= recs[1].Seq || recs[0].Action != "test.chain" {
		t.Fatalf("list: %+v %v", recs, err)
	}
}

func TestAuditConcurrentAppendsStayLinear(t *testing.T) {
	ctx := context.Background()
	app := pool(t, "KUBECHAOS_TEST_APP_URL")
	w := audit.NewWriter(app)
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		go func() { errs <- w.Append(ctx, audit.Event{Action: "test.concurrent"}) }()
	}
	for i := 0; i < 20; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent append: %v", err)
		}
	}
	if _, err := audit.Verify(ctx, app); err != nil {
		t.Fatalf("chain must stay linear under concurrency: %v", err)
	}
}

func TestAuditIsAppendOnlyForApp(t *testing.T) {
	ctx := context.Background()
	app := pool(t, "KUBECHAOS_TEST_APP_URL")
	h := appendEvent(t, app, "test.appendonly")
	for name, sql := range map[string]string{
		"update":   `UPDATE audit.events SET result = 'tampered' WHERE hash = $1`,
		"delete":   `DELETE FROM audit.events WHERE hash = $1`,
		"truncate": `TRUNCATE audit.events`,
	} {
		args := []any{h}
		if name == "truncate" {
			args = nil
		}
		if _, err := app.Exec(ctx, sql, args...); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("app %s must be denied by privileges, got %v", name, err)
		}
	}
}

// Even the owner (migrator) cannot modify audit rows: the trigger is a second barrier.
func TestAuditTriggerBlocksOwner(t *testing.T) {
	ctx := context.Background()
	app := pool(t, "KUBECHAOS_TEST_APP_URL")
	owner := pool(t, "KUBECHAOS_TEST_MIGRATOR_URL")
	h := appendEvent(t, app, "test.trigger")
	for name, sql := range map[string]string{
		"update":   `UPDATE audit.events SET result = 'tampered' WHERE hash = $1`,
		"delete":   `DELETE FROM audit.events WHERE hash = $1`,
		"truncate": `TRUNCATE audit.events`,
	} {
		args := []any{h}
		if name == "truncate" {
			args = nil
		}
		if _, err := owner.Exec(ctx, sql, args...); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("owner %s must be rejected by trigger, got %v", name, err)
		}
	}
}

func TestAuditChainCannotFork(t *testing.T) {
	ctx := context.Background()
	app := pool(t, "KUBECHAOS_TEST_APP_URL")
	appendEvent(t, app, "test.fork")
	var prev []byte // the head's predecessor: already claimed by the head
	if err := app.QueryRow(ctx, `SELECT prev_hash FROM audit.events ORDER BY seq DESC LIMIT 1`).Scan(&prev); err != nil {
		t.Fatal(err)
	}
	if err := insertAudit(ctx, app, prev, randHash(t)); err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("second event with the same prev_hash must be rejected, got %v", err)
	}
	if err := insertAudit(ctx, app, bytes.Repeat([]byte{1}, 31), randHash(t)); err == nil {
		t.Fatal("prev_hash of wrong length must be rejected")
	}
}

func TestAuditorIsReadOnly(t *testing.T) {
	ctx := context.Background()
	auditor := pool(t, "KUBECHAOS_TEST_AUDITOR_URL")
	var n int
	if err := auditor.QueryRow(ctx, `SELECT count(*) FROM audit.events`).Scan(&n); err != nil {
		t.Fatalf("auditor must read audit: %v", err)
	}
	if err := insertAudit(ctx, auditor, randHash(t), randHash(t)); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("auditor insert must be denied, got %v", err)
	}
	if _, err := auditor.Exec(ctx, `SELECT 1 FROM app.identities`); err == nil {
		t.Fatal("auditor must not read application tables")
	}
}

func TestAppCannotDeleteOrAlterAppTables(t *testing.T) {
	ctx := context.Background()
	app := pool(t, "KUBECHAOS_TEST_APP_URL")
	if _, err := app.Exec(ctx, `INSERT INTO app.identities (issuer, subject) VALUES ('https://idp.test', $1)`, randHashHex(t)); err != nil {
		t.Fatalf("app insert identity: %v", err)
	}
	for _, sql := range []string{
		`DELETE FROM app.identities`,
		`DELETE FROM app.clusters`,
		`ALTER TABLE app.identities ADD COLUMN pwned text`,
		`CREATE TABLE app.pwned (i int)`,
		`DROP TABLE audit.events`,
	} {
		if _, err := app.Exec(ctx, sql); err == nil {
			t.Errorf("app must be denied: %s", sql)
		}
	}
}

func TestClusterIDAndEnvironmentConstraints(t *testing.T) {
	ctx := context.Background()
	app := pool(t, "KUBECHAOS_TEST_APP_URL")
	bad := [][2]string{{"Prod_Cluster", "production"}, {"ok-id", "prod"}, {"-leading", "development"}}
	for _, c := range bad {
		if _, err := app.Exec(ctx, `INSERT INTO app.clusters (id, display_name, environment) VALUES ($1, 'x', $2)`, c[0], c[1]); err == nil {
			t.Errorf("must reject cluster %v", c)
		}
	}
}
