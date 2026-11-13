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
)

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

func TestAuditIsAppendOnlyForApp(t *testing.T) {
	ctx := context.Background()
	app := pool(t, "KUBECHAOS_TEST_APP_URL")
	h := randHash(t)
	if err := insertAudit(ctx, app, randHash(t), h); err != nil {
		t.Fatalf("app must be able to append: %v", err)
	}
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
	h := randHash(t)
	if err := insertAudit(ctx, app, randHash(t), h); err != nil {
		t.Fatal(err)
	}
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
	prev := randHash(t)
	if err := insertAudit(ctx, app, prev, randHash(t)); err != nil {
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
