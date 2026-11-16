package repository

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// newProvider builds a goose provider over the embedded control-plane migrations.
func newProvider(dsn string, o PoolOptions) (*goose.Provider, *sql.DB, error) {
	return newProviderFS(dsn, o, mustSub(migrationsFS, "migrations"))
}

// MigrateUpFS applies the migrations in fsys (used by the approval service's own database).
func MigrateUpFS(ctx context.Context, dsn string, o PoolOptions, fsys fs.FS, logger *slog.Logger) error {
	p, db, err := newProviderFS(dsn, o, fsys)
	if err != nil {
		return err
	}
	defer db.Close()
	results, err := p.Up(ctx)
	for _, r := range results {
		logger.InfoContext(ctx, "migration applied", slog.Int64("migration_version", r.Source.Version), slog.String("file", r.Source.Path))
	}
	if err != nil {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}

func newProviderFS(dsn string, o PoolOptions, fsys fs.FS) (*goose.Provider, *sql.DB, error) {
	cfg, err := ParsePoolConfig(dsn, o)
	if err != nil {
		return nil, nil, err
	}
	db := stdlib.OpenDB(*cfg.ConnConfig)
	p, err := goose.NewProvider(goose.DialectPostgres, db, fsys)
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("migration provider: %w", err)
	}
	return p, db, nil
}

// MigrateUp applies all pending migrations. Must be run with the migrator role.
func MigrateUp(ctx context.Context, dsn string, o PoolOptions, logger *slog.Logger) error {
	p, db, err := newProvider(dsn, o)
	if err != nil {
		return err
	}
	defer db.Close()
	results, err := p.Up(ctx)
	for _, r := range results {
		logger.InfoContext(ctx, "migration applied", slog.Int64("migration_version", r.Source.Version),
			slog.String("file", r.Source.Path), slog.Duration("duration", r.Duration))
	}
	if err != nil {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}

// MigrationStatus logs the state of every known migration.
func MigrationStatus(ctx context.Context, dsn string, o PoolOptions, logger *slog.Logger) error {
	p, db, err := newProvider(dsn, o)
	if err != nil {
		return err
	}
	defer db.Close()
	statuses, err := p.Status(ctx)
	if err != nil {
		return fmt.Errorf("migration status: %w", err)
	}
	for _, s := range statuses {
		logger.InfoContext(ctx, "migration", slog.Int64("migration_version", s.Source.Version),
			slog.String("file", s.Source.Path), slog.String("state", string(s.State)))
	}
	return nil
}
