// Package repository owns PostgreSQL access: connection pools, migrations and the
// startup privilege self-check.
package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PoolOptions configures a connection pool.
type PoolOptions struct {
	MaxConns        int32
	ApplicationName string
	// RequireTLS rejects DSNs that do not verify the server certificate
	// (sslmode=verify-full). Must be true outside development.
	RequireTLS bool
}

// ErrInsecureDSN is returned when TLS verification is required but not configured.
var ErrInsecureDSN = errors.New("database DSN must use sslmode=verify-full outside development")

// ParsePoolConfig parses and hardens a pool configuration without connecting.
// Errors never include the DSN.
func ParsePoolConfig(dsn string, o PoolOptions) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("invalid database DSN") // pgx errors can echo the DSN
	}
	if o.RequireTLS {
		tls := cfg.ConnConfig.TLSConfig
		if tls == nil || tls.InsecureSkipVerify || len(cfg.ConnConfig.Fallbacks) > 0 {
			// Fallbacks indicate sslmode=prefer/allow, which can silently downgrade to plaintext.
			return nil, ErrInsecureDSN
		}
	}
	if o.MaxConns > 0 {
		cfg.MaxConns = o.MaxConns
	}
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.ConnConfig.ConnectTimeout = 5 * time.Second
	rp := cfg.ConnConfig.RuntimeParams
	rp["application_name"] = o.ApplicationName
	rp["statement_timeout"] = "10000"                   // ms
	rp["idle_in_transaction_session_timeout"] = "30000" // ms
	return cfg, nil
}

// Connect opens a pool and verifies connectivity.
func Connect(ctx context.Context, dsn string, o PoolOptions) (*pgxpool.Pool, error) {
	cfg, err := ParsePoolConfig(dsn, o)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return pool, nil
}
