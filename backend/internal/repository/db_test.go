package repository

import (
	"errors"
	"strings"
	"testing"
)

func TestParsePoolConfig_RequireTLS(t *testing.T) {
	insecure := []string{
		"postgres://u:p@db.example/kc?sslmode=disable",
		"postgres://u:p@db.example/kc?sslmode=allow",
		"postgres://u:p@db.example/kc?sslmode=prefer",
		"postgres://u:p@db.example/kc?sslmode=require",   // encrypts but does not verify the server
		"postgres://u:p@db.example/kc?sslmode=verify-ca", // does not verify the hostname
		"postgres://u:p@db.example/kc",                   // pgx default is prefer
	}
	for _, dsn := range insecure {
		if _, err := ParsePoolConfig(dsn, PoolOptions{RequireTLS: true}); !errors.Is(err, ErrInsecureDSN) {
			t.Errorf("%s: want ErrInsecureDSN, got %v", dsn, err)
		}
	}
	if _, err := ParsePoolConfig("postgres://u:p@db.example/kc?sslmode=verify-full", PoolOptions{RequireTLS: true}); err != nil {
		t.Errorf("verify-full must be accepted: %v", err)
	}
	if _, err := ParsePoolConfig("postgres://u:p@localhost/kc?sslmode=disable", PoolOptions{RequireTLS: false}); err != nil {
		t.Errorf("plaintext allowed when TLS not required (development): %v", err)
	}
}

func TestParsePoolConfig_HardensSession(t *testing.T) {
	cfg, err := ParsePoolConfig("postgres://u:p@localhost/kc?sslmode=disable", PoolOptions{MaxConns: 7, ApplicationName: "kubechaos-api"})
	if err != nil {
		t.Fatal(err)
	}
	rp := cfg.ConnConfig.RuntimeParams
	if cfg.MaxConns != 7 || rp["application_name"] != "kubechaos-api" || rp["statement_timeout"] == "" {
		t.Fatalf("unexpected config: maxConns=%d params=%v", cfg.MaxConns, rp)
	}
}

func TestParsePoolConfig_ErrorDoesNotLeakDSN(t *testing.T) {
	_, err := ParsePoolConfig("postgres://u:TopSecret@localhost:notaport/kc", PoolOptions{})
	if err == nil || strings.Contains(err.Error(), "TopSecret") {
		t.Fatalf("want sanitized error, got %v", err)
	}
}
