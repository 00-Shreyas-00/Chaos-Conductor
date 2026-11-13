package config

import (
	"log/slog"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestLoadServer_Valid(t *testing.T) {
	c, err := LoadServer(env(map[string]string{
		"KUBECHAOS_ENV":          "development",
		"KUBECHAOS_DATABASE_URL": "postgres://u:p@h/db",
		"KUBECHAOS_DB_MAX_CONNS": "5",
		"KUBECHAOS_LOG_LEVEL":    "debug",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Environment != EnvDevelopment || c.DBMaxConns != 5 || c.LogLevel != slog.LevelDebug {
		t.Fatalf("unexpected config: %+v", c)
	}
	if c.HTTPAddr != "127.0.0.1:8080" {
		t.Fatalf("default listen address must be loopback, got %q", c.HTTPAddr)
	}
}

func TestLoadServer_FailsClosed(t *testing.T) {
	cases := map[string]map[string]string{
		"missing env":       {"KUBECHAOS_DATABASE_URL": "postgres://x"},
		"unknown env":       {"KUBECHAOS_ENV": "prod", "KUBECHAOS_DATABASE_URL": "postgres://x"},
		"missing dsn":       {"KUBECHAOS_ENV": "development"},
		"bad max conns":     {"KUBECHAOS_ENV": "development", "KUBECHAOS_DATABASE_URL": "postgres://x", "KUBECHAOS_DB_MAX_CONNS": "0"},
		"non-numeric conns": {"KUBECHAOS_ENV": "development", "KUBECHAOS_DATABASE_URL": "postgres://x", "KUBECHAOS_DB_MAX_CONNS": "lots"},
		"unknown log level": {"KUBECHAOS_ENV": "development", "KUBECHAOS_DATABASE_URL": "postgres://x", "KUBECHAOS_LOG_LEVEL": "trace"},
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadServer(env(m)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestErrorsNeverContainSecrets(t *testing.T) {
	_, err := LoadServer(env(map[string]string{
		"KUBECHAOS_ENV":          "nope",
		"KUBECHAOS_DATABASE_URL": "postgres://user:SuperSecret@h/db",
	}))
	if err == nil || strings.Contains(err.Error(), "SuperSecret") {
		t.Fatalf("error must exist and must not leak DSN: %v", err)
	}
}

func TestLoadMigrate(t *testing.T) {
	if _, err := LoadMigrate(env(map[string]string{"KUBECHAOS_ENV": "development"})); err == nil {
		t.Fatal("expected error for missing migrate DSN")
	}
	c, err := LoadMigrate(env(map[string]string{"KUBECHAOS_ENV": "staging", "KUBECHAOS_MIGRATE_DATABASE_URL": "postgres://m"}))
	if err != nil || c.Environment != EnvStaging {
		t.Fatalf("unexpected: %+v %v", c, err)
	}
}
