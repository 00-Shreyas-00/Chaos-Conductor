package config

import (
	"log/slog"
	"maps"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

const testSecret = "0123456789abcdef0123456789abcdef"

func validServerEnv() map[string]string {
	return map[string]string{
		"KUBECHAOS_ENV":                "development",
		"KUBECHAOS_DATABASE_URL":       "postgres://u:p@h/db",
		"KUBECHAOS_PUBLIC_URL":         "http://localhost:4200",
		"KUBECHAOS_OIDC_ISSUER":        "http://localhost:8180/realms/kubechaos",
		"KUBECHAOS_OIDC_CLIENT_ID":     "kubechaos-api",
		"KUBECHAOS_OIDC_CLIENT_SECRET": testSecret,
	}
}

func with(overrides map[string]string) map[string]string {
	m := validServerEnv()
	maps.Copy(m, overrides)
	return m
}

func TestLoadServer_Valid(t *testing.T) {
	c, err := LoadServer(env(with(map[string]string{"KUBECHAOS_DB_MAX_CONNS": "5", "KUBECHAOS_LOG_LEVEL": "debug"})))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Environment != EnvDevelopment || c.DBMaxConns != 5 || c.LogLevel != slog.LevelDebug {
		t.Fatalf("unexpected config: %+v", c)
	}
	if c.HTTPAddr != "127.0.0.1:8080" {
		t.Fatalf("default listen address must be loopback, got %q", c.HTTPAddr)
	}
	if c.PublicURL.String() != "http://localhost:4200" {
		t.Fatalf("public url = %q", c.PublicURL)
	}
}

func TestLoadServer_FailsClosed(t *testing.T) {
	cases := map[string]map[string]string{
		"missing env":              {"KUBECHAOS_ENV": ""},
		"unknown env":              {"KUBECHAOS_ENV": "prod"},
		"missing dsn":              {"KUBECHAOS_DATABASE_URL": ""},
		"bad max conns":            {"KUBECHAOS_DB_MAX_CONNS": "0"},
		"non-numeric conns":        {"KUBECHAOS_DB_MAX_CONNS": "lots"},
		"unknown log level":        {"KUBECHAOS_LOG_LEVEL": "trace"},
		"missing public url":       {"KUBECHAOS_PUBLIC_URL": ""},
		"public url with path":     {"KUBECHAOS_PUBLIC_URL": "http://localhost:4200/app"},
		"public url with creds":    {"KUBECHAOS_PUBLIC_URL": "http://u:p@localhost:4200"},
		"public url non-loopback":  {"KUBECHAOS_PUBLIC_URL": "http://chaos.example.com"},
		"public url bad scheme":    {"KUBECHAOS_PUBLIC_URL": "javascript://localhost"},
		"missing issuer":           {"KUBECHAOS_OIDC_ISSUER": ""},
		"issuer with query":        {"KUBECHAOS_OIDC_ISSUER": "http://localhost:8180/realms/x?a=b"},
		"missing client id":        {"KUBECHAOS_OIDC_CLIENT_ID": ""},
		"missing client secret":    {"KUBECHAOS_OIDC_CLIENT_SECRET": ""},
		"short client secret":      {"KUBECHAOS_OIDC_CLIENT_SECRET": "short"},
		"staging with http public": {"KUBECHAOS_ENV": "staging"},
		"production with http idp": {"KUBECHAOS_ENV": "production", "KUBECHAOS_PUBLIC_URL": "https://chaos.example.com"},
	}
	for name, overrides := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadServer(env(with(overrides))); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestLoadServer_ProductionHTTPS(t *testing.T) {
	_, err := LoadServer(env(with(map[string]string{
		"KUBECHAOS_ENV":         "production",
		"KUBECHAOS_PUBLIC_URL":  "https://chaos.example.com",
		"KUBECHAOS_OIDC_ISSUER": "https://idp.example.com/realms/kubechaos",
	})))
	if err != nil {
		t.Fatalf("https config must be accepted in production: %v", err)
	}
}

func TestErrorsNeverContainSecrets(t *testing.T) {
	_, err := LoadServer(env(with(map[string]string{
		"KUBECHAOS_ENV":                "nope",
		"KUBECHAOS_DATABASE_URL":       "postgres://user:SuperSecret@h/db",
		"KUBECHAOS_OIDC_CLIENT_SECRET": "ClientSecretValue",
	})))
	if err == nil || strings.Contains(err.Error(), "SuperSecret") || strings.Contains(err.Error(), "ClientSecretValue") {
		t.Fatalf("error must exist and must not leak secrets: %v", err)
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
