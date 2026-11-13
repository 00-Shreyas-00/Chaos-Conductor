// Package config loads typed configuration from the environment and fails fast on
// anything missing or invalid. Secrets (DSNs) are never included in error messages.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// Environment is the deployment environment of the control plane itself.
type Environment string

const (
	EnvDevelopment Environment = "development"
	EnvStaging     Environment = "staging"
	EnvProduction  Environment = "production"
)

func parseEnvironment(s string) (Environment, error) {
	switch e := Environment(s); e {
	case EnvDevelopment, EnvStaging, EnvProduction:
		return e, nil
	default:
		return "", fmt.Errorf("KUBECHAOS_ENV must be one of development|staging|production, got %q", s)
	}
}

// Server is the configuration for `kubechaos-api serve`.
type Server struct {
	Environment     Environment
	HTTPAddr        string
	DatabaseURL     string // app role (least privilege); never logged
	DBMaxConns      int32
	MaxBodyBytes    int64
	ShutdownTimeout time.Duration
	LogLevel        slog.Level
}

// Migrate is the configuration for `kubechaos-api migrate`.
type Migrate struct {
	Environment Environment
	DatabaseURL string // migrator role; never logged
	LogLevel    slog.Level
}

// LoadServer reads server configuration using getenv (os.Getenv in production, a map in tests).
func LoadServer(getenv func(string) string) (Server, error) {
	var errs []error
	env, err := parseEnvironment(getenv("KUBECHAOS_ENV"))
	errs = append(errs, err)

	c := Server{
		Environment:     env,
		HTTPAddr:        withDefault(getenv("KUBECHAOS_HTTP_ADDR"), "127.0.0.1:8080"),
		DatabaseURL:     getenv("KUBECHAOS_DATABASE_URL"),
		DBMaxConns:      10,
		MaxBodyBytes:    1 << 20, // 1 MiB
		ShutdownTimeout: 15 * time.Second,
	}
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("KUBECHAOS_DATABASE_URL is required"))
	}
	if v := getenv("KUBECHAOS_DB_MAX_CONNS"); v != "" {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil || n < 1 || n > 100 {
			errs = append(errs, errors.New("KUBECHAOS_DB_MAX_CONNS must be an integer in [1,100]"))
		} else {
			c.DBMaxConns = int32(n)
		}
	}
	c.LogLevel, err = parseLevel(getenv("KUBECHAOS_LOG_LEVEL"))
	errs = append(errs, err)
	return c, errors.Join(errs...)
}

// LoadMigrate reads migration configuration.
func LoadMigrate(getenv func(string) string) (Migrate, error) {
	var errs []error
	env, err := parseEnvironment(getenv("KUBECHAOS_ENV"))
	errs = append(errs, err)
	c := Migrate{Environment: env, DatabaseURL: getenv("KUBECHAOS_MIGRATE_DATABASE_URL")}
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("KUBECHAOS_MIGRATE_DATABASE_URL is required"))
	}
	c.LogLevel, err = parseLevel(getenv("KUBECHAOS_LOG_LEVEL"))
	errs = append(errs, err)
	return c, errors.Join(errs...)
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("KUBECHAOS_LOG_LEVEL must be debug|info|warn|error, got %q", s)
	}
}

func withDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
