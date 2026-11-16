// Package config loads typed configuration from the environment and fails fast on
// anything missing or invalid. Secrets (DSNs) are never included in error messages.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
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

	// PublicURL is the origin browsers use to reach the SPA and API (same origin).
	PublicURL *url.URL
	// OIDC (Keycloak) confidential client. The secret is never logged.
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string

	// Cluster connector (optional). Without it, experiment endpoints return 503 (fail closed).
	KubeconfigPath string // the control-plane ServiceAccount's kubeconfig; never logged
	ClusterID      string
	ClusterName    string
}

// validURL enforces an absolute http(s) URL without credentials, query or fragment.
// Plain http is accepted only in development and only for loopback hosts.
func validURL(name, raw string, env Environment) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%s must be an absolute URL without credentials, query or fragment", name)
	}
	switch u.Scheme {
	case "https":
	case "http":
		h := u.Hostname()
		if env != EnvDevelopment || (h != "localhost" && h != "127.0.0.1" && h != "::1") {
			return nil, fmt.Errorf("%s must use https (http only allowed for loopback in development)", name)
		}
	default:
		return nil, fmt.Errorf("%s must use https", name)
	}
	return u, nil
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

	if v := getenv("KUBECHAOS_PUBLIC_URL"); v == "" {
		errs = append(errs, errors.New("KUBECHAOS_PUBLIC_URL is required"))
	} else if u, err := validURL("KUBECHAOS_PUBLIC_URL", v, env); err != nil {
		errs = append(errs, err)
	} else if u.Path != "" && u.Path != "/" {
		errs = append(errs, errors.New("KUBECHAOS_PUBLIC_URL must be an origin without a path"))
	} else {
		u.Path = ""
		c.PublicURL = u
	}
	c.OIDCIssuer = getenv("KUBECHAOS_OIDC_ISSUER")
	if c.OIDCIssuer == "" {
		errs = append(errs, errors.New("KUBECHAOS_OIDC_ISSUER is required"))
	} else if _, err := validURL("KUBECHAOS_OIDC_ISSUER", c.OIDCIssuer, env); err != nil {
		errs = append(errs, err)
	}
	c.OIDCClientID = getenv("KUBECHAOS_OIDC_CLIENT_ID")
	if c.OIDCClientID == "" {
		errs = append(errs, errors.New("KUBECHAOS_OIDC_CLIENT_ID is required"))
	}
	c.OIDCClientSecret = getenv("KUBECHAOS_OIDC_CLIENT_SECRET")
	if len(c.OIDCClientSecret) < 32 {
		errs = append(errs, errors.New("KUBECHAOS_OIDC_CLIENT_SECRET is required (min 32 characters)"))
	}
	c.KubeconfigPath = getenv("KUBECHAOS_KUBECONFIG")
	if c.KubeconfigPath != "" {
		c.ClusterID = getenv("KUBECHAOS_CLUSTER_ID")
		if !clusterIDRe.MatchString(c.ClusterID) {
			errs = append(errs, errors.New("KUBECHAOS_CLUSTER_ID must be a DNS-1123 label when KUBECHAOS_KUBECONFIG is set"))
		}
		c.ClusterName = withDefault(getenv("KUBECHAOS_CLUSTER_NAME"), c.ClusterID)
		if len(c.ClusterName) > 128 {
			errs = append(errs, errors.New("KUBECHAOS_CLUSTER_NAME must be at most 128 characters"))
		}
	}
	return c, errors.Join(errs...)
}

var clusterIDRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Admin is the configuration for break-glass admin commands (e.g. `sessions revoke`).
// They need only the database, so they keep working when the IdP or web tier is down.
type Admin struct {
	Environment Environment
	DatabaseURL string // app role; never logged
	LogLevel    slog.Level
}

// LoadAdmin reads admin-command configuration.
func LoadAdmin(getenv func(string) string) (Admin, error) {
	var errs []error
	env, err := parseEnvironment(getenv("KUBECHAOS_ENV"))
	errs = append(errs, err)
	c := Admin{Environment: env, DatabaseURL: getenv("KUBECHAOS_DATABASE_URL")}
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("KUBECHAOS_DATABASE_URL is required"))
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
