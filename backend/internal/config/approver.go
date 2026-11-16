package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Approver is the configuration for `kubechaos-approver serve`. Every variable is prefixed
// KUBECHAOS_APPROVER_ so the approval service never accidentally reads control-plane secrets.
type Approver struct {
	Environment        Environment
	HTTPAddr           string
	DatabaseURL        string // approver_app role; never logged
	MigrateDatabaseURL string // approver_migrator role; never logged
	LogLevel           slog.Level
	PublicURL          *url.URL

	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string

	ServiceToken string             // bearer token the control plane presents; never logged
	SigningKey   ed25519.PrivateKey // derived from a 32-byte hex seed; never logged
	KID          string

	ClusterID    string
	ClusterEnv   string            // environment of the target cluster (must match its ChaosPolicy)
	Routes       map[string]string // namespace -> approver group path
	MinApprovals int
}

var (
	kidRe   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	groupRe = regexp.MustCompile(`^/[A-Za-z0-9 ._/-]{1,254}$`)
)

// LoadApproverKey loads only what `pubkey` needs (seed and kid).
func LoadApproverKey(getenv func(string) string) (ed25519.PrivateKey, string, error) {
	var errs []error
	seed, err := hex.DecodeString(getenv("KUBECHAOS_APPROVER_SIGNING_SEED"))
	if err != nil || len(seed) != ed25519.SeedSize {
		errs = append(errs, errors.New("KUBECHAOS_APPROVER_SIGNING_SEED must be 64 hex characters (32 bytes)"))
	}
	kid := getenv("KUBECHAOS_APPROVER_KID")
	if !kidRe.MatchString(kid) {
		errs = append(errs, errors.New("KUBECHAOS_APPROVER_KID must match [A-Za-z0-9._-]{1,64}"))
	}
	if len(errs) > 0 {
		return nil, "", errors.Join(errs...)
	}
	return ed25519.NewKeyFromSeed(seed), kid, nil
}

// LoadApproverMigrate reads the migrator DSN.
func LoadApproverMigrate(getenv func(string) string) (Approver, error) {
	var errs []error
	env, err := parseEnvironment(getenv("KUBECHAOS_ENV"))
	errs = append(errs, err)
	c := Approver{Environment: env, MigrateDatabaseURL: getenv("KUBECHAOS_APPROVER_MIGRATE_DATABASE_URL")}
	if c.MigrateDatabaseURL == "" {
		errs = append(errs, errors.New("KUBECHAOS_APPROVER_MIGRATE_DATABASE_URL is required"))
	}
	c.LogLevel, err = parseLevel(getenv("KUBECHAOS_LOG_LEVEL"))
	errs = append(errs, err)
	return c, errors.Join(errs...)
}

// LoadApprover reads the server configuration and fails fast on anything missing.
func LoadApprover(getenv func(string) string) (Approver, error) {
	var errs []error
	env, err := parseEnvironment(getenv("KUBECHAOS_ENV"))
	errs = append(errs, err)
	c := Approver{
		Environment:  env,
		HTTPAddr:     withDefault(getenv("KUBECHAOS_APPROVER_HTTP_ADDR"), "127.0.0.1:8081"),
		DatabaseURL:  getenv("KUBECHAOS_APPROVER_DATABASE_URL"),
		MinApprovals: 1,
	}
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("KUBECHAOS_APPROVER_DATABASE_URL is required"))
	}
	c.LogLevel, err = parseLevel(getenv("KUBECHAOS_LOG_LEVEL"))
	errs = append(errs, err)

	if v := getenv("KUBECHAOS_APPROVER_PUBLIC_URL"); v == "" {
		errs = append(errs, errors.New("KUBECHAOS_APPROVER_PUBLIC_URL is required"))
	} else if u, err := validURL("KUBECHAOS_APPROVER_PUBLIC_URL", v, env); err != nil {
		errs = append(errs, err)
	} else if u.Path != "" && u.Path != "/" {
		errs = append(errs, errors.New("KUBECHAOS_APPROVER_PUBLIC_URL must be an origin without a path"))
	} else {
		u.Path = ""
		c.PublicURL = u
	}
	c.OIDCIssuer = getenv("KUBECHAOS_APPROVER_OIDC_ISSUER")
	if c.OIDCIssuer == "" {
		errs = append(errs, errors.New("KUBECHAOS_APPROVER_OIDC_ISSUER is required"))
	} else if _, err := validURL("KUBECHAOS_APPROVER_OIDC_ISSUER", c.OIDCIssuer, env); err != nil {
		errs = append(errs, err)
	}
	c.OIDCClientID = withDefault(getenv("KUBECHAOS_APPROVER_OIDC_CLIENT_ID"), "kubechaos-approver")
	c.OIDCClientSecret = getenv("KUBECHAOS_APPROVER_OIDC_CLIENT_SECRET")
	if len(c.OIDCClientSecret) < 32 {
		errs = append(errs, errors.New("KUBECHAOS_APPROVER_OIDC_CLIENT_SECRET is required (min 32 characters)"))
	}
	c.ServiceToken = getenv("KUBECHAOS_APPROVER_SERVICE_TOKEN")
	if len(c.ServiceToken) < 32 {
		errs = append(errs, errors.New("KUBECHAOS_APPROVER_SERVICE_TOKEN is required (min 32 characters)"))
	}
	key, kid, err := LoadApproverKey(getenv)
	errs = append(errs, err)
	c.SigningKey, c.KID = key, kid

	c.ClusterID = getenv("KUBECHAOS_APPROVER_CLUSTER_ID")
	if !clusterIDRe.MatchString(c.ClusterID) {
		errs = append(errs, errors.New("KUBECHAOS_APPROVER_CLUSTER_ID must be a DNS-1123 label"))
	}
	c.ClusterEnv = getenv("KUBECHAOS_APPROVER_CLUSTER_ENVIRONMENT")
	if _, err := parseEnvironment(c.ClusterEnv); err != nil {
		errs = append(errs, errors.New("KUBECHAOS_APPROVER_CLUSTER_ENVIRONMENT must be development|staging|production"))
	}
	if err := json.Unmarshal([]byte(getenv("KUBECHAOS_APPROVER_ROUTES")), &c.Routes); err != nil || len(c.Routes) == 0 {
		errs = append(errs, errors.New(`KUBECHAOS_APPROVER_ROUTES must be a JSON object {"namespace": "/group/path"}`))
	}
	for ns, g := range c.Routes {
		if !clusterIDRe.MatchString(ns) || !groupRe.MatchString(g) || strings.Contains(g, "//") {
			errs = append(errs, fmt.Errorf("KUBECHAOS_APPROVER_ROUTES: invalid route %q -> %q", ns, g))
		}
	}
	if v := getenv("KUBECHAOS_APPROVER_MIN_APPROVALS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 5 {
			errs = append(errs, errors.New("KUBECHAOS_APPROVER_MIN_APPROVALS must be in [1,5]"))
		} else {
			c.MinApprovals = n
		}
	}
	if c.ClusterEnv == "production" && c.MinApprovals < 1 {
		errs = append(errs, errors.New("production requires at least one approval"))
	}
	return c, errors.Join(errs...)
}
