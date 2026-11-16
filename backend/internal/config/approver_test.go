package config

import (
	"strings"
	"testing"
)

func approverEnv() map[string]string {
	return map[string]string{
		"KUBECHAOS_ENV":                          "development",
		"KUBECHAOS_APPROVER_DATABASE_URL":        "postgres://approver_app:x@127.0.0.1/kubechaos_approval",
		"KUBECHAOS_APPROVER_PUBLIC_URL":          "http://localhost:4201",
		"KUBECHAOS_APPROVER_OIDC_ISSUER":         "http://localhost:8180/realms/kubechaos",
		"KUBECHAOS_APPROVER_OIDC_CLIENT_SECRET":  strings.Repeat("s", 32),
		"KUBECHAOS_APPROVER_SERVICE_TOKEN":       strings.Repeat("t", 32),
		"KUBECHAOS_APPROVER_SIGNING_SEED":        strings.Repeat("ab", 32),
		"KUBECHAOS_APPROVER_KID":                 "dev-1",
		"KUBECHAOS_APPROVER_CLUSTER_ID":          "dev-kind-01",
		"KUBECHAOS_APPROVER_CLUSTER_ENVIRONMENT": "development",
		"KUBECHAOS_APPROVER_ROUTES":              `{"demo": "/teams/demo/head-developers"}`,
	}
}

func TestLoadApprover(t *testing.T) {
	env := approverEnv()
	c, err := LoadApprover(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if c.Routes["demo"] != "/teams/demo/head-developers" || c.MinApprovals != 1 || len(c.SigningKey) != 64 || c.OIDCClientID != "kubechaos-approver" {
		t.Fatalf("%+v", c)
	}
}

func TestLoadApproverRejects(t *testing.T) {
	for key, bad := range map[string]string{
		"KUBECHAOS_APPROVER_SERVICE_TOKEN":       "short",
		"KUBECHAOS_APPROVER_SIGNING_SEED":        "abcd",
		"KUBECHAOS_APPROVER_KID":                 "bad kid!",
		"KUBECHAOS_APPROVER_ROUTES":              `{"demo": "no-leading-slash"}`,
		"KUBECHAOS_APPROVER_PUBLIC_URL":          "http://approver.example.com",
		"KUBECHAOS_APPROVER_CLUSTER_ENVIRONMENT": "prod",
		"KUBECHAOS_APPROVER_MIN_APPROVALS":       "9",
	} {
		env := approverEnv()
		env[key] = bad
		_, err := LoadApprover(func(k string) string { return env[k] })
		if err == nil || !strings.Contains(err.Error(), key[:len("KUBECHAOS_APPROVER_")]) && !strings.Contains(err.Error(), "production") {
			t.Errorf("%s=%q: expected an error, got %v", key, bad, err)
		}
		if err != nil && strings.Contains(err.Error(), strings.Repeat("t", 32)) {
			t.Error("secrets must never appear in errors")
		}
	}
}
