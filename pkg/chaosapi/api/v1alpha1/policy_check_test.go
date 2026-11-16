package v1alpha1

import (
	"strings"
	"testing"
)

func policy() *ChaosPolicy {
	return &ChaosPolicy{Spec: ChaosPolicySpec{
		Environment: "development", AllowedFaults: []FaultType{FaultPodKill}, AllowedNamespaces: []string{"payments"},
		Limits:   PolicyLimits{MaxPodKillCount: 2, MaxDuration: "5m", MaxConcurrentExperiments: 1},
		Approval: ApprovalPolicy{Required: ApprovalNever},
	}}
}

func TestCheckPolicy(t *testing.T) {
	s := validSpec()
	if v := CheckPolicy(&s, policy(), "development"); len(v) != 0 {
		t.Fatalf("permitted spec rejected: %+v", v)
	}
	cases := map[string]struct {
		spec   func(*ChaosExperimentSpec)
		pol    func(*ChaosPolicy)
		env    string
		expect string
	}{
		"no policy":             {pol: nil, expect: "no ChaosPolicy"},
		"environment mismatch":  {env: "production", expect: "policy is for"},
		"fault not allowed":     {pol: func(p *ChaosPolicy) { p.Spec.AllowedFaults = nil }, expect: "not allowed by policy"},
		"namespace not allowed": {spec: func(s *ChaosExperimentSpec) { s.Steps[0].Fault.Target.Namespace = "ledger" }, expect: `"ledger" is not allowed`},
		"count over policy":     {spec: func(s *ChaosExperimentSpec) { s.Steps[0].Fault.PodKill.Count = 3 }, expect: "exceeds the policy limit of 2"},
		"maxDuration over":      {spec: func(s *ChaosExperimentSpec) { s.MaxDuration = "10m" }, expect: "exceeds the policy limit of 5m"},
		"prometheus unavailable": {spec: func(s *ChaosExperimentSpec) {
			s.SuccessCriteria = []Criterion{{Metric: MetricHTTPErrorRate, Operator: "lt", Value: "5"}}
		}, expect: "Prometheus provider"},
		"criterion target ns": {spec: func(s *ChaosExperimentSpec) {
			s.SuccessCriteria = []Criterion{{Metric: MetricAvailableReplicas, Operator: "ge", Value: "1", Target: &Target{Namespace: "ledger"}}}
		}, expect: "ledger"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := validSpec()
			if c.spec != nil {
				c.spec(&s)
			}
			var p *ChaosPolicy
			if name != "no policy" {
				p = policy()
				if c.pol != nil {
					c.pol(p)
				}
			}
			env := "development"
			if c.env != "" {
				env = c.env
			}
			v := CheckPolicy(&s, p, env)
			joined := ""
			for _, x := range v {
				joined += x.Message + "; "
			}
			if !strings.Contains(joined, c.expect) {
				t.Fatalf("violations %q do not mention %q", joined, c.expect)
			}
		})
	}
}

func TestApprovalRequired(t *testing.T) {
	s := validSpec()
	p := policy()
	if ApprovalRequired(&s, p) {
		t.Fatal("Never: no approval needed")
	}
	if !ApprovalRequired(&s, nil) {
		t.Fatal("no policy: fail closed")
	}
	p.Spec.Approval.Required = ApprovalAlways
	if !ApprovalRequired(&s, p) {
		t.Fatal("Always")
	}
	p.Spec.Approval = ApprovalPolicy{Required: ApprovalRiskAtLeast, RiskAtLeast: RiskHigh}
	if ApprovalRequired(&s, p) {
		t.Fatal("count 1 is Medium < High")
	}
	s.Steps[0].Fault.PodKill.Count = 2
	if !ApprovalRequired(&s, p) {
		t.Fatal("count 2 is High")
	}
	p.Spec.Approval.Required = ApprovalNever
	p.Spec.Environment = "production"
	if !ApprovalRequired(&s, p) {
		t.Fatal("production always requires approval, whatever the policy says")
	}
	p.Spec.Environment = "development"
	p.Spec.Approval.Required = "Sometimes"
	if !ApprovalRequired(&s, p) {
		t.Fatal("unknown requirement: fail closed")
	}
}

func TestCriteriaValidation(t *testing.T) {
	s := validSpec()
	s.SuccessCriteria = []Criterion{
		{Metric: MetricAvailableReplicas, Operator: "ge", Value: "3", Weight: 2},
		{Metric: MetricRecoveryTime, Operator: "lt", Value: "30s"},
		{Metric: MetricReadyRatio, Operator: "eq", Value: "100"},
	}
	if errs := ValidateSpec(&s); len(errs) != 0 {
		t.Fatalf("valid criteria rejected: %v", errs.ToAggregate())
	}
	bad := []Criterion{
		{Metric: "cpu_usage", Operator: "lt", Value: "1"},
		{Metric: MetricRecoveryTime, Operator: "lt", Value: "30"},
		{Metric: MetricReadyRatio, Operator: "ge", Value: "150"},
		{Metric: MetricAvailableReplicas, Operator: "approx", Value: "3"},
		{Metric: MetricAvailableReplicas, Operator: "ge", Value: "rate(http_requests_total[5m])"},
		{Metric: MetricAvailableReplicas, Operator: "ge", Value: "1", Target: &Target{Namespace: "kube-system", Selector: map[string]LabelValue{"a": "b"}}},
	}
	for _, c := range bad {
		s := validSpec()
		s.SuccessCriteria = []Criterion{c}
		if errs := ValidateSpec(&s); len(errs) == 0 {
			t.Errorf("criterion %+v must be rejected", c)
		}
	}
}
