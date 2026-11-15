package v1alpha1

import (
	"strings"
	"testing"
)

func i32(v int32) *int32 { return &v }

func validSpec() ChaosExperimentSpec {
	return ChaosExperimentSpec{
		ClusterID:   "dev-kind-01",
		RequestedBy: Requester{Issuer: "http://localhost:8180/realms/kubechaos", Subject: "alice"},
		MaxDuration: "2m",
		Steps: []Step{
			{Fault: &FaultStep{
				Type:    FaultPodKill,
				Target:  Target{Namespace: "payments", Selector: map[string]LabelValue{"app": "payment-api"}},
				PodKill: &PodKillParams{Count: 1, GracePeriodSeconds: i32(0)},
			}},
			{Wait: &WaitStep{Duration: "30s"}},
		},
	}
}

func TestValidateSpecAcceptsValid(t *testing.T) {
	s := validSpec()
	if errs := ValidateSpec(&s); len(errs) != 0 {
		t.Fatalf("valid spec rejected: %v", errs.ToAggregate())
	}
}

func TestValidateSpecRejects(t *testing.T) {
	cases := map[string]struct {
		mutate func(*ChaosExperimentSpec)
		want   string // substring of the error
	}{
		"bad cluster id":        {func(s *ChaosExperimentSpec) { s.ClusterID = "Prod_1" }, "spec.clusterID"},
		"missing subject":       {func(s *ChaosExperimentSpec) { s.RequestedBy.Subject = "" }, "requestedBy.subject"},
		"maxDuration too long":  {func(s *ChaosExperimentSpec) { s.MaxDuration = "2h" }, "between 10s and 1h"},
		"maxDuration too short": {func(s *ChaosExperimentSpec) { s.MaxDuration = "5s" }, "between 10s and 1h"},
		"maxDuration go syntax": {func(s *ChaosExperimentSpec) { s.MaxDuration = "1.5h" }, "duration like"},
		"maxDuration negative":  {func(s *ChaosExperimentSpec) { s.MaxDuration = "-1m" }, "duration like"},
		"no steps":              {func(s *ChaosExperimentSpec) { s.Steps = nil }, "at least one step"},
		"only waits":            {func(s *ChaosExperimentSpec) { s.Steps = s.Steps[1:] }, "at least one fault"},
		"too many steps": {func(s *ChaosExperimentSpec) {
			for len(s.Steps) <= MaxSteps {
				s.Steps = append(s.Steps, Step{Wait: &WaitStep{Duration: "1s"}})
			}
		}, "Too many"},
		"step with both":         {func(s *ChaosExperimentSpec) { s.Steps[0].Wait = &WaitStep{Duration: "1s"} }, "exactly one of fault or wait"},
		"empty step":             {func(s *ChaosExperimentSpec) { s.Steps[1].Wait = nil }, "exactly one of fault or wait"},
		"wait too long":          {func(s *ChaosExperimentSpec) { s.Steps[1].Wait.Duration = "11m" }, "between 1s and 10m"},
		"waits exceed maxDur":    {func(s *ChaosExperimentSpec) { s.MaxDuration = "30s" }, "total wait time"},
		"unknown fault type":     {func(s *ChaosExperimentSpec) { s.Steps[0].Fault.Type = "ShellCommand" }, "Unsupported value"},
		"podkill without params": {func(s *ChaosExperimentSpec) { s.Steps[0].Fault.PodKill = nil }, "required for type PodKill"},
		"count zero":             {func(s *ChaosExperimentSpec) { s.Steps[0].Fault.PodKill.Count = 0 }, "must be 1-10"},
		"count over cap":         {func(s *ChaosExperimentSpec) { s.Steps[0].Fault.PodKill.Count = 10000 }, "must be 1-10"},
		"grace too long":         {func(s *ChaosExperimentSpec) { s.Steps[0].Fault.PodKill.GracePeriodSeconds = i32(301) }, "must be 0-300"},
		"protected kube-system":  {func(s *ChaosExperimentSpec) { s.Steps[0].Fault.Target.Namespace = "kube-system" }, "protected"},
		"protected own ns":       {func(s *ChaosExperimentSpec) { s.Steps[0].Fault.Target.Namespace = "kubechaos-system" }, "protected"},
		"bad namespace":          {func(s *ChaosExperimentSpec) { s.Steps[0].Fault.Target.Namespace = "Payments" }, "target.namespace"},
		"empty selector":         {func(s *ChaosExperimentSpec) { s.Steps[0].Fault.Target.Selector = nil }, "match every pod"},
		"bad selector key":       {func(s *ChaosExperimentSpec) { s.Steps[0].Fault.Target.Selector = map[string]LabelValue{"a b": "x"} }, "selector"},
		"bad selector value":     {func(s *ChaosExperimentSpec) { s.Steps[0].Fault.Target.Selector = map[string]LabelValue{"app": "x y"} }, "invalid label value"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := validSpec()
			c.mutate(&s)
			errs := ValidateSpec(&s)
			if len(errs) == 0 {
				t.Fatal("expected rejection")
			}
			if agg := errs.ToAggregate().Error(); !strings.Contains(agg, c.want) {
				t.Fatalf("error %q does not mention %q", agg, c.want)
			}
		})
	}
}
