package v1alpha1

import (
	"fmt"
	"slices"
	"time"
)

// PolicyViolation is one reason a spec is not permitted by the cluster's ChaosPolicy.
type PolicyViolation struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// CheckPolicy evaluates a (schema-valid) spec against the cluster's policy. It is shared by the
// control plane (early, user-facing denial) and the operator (authoritative enforcement); both
// run it independently. clusterEnv is the environment of the cluster identity.
// A nil policy is a violation: no policy, no execution (fail closed).
func CheckPolicy(s *ChaosExperimentSpec, p *ChaosPolicy, clusterEnv string) []PolicyViolation {
	if p == nil {
		return []PolicyViolation{{Field: "policy", Message: "no ChaosPolicy is installed on this cluster; nothing may run"}}
	}
	var v []PolicyViolation
	add := func(field, format string, args ...any) {
		v = append(v, PolicyViolation{Field: field, Message: fmt.Sprintf(format, args...)})
	}
	if p.Spec.Environment != clusterEnv {
		add("policy.environment", "policy is for %q but this cluster is %q", p.Spec.Environment, clusterEnv)
	}
	if d, err := time.ParseDuration(s.MaxDuration); err == nil {
		if max, err := time.ParseDuration(p.Spec.Limits.MaxDuration); err != nil || d > max {
			add("spec.maxDuration", "%s exceeds the policy limit of %s", s.MaxDuration, p.Spec.Limits.MaxDuration)
		}
	}
	for i, st := range s.Steps {
		if st.Fault == nil {
			continue
		}
		f := st.Fault
		path := fmt.Sprintf("spec.steps[%d].fault", i)
		if !slices.Contains(p.Spec.AllowedFaults, f.Type) {
			add(path+".type", "fault type %s is not allowed by policy", f.Type)
		}
		if !slices.Contains(p.Spec.AllowedNamespaces, f.Target.Namespace) {
			add(path+".target.namespace", "namespace %q is not allowed by policy", f.Target.Namespace)
		}
		if f.Type == FaultPodKill && f.PodKill != nil && f.PodKill.Count > p.Spec.Limits.MaxPodKillCount {
			add(path+".podKill.count", "count %d exceeds the policy limit of %d", f.PodKill.Count, p.Spec.Limits.MaxPodKillCount)
		}
	}
	for i, c := range s.SuccessCriteria {
		path := fmt.Sprintf("spec.successCriteria[%d]", i)
		if c.Metric.IsPrometheus() && (p.Spec.Observability == nil || p.Spec.Observability.Prometheus == nil) {
			add(path+".metric", "%s needs the Prometheus provider, which this cluster's policy does not configure", c.Metric)
		}
		if c.Target != nil && !slices.Contains(p.Spec.AllowedNamespaces, c.Target.Namespace) {
			add(path+".target.namespace", "namespace %q is not allowed by policy", c.Target.Namespace)
		}
	}
	return v
}

// ApprovalRequired reports whether the spec needs an approval attestation under the policy.
// Production always requires approval regardless of the policy text (defence in depth on top
// of the CRD's CEL rule).
func ApprovalRequired(s *ChaosExperimentSpec, p *ChaosPolicy) bool {
	if p == nil {
		return true
	}
	if p.Spec.Environment == "production" {
		return true
	}
	switch p.Spec.Approval.Required {
	case ApprovalAlways:
		return true
	case ApprovalRiskAtLeast:
		return RiskAtLeast(SpecRisk(s), p.Spec.Approval.RiskAtLeast) || p.Spec.Approval.RiskAtLeast == ""
	case ApprovalNever:
		return false
	default:
		return true // unknown value: fail closed
	}
}

// MinApprovals returns the number of distinct approvers required (at least 1 when required).
func MinApprovals(p *ChaosPolicy) int {
	if p == nil || p.Spec.Approval.MinApprovals < 1 {
		return 1
	}
	return int(p.Spec.Approval.MinApprovals)
}

// MinSurvivors returns the per-workload number of Ready pods that must survive.
func MinSurvivors(p *ChaosPolicy) int {
	if p == nil || p.Spec.Limits.MinReadyReplicas < 1 {
		return 1
	}
	return int(p.Spec.Limits.MinReadyReplicas)
}
