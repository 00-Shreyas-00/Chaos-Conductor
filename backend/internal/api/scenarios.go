package api

import chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"

// Scenario is a reusable, read-only experiment template the UI can pre-fill a form from.
type Scenario struct {
	ID              string              `json:"id"`
	Name            string              `json:"name"`
	Description     string              `json:"description"`
	MaxDuration     string              `json:"maxDuration"`
	Steps           []chaosv1.Step      `json:"steps"`
	SuccessCriteria []chaosv1.Criterion `json:"successCriteria"`
}

func i32(v int32) *int32 { return &v }

// scenarios are built-in templates (no user-defined scripts exist anywhere).
var scenarios = []Scenario{
	{
		ID: "single-pod-kill", Name: "Single pod kill",
		Description: "Kill one pod and verify the workload recovers within 30s with all replicas available.",
		MaxDuration: "3m",
		Steps: []chaosv1.Step{
			{Fault: &chaosv1.FaultStep{Type: chaosv1.FaultPodKill,
				Target:  chaosv1.Target{Namespace: "demo", Selector: map[string]chaosv1.LabelValue{"app": "web"}},
				PodKill: &chaosv1.PodKillParams{Count: 1, GracePeriodSeconds: i32(0)}}},
			{Wait: &chaosv1.WaitStep{Duration: "30s"}},
		},
		SuccessCriteria: []chaosv1.Criterion{
			{Metric: chaosv1.MetricAvailableReplicas, Operator: "ge", Value: "3", Weight: 2},
			{Metric: chaosv1.MetricRecoveryTime, Operator: "lt", Value: "30s", Weight: 1},
		},
	},
	{
		ID: "rolling-kills", Name: "Two kills in a row",
		Description: "Kill a pod, wait, kill another: checks recovery is repeatable.",
		MaxDuration: "5m",
		Steps: []chaosv1.Step{
			{Fault: &chaosv1.FaultStep{Type: chaosv1.FaultPodKill,
				Target:  chaosv1.Target{Namespace: "demo", Selector: map[string]chaosv1.LabelValue{"app": "web"}},
				PodKill: &chaosv1.PodKillParams{Count: 1, GracePeriodSeconds: i32(0)}}},
			{Wait: &chaosv1.WaitStep{Duration: "20s"}},
			{Fault: &chaosv1.FaultStep{Type: chaosv1.FaultPodKill,
				Target:  chaosv1.Target{Namespace: "demo", Selector: map[string]chaosv1.LabelValue{"app": "web"}},
				PodKill: &chaosv1.PodKillParams{Count: 1, GracePeriodSeconds: i32(0)}}},
			{Wait: &chaosv1.WaitStep{Duration: "20s"}},
		},
		SuccessCriteria: []chaosv1.Criterion{
			{Metric: chaosv1.MetricReadyRatio, Operator: "eq", Value: "100", Weight: 1},
			{Metric: chaosv1.MetricRecoveryTime, Operator: "lt", Value: "45s", Weight: 1},
		},
	},
}
