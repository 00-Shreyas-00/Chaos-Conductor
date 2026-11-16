package experiments

import (
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
)

// Timeline derives new timeline entries from the transition old -> cur of the operator's
// status (architecture §14: before, failure event, during, recovery, after).
func Timeline(old, cur *chaosv1.ChaosExperimentStatus, now time.Time) []TimelineEvent {
	if cur == nil {
		return nil
	}
	if old == nil {
		old = &chaosv1.ChaosExperimentStatus{}
	}
	var out []TimelineEvent
	add := func(at *time.Time, typ, format string, args ...any) {
		t := now
		if at != nil {
			t = *at
		}
		out = append(out, TimelineEvent{OccurredAt: t, Type: typ, Message: truncate(fmt.Sprintf(format, args...), 1024)})
	}
	if old.Phase != cur.Phase {
		switch cur.Phase {
		case chaosv1.PhasePending:
			add(nil, "Pending", "Waiting: %s", cur.Message)
		case chaosv1.PhaseRejected:
			add(nil, "Rejected", "Rejected by the operator: %s", cur.Message)
		case chaosv1.PhaseRunning, chaosv1.PhaseCompleted, chaosv1.PhaseFailed, chaosv1.PhaseAborted:
			if old.Phase == "" || old.Phase == chaosv1.PhasePending {
				if cur.StartedAt != nil {
					add(timeOf(cur.StartedAt), "Started", "Experiment started")
				}
			}
		}
	}
	for i := range cur.Steps {
		var prev chaosv1.StepStatus
		if i < len(old.Steps) {
			prev = old.Steps[i]
		}
		st := cur.Steps[i]
		if prev.Phase == st.Phase {
			continue
		}
		n := i + 1
		switch st.Phase {
		case chaosv1.StepInjecting:
			add(timeOf(st.StartedAt), "TargetSelected", "Step %d: target selected: %s", n, podList(st.Targets))
		case chaosv1.StepObserving:
			if prev.Phase != chaosv1.StepInjecting {
				add(timeOf(st.StartedAt), "TargetSelected", "Step %d: target selected: %s", n, podList(st.Targets))
			}
			add(timeOf(st.InjectedAt), "PodTerminated", "Step %d: pod(s) terminated: %s (%d Ready before)", n, podList(st.Targets), st.ReadyBefore)
		case chaosv1.StepRunning:
			add(timeOf(st.StartedAt), "WaitStarted", "Step %d: waiting until %s", n, waitUntil(st))
		case chaosv1.StepSucceeded:
			if st.RecoveryMillis != nil {
				add(timeOf(st.FinishedAt), "Recovered", "Step %d: all %d replicas Ready again — recovery time %s", n, st.ReadyBefore,
					(time.Duration(*st.RecoveryMillis) * time.Millisecond).String())
			} else {
				add(timeOf(st.FinishedAt), "StepCompleted", "Step %d: completed", n)
			}
		case chaosv1.StepFailed:
			add(timeOf(st.FinishedAt), "StepFailed", "Step %d failed: %s", n, st.Message)
		case chaosv1.StepSkipped:
			add(nil, "StepSkipped", "Step %d skipped", n)
		}
	}
	if old.Phase != cur.Phase {
		switch cur.Phase {
		case chaosv1.PhaseCompleted:
			msg := "Experiment completed"
			if cur.Score != nil {
				msg = fmt.Sprintf("Experiment completed — %s, resilience score %d/100", cur.Result, *cur.Score)
			}
			add(timeOf(cur.CompletedAt), "Completed", "%s", msg)
			for _, c := range cur.Criteria {
				verdict := "FAIL"
				if c.Passed {
					verdict = "PASS"
				}
				add(timeOf(cur.CompletedAt), "Criterion", "%s %s %s: observed %s — %s", c.Metric, c.Operator, c.Expected, orDash(c.Observed), verdict)
			}
		case chaosv1.PhaseFailed:
			add(timeOf(cur.CompletedAt), "Failed", "Experiment failed: %s", cur.Message)
		case chaosv1.PhaseAborted:
			add(timeOf(cur.CompletedAt), "Aborted", "Experiment aborted: %s", cur.Message)
		}
	}
	return out
}

func timeOf(t *metav1.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.Time
	return &v
}

func podList(refs []chaosv1.PodRef) string {
	if len(refs) == 0 {
		return "-"
	}
	names := make([]string, len(refs))
	for i, r := range refs {
		names[i] = r.Namespace + "/" + r.Name
	}
	return strings.Join(names, ", ")
}

func waitUntil(st chaosv1.StepStatus) string {
	if st.WaitUntil == nil {
		return "-"
	}
	return st.WaitUntil.UTC().Format(time.RFC3339)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
