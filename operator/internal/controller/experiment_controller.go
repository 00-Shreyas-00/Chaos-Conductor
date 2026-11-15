// Package controller contains the operator's reconcilers.
package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"

	"github.com/kubechaos/kubechaos/operator/internal/faults"
	"github.com/kubechaos/kubechaos/operator/internal/identity"
)

// Condition reasons.
const (
	ReasonWrongNamespace      = "WrongNamespace"
	ReasonClusterMismatch     = "ClusterMismatch"
	ReasonInvalidSpec         = "InvalidSpec"
	ReasonValidated           = "Validated"
	ReasonCancelledByUser     = "Cancelled"
	ReasonExecutionDisabled   = "ExecutionDisabled"
	ReasonNamespaceNotOptedIn = "NamespaceNotOptedIn"
	ReasonNamespaceProtected  = "NamespaceProtected"
	ReasonAccepted            = "Accepted"
	ReasonCompleted           = "Completed"
	ReasonStepFailed          = "StepFailed"
	ReasonInterrupted         = "InjectionInterrupted"
	ReasonMaxDuration         = "MaxDurationExceeded"
	ReasonInconsistentStatus  = "InconsistentStatus"
)

// observeInterval is how often recovery is checked after an injection.
const observeInterval = 2 * time.Second

// ExperimentReconciler validates ChaosExperiments, applies the execution gates and runs their
// steps. It is the only code in KubeChaos that changes workloads.
type ExperimentReconciler struct {
	client.Client
	// Reader performs uncached reads (pods, namespaces): RBAC grants get/list there, not watch.
	Reader    client.Reader
	Recorder  record.EventRecorder
	Identity  identity.Identity
	Namespace string
	Now       func() time.Time
}

func (r *ExperimentReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Reconcile dispatches on phase. Terminal phases are final.
func (r *ExperimentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var exp chaosv1.ChaosExperiment
	if err := r.Get(ctx, req.NamespacedName, &exp); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	switch {
	case isTerminal(exp.Status.Phase):
		return ctrl.Result{}, nil
	case exp.Status.Phase == chaosv1.PhaseRunning:
		return r.advance(ctx, &exp)
	default:
		return r.admit(ctx, &exp)
	}
}

// ---------------------------------------------------------------- admission ----------

func (r *ExperimentReconciler) admit(ctx context.Context, exp *chaosv1.ChaosExperiment) (ctrl.Result, error) {
	orig := exp.DeepCopy()
	phase, cond := r.decide(exp)
	if phase == chaosv1.PhasePending {
		var err error
		if phase, cond, err = r.gate(ctx, exp); err != nil {
			return ctrl.Result{}, err // transient read error: retry, never proceed
		}
	}
	if phase == chaosv1.PhaseRunning {
		return r.start(ctx, exp, orig, cond)
	}
	prev := meta.FindStatusCondition(exp.Status.Conditions, chaosv1.ConditionAccepted)
	if exp.Status.Phase == phase && exp.Status.ObservedGeneration == exp.Generation && prev != nil && prev.Reason == cond.Reason {
		return ctrl.Result{}, nil
	}
	r.setCondition(exp, cond)
	exp.Status.Phase = phase
	exp.Status.Message = cond.Message
	if err := r.Status().Patch(ctx, exp, client.MergeFrom(orig)); err != nil {
		return ctrl.Result{}, err
	}
	r.event(exp, phase != chaosv1.PhasePending, cond.Reason, cond.Message)
	log.FromContext(ctx).Info("experiment decision recorded", "phase", phase, "reason", cond.Reason)
	return ctrl.Result{}, nil
}

// decide applies the static checks in fail-closed order.
func (r *ExperimentReconciler) decide(exp *chaosv1.ChaosExperiment) (chaosv1.ExperimentPhase, metav1.Condition) {
	switch {
	case exp.Namespace != r.Namespace:
		return reject(ReasonWrongNamespace, fmt.Sprintf("experiments are only accepted in namespace %s", r.Namespace))
	case exp.Spec.ClusterID != r.Identity.ClusterID:
		return reject(ReasonClusterMismatch, fmt.Sprintf("spec.clusterID %q does not match this cluster (%q)",
			exp.Spec.ClusterID, r.Identity.ClusterID))
	}
	if errs := chaosv1.ValidateSpec(&exp.Spec); len(errs) > 0 {
		return reject(ReasonInvalidSpec, errs.ToAggregate().Error())
	}
	if exp.Spec.Cancel {
		return chaosv1.PhaseAborted, condition(metav1.ConditionFalse, ReasonCancelledByUser, "cancelled before execution")
	}
	return chaosv1.PhasePending, condition(metav1.ConditionUnknown, ReasonValidated, "validated")
}

// gate decides whether a validated experiment may execute now. Fail closed throughout.
func (r *ExperimentReconciler) gate(ctx context.Context, exp *chaosv1.ChaosExperiment) (chaosv1.ExperimentPhase, metav1.Condition, error) {
	// Until ChaosPolicy (blast-radius limits) and approval attestations are enforced, nothing
	// executes outside development clusters (architecture §12, §15).
	if r.Identity.Environment != identity.Development {
		p, c := chaosv1.PhasePending, condition(metav1.ConditionUnknown, ReasonExecutionDisabled,
			fmt.Sprintf("execution is disabled in %s clusters until ChaosPolicy and approval attestations are enforced", r.Identity.Environment))
		return p, c, nil
	}
	checked := map[string]bool{}
	for _, st := range exp.Spec.Steps {
		if st.Fault == nil || checked[st.Fault.Target.Namespace] {
			continue
		}
		name := st.Fault.Target.Namespace
		checked[name] = true
		var ns corev1.Namespace
		err := r.Reader.Get(ctx, types.NamespacedName{Name: name}, &ns)
		switch {
		case apierrors.IsNotFound(err), apierrors.IsForbidden(err):
			// Forbidden = cluster admins have not granted the operator this namespace (Helm
			// chaosTargets.namespaces). Indistinguishable from "does not exist" on purpose.
			p, c := reject(ReasonNamespaceNotOptedIn, fmt.Sprintf("namespace %q is not opted in: the operator has not been granted access to it", name))
			return p, c, nil
		case err != nil:
			return "", metav1.Condition{}, fmt.Errorf("read namespace %s: %w", name, err)
		}
		if ns.Labels[chaosv1.LabelProtected] == "true" {
			p, c := reject(ReasonNamespaceProtected, fmt.Sprintf("namespace %q is labelled %s=true", name, chaosv1.LabelProtected))
			return p, c, nil
		}
		if ns.Labels[chaosv1.LabelEnabled] != "true" {
			p, c := reject(ReasonNamespaceNotOptedIn, fmt.Sprintf("namespace %q is not opted in: label %s=true is missing", name, chaosv1.LabelEnabled))
			return p, c, nil
		}
	}
	return chaosv1.PhaseRunning, condition(metav1.ConditionTrue, ReasonAccepted, "accepted for execution"), nil
}

func (r *ExperimentReconciler) start(ctx context.Context, exp, orig *chaosv1.ChaosExperiment, cond metav1.Condition) (ctrl.Result, error) {
	now := metav1.NewTime(r.now())
	exp.Status.Phase = chaosv1.PhaseRunning
	exp.Status.StartedAt = &now
	exp.Status.CurrentStep = 0
	exp.Status.Steps = make([]chaosv1.StepStatus, len(exp.Spec.Steps))
	for i := range exp.Status.Steps {
		exp.Status.Steps[i].Phase = chaosv1.StepPending
	}
	exp.Status.Message = "running"
	r.setCondition(exp, cond)
	// Optimistic lock: if the spec changed (e.g. cancel) since we read it, start nothing.
	if err := r.Status().Patch(ctx, exp, client.MergeFromWithOptions(orig, client.MergeFromWithOptimisticLock{})); err != nil {
		return ctrl.Result{}, err
	}
	r.event(exp, false, "Started", fmt.Sprintf("experiment started (%d steps, maxDuration %s)", len(exp.Spec.Steps), exp.Spec.MaxDuration))
	log.FromContext(ctx).Info("experiment started", "requestedBy", exp.Spec.RequestedBy.Subject)
	return ctrl.Result{RequeueAfter: 100 * time.Millisecond}, nil
}

// ---------------------------------------------------------------- execution ----------

func (r *ExperimentReconciler) advance(ctx context.Context, exp *chaosv1.ChaosExperiment) (ctrl.Result, error) {
	orig := exp.DeepCopy()
	now := r.now()
	i := int(exp.Status.CurrentStep)

	if len(exp.Status.Steps) != len(exp.Spec.Steps) || exp.Status.StartedAt == nil || i < 0 || i > len(exp.Spec.Steps) {
		return r.finish(ctx, exp, orig, chaosv1.PhaseFailed, ReasonInconsistentStatus, "status does not match spec; refusing to continue")
	}
	// At-most-once: a step still Injecting at the start of a reconcile means the operator
	// stopped between recording intent and recording the result. Never retry.
	if i < len(exp.Spec.Steps) && exp.Status.Steps[i].Phase == chaosv1.StepInjecting {
		r.failStep(exp, i, now, "injection was interrupted; outcome unknown and NOT retried")
		r.skipRemaining(exp, i+1)
		return r.finish(ctx, exp, orig, chaosv1.PhaseFailed, ReasonInterrupted,
			fmt.Sprintf("step %d: injection interrupted (at-most-once execution: not retried)", i))
	}
	if exp.Spec.Cancel {
		r.skipRemaining(exp, i)
		return r.finish(ctx, exp, orig, chaosv1.PhaseAborted, ReasonCancelledByUser, "cancelled during execution")
	}
	maxDur, _ := time.ParseDuration(exp.Spec.MaxDuration) // validated at admission
	deadline := exp.Status.StartedAt.Add(maxDur)
	if !now.Before(deadline) {
		if i < len(exp.Spec.Steps) {
			r.failStep(exp, i, now, "maxDuration exceeded")
			r.skipRemaining(exp, i+1)
		}
		return r.finish(ctx, exp, orig, chaosv1.PhaseFailed, ReasonMaxDuration,
			fmt.Sprintf("maxDuration %s exceeded", exp.Spec.MaxDuration))
	}
	if i == len(exp.Spec.Steps) {
		return r.finish(ctx, exp, orig, chaosv1.PhaseCompleted, ReasonCompleted, summary(exp))
	}

	res, err := r.runStep(ctx, exp, orig, i, now)
	if err == nil && res.RequeueAfter > 0 {
		if left := deadline.Sub(now) + 50*time.Millisecond; res.RequeueAfter > left {
			res.RequeueAfter = left // wake up exactly at the deadline
		}
	}
	return res, err
}

func (r *ExperimentReconciler) runStep(ctx context.Context, exp, orig *chaosv1.ChaosExperiment, i int, now time.Time) (ctrl.Result, error) {
	step, st := exp.Spec.Steps[i], &exp.Status.Steps[i]
	if step.Wait != nil {
		return r.runWait(ctx, exp, orig, i, now)
	}
	if step.Fault == nil || step.Fault.Type != chaosv1.FaultPodKill { // unreachable after validation
		r.failStep(exp, i, now, "unsupported step")
		return r.finish(ctx, exp, orig, chaosv1.PhaseFailed, ReasonStepFailed, fmt.Sprintf("step %d: unsupported step", i))
	}
	switch st.Phase {
	case chaosv1.StepPending:
		return r.injectPodKill(ctx, exp, orig, i, now)
	case chaosv1.StepObserving:
		return r.observePodKill(ctx, exp, orig, i, now)
	default:
		r.failStep(exp, i, now, "unexpected step phase "+string(st.Phase))
		return r.finish(ctx, exp, orig, chaosv1.PhaseFailed, ReasonInconsistentStatus, fmt.Sprintf("step %d: unexpected phase", i))
	}
}

func (r *ExperimentReconciler) runWait(ctx context.Context, exp, orig *chaosv1.ChaosExperiment, i int, now time.Time) (ctrl.Result, error) {
	st := &exp.Status.Steps[i]
	switch st.Phase {
	case chaosv1.StepPending:
		d, _ := time.ParseDuration(exp.Spec.Steps[i].Wait.Duration)
		started, until := metav1.NewTime(now), metav1.NewTime(now.Add(d))
		st.Phase, st.StartedAt, st.WaitUntil = chaosv1.StepRunning, &started, &until
		if err := r.Status().Patch(ctx, exp, client.MergeFrom(orig)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: d}, nil
	case chaosv1.StepRunning:
		if now.Before(st.WaitUntil.Time) {
			return ctrl.Result{RequeueAfter: st.WaitUntil.Sub(now)}, nil
		}
		fin := metav1.NewTime(now)
		st.Phase, st.FinishedAt = chaosv1.StepSucceeded, &fin
		exp.Status.CurrentStep++
		if err := r.Status().Patch(ctx, exp, client.MergeFrom(orig)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 100 * time.Millisecond}, nil
	default:
		r.failStep(exp, i, now, "unexpected wait phase "+string(st.Phase))
		return r.finish(ctx, exp, orig, chaosv1.PhaseFailed, ReasonInconsistentStatus, fmt.Sprintf("step %d: unexpected phase", i))
	}
}

func (r *ExperimentReconciler) injectPodKill(ctx context.Context, exp, orig *chaosv1.ChaosExperiment, i int, now time.Time) (ctrl.Result, error) {
	f := exp.Spec.Steps[i].Fault
	st := &exp.Status.Steps[i]

	// 1. Plan (read-only). Targets are resolved now, at execution time, and the blast radius
	//    is checked against the pods actually chosen.
	plan, err := faults.PlanPodKill(ctx, r.Reader, f)
	if err != nil {
		r.failStep(exp, i, now, err.Error())
		r.skipRemaining(exp, i+1)
		return r.finish(ctx, exp, orig, chaosv1.PhaseFailed, ReasonStepFailed, fmt.Sprintf("step %d: %v", i, err))
	}

	// 2. Record intent BEFORE destroying anything, with an optimistic lock: if the object
	//    changed (e.g. cancel was requested) the write fails and nothing is deleted.
	started := metav1.NewTime(now)
	st.Phase, st.StartedAt, st.Targets, st.ReadyBefore = chaosv1.StepInjecting, &started, plan.Targets, plan.ReadyBefore
	if err := r.Status().Patch(ctx, exp, client.MergeFromWithOptions(orig, client.MergeFromWithOptimisticLock{})); err != nil {
		return ctrl.Result{}, err
	}
	r.event(exp, false, "TargetsSelected", fmt.Sprintf("step %d: PodKill selected %s in %s", i, podNames(plan.Targets), f.Target.Namespace))

	// 3. Inject.
	grace := int64(30)
	if f.PodKill.GracePeriodSeconds != nil {
		grace = int64(*f.PodKill.GracePeriodSeconds)
	}
	results, injErr := faults.InjectPodKill(ctx, r.Client, plan.Targets, grace)
	injectedAt := metav1.NewTime(r.now())
	after := exp.DeepCopy()

	var deleted []string
	var notes []string
	for _, res := range results {
		if res.Deleted {
			deleted = append(deleted, res.Pod.Name)
			r.event(exp, true, "PodDeleted", fmt.Sprintf("step %d: deleted pod %s/%s (grace %ds)", i, res.Pod.Namespace, res.Pod.Name, grace))
		} else {
			notes = append(notes, res.Pod.Name+": "+res.Note)
		}
	}
	switch {
	case injErr != nil:
		r.failStep(exp, i, injectedAt.Time, fmt.Sprintf("deleted %v before error: %v", deleted, injErr))
	case len(deleted) == 0:
		r.failStep(exp, i, injectedAt.Time, "none of the selected pods could be deleted: "+strings.Join(notes, "; "))
	}
	if injErr != nil || len(deleted) == 0 {
		r.skipRemaining(exp, i+1)
		return r.finish(ctx, exp, after, chaosv1.PhaseFailed, ReasonStepFailed, fmt.Sprintf("step %d: %s", i, exp.Status.Steps[i].Message))
	}

	// 4. Record the result (no optimistic lock: the deletion already happened and must be
	//    recorded even if, say, cancel was set concurrently).
	st = &exp.Status.Steps[i]
	st.Phase, st.InjectedAt = chaosv1.StepObserving, &injectedAt
	st.Message = truncate(fmt.Sprintf("deleted %d pod(s): %s", len(deleted), strings.Join(deleted, ", ")), 512)
	if len(notes) > 0 {
		st.Message = truncate(st.Message+"; "+strings.Join(notes, "; "), 512)
	}
	if err := r.Status().Patch(ctx, exp, client.MergeFrom(after)); err != nil {
		return ctrl.Result{}, err // next reconcile sees Injecting => failed, not retried
	}
	return ctrl.Result{RequeueAfter: observeInterval}, nil
}

func (r *ExperimentReconciler) observePodKill(ctx context.Context, exp, orig *chaosv1.ChaosExperiment, i int, now time.Time) (ctrl.Result, error) {
	st := &exp.Status.Steps[i]
	ready, err := faults.ReadyCount(ctx, r.Reader, exp.Spec.Steps[i].Fault.Target, st.Targets)
	if err != nil {
		return ctrl.Result{}, err // retry; maxDuration still bounds the step
	}
	if ready < st.ReadyBefore {
		return ctrl.Result{RequeueAfter: observeInterval}, nil
	}
	ms := now.Sub(st.InjectedAt.Time).Milliseconds()
	fin := metav1.NewTime(now)
	st.Phase, st.FinishedAt, st.RecoveryMillis = chaosv1.StepSucceeded, &fin, &ms
	st.Message = truncate(fmt.Sprintf("%s; recovered: %d/%d Ready after %s", st.Message, ready, st.ReadyBefore,
		(time.Duration(ms)*time.Millisecond).Round(time.Millisecond)), 512)
	exp.Status.CurrentStep++
	if err := r.Status().Patch(ctx, exp, client.MergeFrom(orig)); err != nil {
		return ctrl.Result{}, err
	}
	r.event(exp, false, "Recovered", fmt.Sprintf("step %d: %d/%d pods Ready again after %dms", i, ready, st.ReadyBefore, ms))
	return ctrl.Result{RequeueAfter: 100 * time.Millisecond}, nil
}

// ---------------------------------------------------------------- helpers ------------

func (r *ExperimentReconciler) finish(ctx context.Context, exp, orig *chaosv1.ChaosExperiment, phase chaosv1.ExperimentPhase, reason, msg string) (ctrl.Result, error) {
	now := metav1.NewTime(r.now())
	exp.Status.Phase = phase
	exp.Status.Message = truncate(msg, 1024)
	if exp.Status.StartedAt != nil {
		exp.Status.CompletedAt = &now
	}
	status := metav1.ConditionFalse
	if phase == chaosv1.PhaseCompleted {
		status = metav1.ConditionTrue
	}
	meta.SetStatusCondition(&exp.Status.Conditions, metav1.Condition{
		Type: chaosv1.ConditionFinished, Status: status, Reason: reason, Message: truncate(msg, 1024), ObservedGeneration: exp.Generation,
	})
	if err := r.Status().Patch(ctx, exp, client.MergeFrom(orig)); err != nil {
		return ctrl.Result{}, err
	}
	r.event(exp, phase != chaosv1.PhaseCompleted, reason, msg)
	log.FromContext(ctx).Info("experiment finished", "phase", phase, "reason", reason)
	return ctrl.Result{}, nil
}

func (r *ExperimentReconciler) failStep(exp *chaosv1.ChaosExperiment, i int, now time.Time, msg string) {
	t := metav1.NewTime(now)
	st := &exp.Status.Steps[i]
	st.Phase, st.FinishedAt, st.Message = chaosv1.StepFailed, &t, truncate(msg, 512)
}

func (r *ExperimentReconciler) skipRemaining(exp *chaosv1.ChaosExperiment, from int) {
	for j := from; j < len(exp.Status.Steps); j++ {
		if exp.Status.Steps[j].Phase == chaosv1.StepPending || exp.Status.Steps[j].Phase == chaosv1.StepRunning {
			exp.Status.Steps[j].Phase = chaosv1.StepSkipped
		}
	}
}

func (r *ExperimentReconciler) setCondition(exp *chaosv1.ChaosExperiment, c metav1.Condition) {
	c.ObservedGeneration = exp.Generation
	meta.SetStatusCondition(&exp.Status.Conditions, c)
	exp.Status.ObservedGeneration = exp.Generation
}

func (r *ExperimentReconciler) event(exp *chaosv1.ChaosExperiment, warning bool, reason, msg string) {
	if r.Recorder == nil {
		return
	}
	t := corev1.EventTypeNormal
	if warning {
		t = corev1.EventTypeWarning
	}
	r.Recorder.Event(exp, t, reason, truncate(msg, 1024))
}

func reject(reason, msg string) (chaosv1.ExperimentPhase, metav1.Condition) {
	return chaosv1.PhaseRejected, condition(metav1.ConditionFalse, reason, msg)
}

func condition(s metav1.ConditionStatus, reason, msg string) metav1.Condition {
	return metav1.Condition{Type: chaosv1.ConditionAccepted, Status: s, Reason: reason, Message: truncate(msg, 1024)}
}

func summary(exp *chaosv1.ChaosExperiment) string {
	var parts []string
	for i, s := range exp.Status.Steps {
		if s.RecoveryMillis != nil {
			parts = append(parts, fmt.Sprintf("step %d recovered in %dms", i, *s.RecoveryMillis))
		}
	}
	if len(parts) == 0 {
		return "all steps succeeded"
	}
	return "all steps succeeded; " + strings.Join(parts, ", ")
}

func podNames(refs []chaosv1.PodRef) string {
	names := make([]string, len(refs))
	for i, p := range refs {
		names[i] = p.Name
	}
	return strings.Join(names, ", ")
}

func isTerminal(p chaosv1.ExperimentPhase) bool {
	switch p {
	case chaosv1.PhaseRejected, chaosv1.PhaseCompleted, chaosv1.PhaseFailed, chaosv1.PhaseAborted:
		return true
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// SetupWithManager registers the reconciler.
func (r *ExperimentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&chaosv1.ChaosExperiment{}).
		WithOptions(controllerOptions()).
		Named("chaosexperiment").
		Complete(r)
}
