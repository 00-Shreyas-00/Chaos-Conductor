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
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
	"github.com/kubechaos/kubechaos/pkg/chaosapi/attestation"

	"github.com/kubechaos/kubechaos/operator/internal/criteria"
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
	ReasonSystemLocked        = "SystemLocked"
	ReasonPolicyUnavailable   = "PolicyUnavailable"
	ReasonPolicyViolation     = "PolicyViolation"
	ReasonConcurrencyLimit    = "ConcurrencyLimit"
	ReasonApprovalRequired    = "ApprovalRequired"
	ReasonApprovalInvalid     = "ApprovalInvalid"
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
	// Read from the API server, not the informer cache. A stale cached copy that still says
	// "Injecting" after we already recorded "Observing" would make the at-most-once guard declare
	// a false interruption (observed in kind). Decisions must be based on current state.
	var exp chaosv1.ChaosExperiment
	if err := r.Reader.Get(ctx, req.NamespacedName, &exp); err != nil {
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

// gate decides whether a validated experiment may execute now. Order and outcomes (fail closed):
//
//	lock present            -> Rejected  SystemLocked
//	policy missing/invalid  -> Rejected  PolicyUnavailable / PolicyViolation
//	concurrency limit hit   -> Pending   ConcurrencyLimit (retried)
//	approval missing/bad    -> Rejected  ApprovalRequired / ApprovalInvalid
//	namespace not opted in  -> Rejected  NamespaceNotOptedIn / NamespaceProtected
func (r *ExperimentReconciler) gate(ctx context.Context, exp *chaosv1.ChaosExperiment) (chaosv1.ExperimentPhase, metav1.Condition, error) {
	locked, lockMsg, err := r.locked(ctx)
	if err != nil {
		return "", metav1.Condition{}, err
	}
	if locked {
		p, c := reject(ReasonSystemLocked, lockMsg)
		return p, c, nil
	}

	pol, err := r.policy(ctx)
	if err != nil {
		return "", metav1.Condition{}, err
	}
	if pol == nil {
		p, c := reject(ReasonPolicyUnavailable, "no ChaosPolicy 'default' is installed (or the operator cannot read it); nothing may run")
		return p, c, nil
	}
	if v := chaosv1.CheckPolicy(&exp.Spec, pol, string(r.Identity.Environment)); len(v) > 0 {
		msgs := make([]string, len(v))
		for i, x := range v {
			msgs[i] = x.Field + ": " + x.Message
		}
		p, c := reject(ReasonPolicyViolation, strings.Join(msgs, "; "))
		return p, c, nil
	}

	running, err := r.runningCount(ctx, exp.Name)
	if err != nil {
		return "", metav1.Condition{}, err
	}
	if running >= int(pol.Spec.Limits.MaxConcurrentExperiments) {
		p, c := chaosv1.PhasePending, condition(metav1.ConditionUnknown, ReasonConcurrencyLimit,
			fmt.Sprintf("%d experiment(s) running; policy allows %d at a time", running, pol.Spec.Limits.MaxConcurrentExperiments))
		return p, c, nil
	}

	namespaces := map[string]*corev1.Namespace{}
	for _, name := range attestation.TargetNamespaces(&exp.Spec) {
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
		namespaces[name] = &ns
	}

	if chaosv1.ApprovalRequired(&exp.Spec, pol) {
		if reason, msg := r.verifyApproval(ctx, exp, pol, namespaces); reason != "" {
			p, c := reject(reason, msg)
			return p, c, nil
		}
	}
	return chaosv1.PhaseRunning, condition(metav1.ConditionTrue, ReasonAccepted, "accepted for execution"), nil
}

// locked reports whether any ChaosLock exists (emergency stop).
func (r *ExperimentReconciler) locked(ctx context.Context) (bool, string, error) {
	var locks chaosv1.ChaosLockList
	if err := r.Client.List(ctx, &locks); err != nil {
		return false, "", fmt.Errorf("list ChaosLocks: %w", err) // cannot tell: retry, never proceed
	}
	if len(locks.Items) == 0 {
		return false, "", nil
	}
	l := locks.Items[0]
	return true, truncate(fmt.Sprintf("emergency stop engaged by %s: %s (ChaosLock %s)", l.Spec.EngagedBy, l.Spec.Reason, l.Name), 1024), nil
}

// policy returns the cluster's ChaosPolicy, or nil when absent or unreadable.
func (r *ExperimentReconciler) policy(ctx context.Context) (*chaosv1.ChaosPolicy, error) {
	var p chaosv1.ChaosPolicy
	err := r.Reader.Get(ctx, types.NamespacedName{Name: chaosv1.PolicyName}, &p)
	if apierrors.IsNotFound(err) || apierrors.IsForbidden(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read ChaosPolicy: %w", err)
	}
	return &p, nil
}

func (r *ExperimentReconciler) runningCount(ctx context.Context, self string) (int, error) {
	var list chaosv1.ChaosExperimentList
	if err := r.Client.List(ctx, &list, client.InNamespace(r.Namespace)); err != nil {
		return 0, fmt.Errorf("list experiments: %w", err)
	}
	n := 0
	for _, e := range list.Items {
		if e.Name != self && e.Status.Phase == chaosv1.PhaseRunning {
			n++
		}
	}
	return n, nil
}

// verifyApproval checks the approval attestation and consumes it (single use). It returns a
// rejection reason and message, or "" when approved.
func (r *ExperimentReconciler) verifyApproval(ctx context.Context, exp *chaosv1.ChaosExperiment, pol *chaosv1.ChaosPolicy, namespaces map[string]*corev1.Namespace) (string, string) {
	token := exp.Annotations[chaosv1.AnnotationApproval]
	if token == "" {
		return ReasonApprovalRequired, fmt.Sprintf("policy requires an approval attestation (%d approver(s)) for this experiment", chaosv1.MinApprovals(pol))
	}
	maxAge, err := time.ParseDuration(pol.Spec.Approval.MaxAttestationAge)
	if err != nil || maxAge <= 0 {
		maxAge = time.Hour
	}
	claims, err := attestation.Verify(token, pol.Spec.Approval.TrustedKeys, attestation.Expectations{
		ClusterID: r.Identity.ClusterID, Environment: string(r.Identity.Environment), Spec: &exp.Spec,
		MinApprovals: chaosv1.MinApprovals(pol), MaxAge: maxAge, Now: r.now(),
	})
	if err != nil {
		return ReasonApprovalInvalid, err.Error()
	}
	// The approving group must be the group cluster admins assigned to every target namespace.
	for name, ns := range namespaces {
		want := ns.Annotations[chaosv1.AnnotationApproverGroup]
		if want == "" || want != claims.ApproverGroup {
			return ReasonApprovalInvalid, fmt.Sprintf("approver group %q is not the approver group of namespace %q", claims.ApproverGroup, name)
		}
	}
	// Single use: creating the record fails with AlreadyExists on replay.
	use := &chaosv1.ChaosAttestationUse{
		ObjectMeta: metav1.ObjectMeta{Name: "jti-" + strings.ToLower(claims.ID)},
		Spec:       chaosv1.ChaosAttestationUseSpec{Experiment: exp.Namespace + "/" + exp.Name, SpecSHA256: claims.SpecSHA256},
	}
	if err := r.Client.Create(ctx, use); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return ReasonApprovalInvalid, "attestation has already been used (replay)"
		}
		return ReasonApprovalInvalid, "could not record attestation use: " + err.Error()
	}
	return "", ""
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
	// Emergency stop: abort before starting or continuing any step.
	if locked, msg, err := r.locked(ctx); err != nil {
		return ctrl.Result{}, err
	} else if locked {
		r.skipRemaining(exp, i)
		return r.finish(ctx, exp, orig, chaosv1.PhaseAborted, ReasonSystemLocked, "aborted: "+msg)
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
		pol, err := r.policy(ctx)
		if err != nil {
			return ctrl.Result{}, err
		}
		var prom *chaosv1.PrometheusProvider
		if pol != nil && pol.Spec.Observability != nil {
			prom = pol.Spec.Observability.Prometheus
		}
		ev := criteria.Evaluator{Reader: r.Reader, Prometheus: prom, Now: r.now}
		exp.Status.Criteria, exp.Status.Score, exp.Status.Result = ev.Evaluate(ctx, exp)
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
	pol, err := r.policy(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	if pol == nil { // policy removed mid-run: fail closed before any further injection
		r.failStep(exp, i, now, "ChaosPolicy no longer available")
		r.skipRemaining(exp, i+1)
		return r.finish(ctx, exp, orig, chaosv1.PhaseFailed, ReasonPolicyUnavailable, "ChaosPolicy removed during execution")
	}
	plan, err := faults.PlanPodKill(ctx, r.Reader, f, chaosv1.MinSurvivors(pol))
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
	if exp.Status.Score != nil {
		parts = append(parts, fmt.Sprintf("result %s, resilience score %d/100", exp.Status.Result, *exp.Status.Score))
	}
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
		// Engaging the emergency stop must abort running experiments promptly, not after their
		// current wait: every ChaosLock event re-queues all non-terminal experiments.
		Watches(&chaosv1.ChaosLock{}, handler.EnqueueRequestsFromMapFunc(r.allActive)).
		WithOptions(controllerOptions()).
		Named("chaosexperiment").
		Complete(r)
}

func (r *ExperimentReconciler) allActive(ctx context.Context, _ client.Object) []reconcile.Request {
	var list chaosv1.ChaosExperimentList
	if err := r.Client.List(ctx, &list, client.InNamespace(r.Namespace)); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for _, e := range list.Items {
		if !isTerminal(e.Status.Phase) {
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: e.Namespace, Name: e.Name}})
		}
	}
	return reqs
}
