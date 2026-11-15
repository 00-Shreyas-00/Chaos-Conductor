// Package controller contains the operator's reconcilers.
package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"

	"github.com/kubechaos/kubechaos/operator/internal/identity"
)

// Condition reasons.
const (
	ReasonWrongNamespace  = "WrongNamespace"
	ReasonClusterMismatch = "ClusterMismatch"
	ReasonInvalidSpec     = "InvalidSpec"
	ReasonAwaitingEngine  = "AwaitingExecutionEngine"
	ReasonCancelledByUser = "Cancelled"
)

// ExperimentReconciler validates ChaosExperiments and records the decision in status.
// Foundation step 11: it never acts on workloads. Execution (PodKill) arrives in step 12 and
// will only ever start from an experiment this reconciler has accepted.
type ExperimentReconciler struct {
	client.Client
	Identity  identity.Identity
	Namespace string
}

// Reconcile is idempotent: it decides once per spec generation and never moves an experiment
// out of a terminal phase.
func (r *ExperimentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var exp chaosv1.ChaosExperiment
	if err := r.Get(ctx, req.NamespacedName, &exp); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if isTerminal(exp.Status.Phase) && exp.Status.ObservedGeneration == exp.Generation {
		return ctrl.Result{}, nil
	}

	phase, cond := r.decide(&exp)
	if exp.Status.Phase == phase && exp.Status.ObservedGeneration == exp.Generation {
		return ctrl.Result{}, nil // nothing new to record
	}
	cond.ObservedGeneration = exp.Generation
	meta.SetStatusCondition(&exp.Status.Conditions, cond)
	exp.Status.Phase = phase
	exp.Status.ObservedGeneration = exp.Generation
	exp.Status.Message = cond.Message
	if err := r.Status().Update(ctx, &exp); err != nil {
		return ctrl.Result{}, err // conflict etc.: requeued with backoff
	}
	logger.Info("experiment decision recorded", "phase", phase, "reason", cond.Reason,
		"requestedBy", exp.Spec.RequestedBy.Subject)
	return ctrl.Result{}, nil
}

// decide applies the checks in fail-closed order. Anything not positively accepted is rejected.
func (r *ExperimentReconciler) decide(exp *chaosv1.ChaosExperiment) (chaosv1.ExperimentPhase, metav1.Condition) {
	reject := func(reason, msg string) (chaosv1.ExperimentPhase, metav1.Condition) {
		return chaosv1.PhaseRejected, metav1.Condition{
			Type: chaosv1.ConditionAccepted, Status: metav1.ConditionFalse, Reason: reason, Message: truncate(msg, 1024),
		}
	}
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
		return chaosv1.PhaseAborted, metav1.Condition{
			Type: chaosv1.ConditionAccepted, Status: metav1.ConditionFalse, Reason: ReasonCancelledByUser,
			Message: "cancelled before execution",
		}
	}
	return chaosv1.PhasePending, metav1.Condition{
		Type: chaosv1.ConditionAccepted, Status: metav1.ConditionUnknown, Reason: ReasonAwaitingEngine,
		Message: "validated; the execution engine is not enabled in this build",
	}
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
