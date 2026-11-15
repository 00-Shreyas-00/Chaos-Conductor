package controller

import (
	"context"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"

	"github.com/kubechaos/kubechaos/operator/internal/identity"
)

const ns = "kubechaos-system"

func experiment(name string, mutate func(*chaosv1.ChaosExperiment)) *chaosv1.ChaosExperiment {
	zero := int32(0)
	e := &chaosv1.ChaosExperiment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Generation: 1},
		Spec: chaosv1.ChaosExperimentSpec{
			ClusterID:   "dev-kind-01",
			RequestedBy: chaosv1.Requester{Issuer: "https://idp", Subject: "alice"},
			MaxDuration: "2m",
			Steps: []chaosv1.Step{{Fault: &chaosv1.FaultStep{
				Type:    chaosv1.FaultPodKill,
				Target:  chaosv1.Target{Namespace: "demo", Selector: map[string]chaosv1.LabelValue{"app": "web"}},
				PodKill: &chaosv1.PodKillParams{Count: 1, GracePeriodSeconds: &zero},
			}}},
		},
	}
	if mutate != nil {
		mutate(e)
	}
	return e
}

func reconcile(t *testing.T, objs ...client.Object) (*ExperimentReconciler, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := chaosv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).
		WithStatusSubresource(&chaosv1.ChaosExperiment{}).Build()
	r := &ExperimentReconciler{Client: c, Namespace: ns,
		Identity: identity.Identity{ClusterID: "dev-kind-01", Environment: identity.Development}}
	for _, o := range objs {
		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: o.GetNamespace(), Name: o.GetName()}}); err != nil {
			t.Fatalf("reconcile %s: %v", o.GetName(), err)
		}
	}
	return r, c
}

func get(t *testing.T, c client.Client, namespace, name string) chaosv1.ChaosExperiment {
	t.Helper()
	var e chaosv1.ChaosExperiment
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: namespace, Name: name}, &e); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestDecisions(t *testing.T) {
	cases := []struct {
		name      string
		exp       *chaosv1.ChaosExperiment
		phase     chaosv1.ExperimentPhase
		reason    string
		condition metav1.ConditionStatus
	}{
		{"valid", experiment("valid", nil), chaosv1.PhasePending, ReasonAwaitingEngine, metav1.ConditionUnknown},
		{"other cluster", experiment("other", func(e *chaosv1.ChaosExperiment) { e.Spec.ClusterID = "prod-eu-1" }),
			chaosv1.PhaseRejected, ReasonClusterMismatch, metav1.ConditionFalse},
		{"wrong namespace", experiment("wrongns", func(e *chaosv1.ChaosExperiment) { e.Namespace = "default" }),
			chaosv1.PhaseRejected, ReasonWrongNamespace, metav1.ConditionFalse},
		// Defence in depth: the CRD schema would reject these, the Go layer must too.
		{"protected target", experiment("protected", func(e *chaosv1.ChaosExperiment) { e.Spec.Steps[0].Fault.Target.Namespace = "kube-system" }),
			chaosv1.PhaseRejected, ReasonInvalidSpec, metav1.ConditionFalse},
		{"count over cap", experiment("count", func(e *chaosv1.ChaosExperiment) { e.Spec.Steps[0].Fault.PodKill.Count = 10000 }),
			chaosv1.PhaseRejected, ReasonInvalidSpec, metav1.ConditionFalse},
		{"unknown fault", experiment("unknown", func(e *chaosv1.ChaosExperiment) { e.Spec.Steps[0].Fault.Type = "NodeDrain" }),
			chaosv1.PhaseRejected, ReasonInvalidSpec, metav1.ConditionFalse},
		{"cancelled", experiment("cancelled", func(e *chaosv1.ChaosExperiment) { e.Spec.Cancel = true }),
			chaosv1.PhaseAborted, ReasonCancelledByUser, metav1.ConditionFalse},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, cl := reconcile(t, c.exp)
			got := get(t, cl, c.exp.Namespace, c.exp.Name)
			cond := meta.FindStatusCondition(got.Status.Conditions, chaosv1.ConditionAccepted)
			if got.Status.Phase != c.phase || cond == nil || cond.Reason != c.reason || cond.Status != c.condition ||
				got.Status.ObservedGeneration != 1 || cond.ObservedGeneration != 1 {
				t.Fatalf("phase=%s cond=%+v", got.Status.Phase, cond)
			}
		})
	}
}

func TestTerminalPhaseIsSticky(t *testing.T) {
	exp := experiment("sticky", func(e *chaosv1.ChaosExperiment) { e.Spec.ClusterID = "prod-eu-1" })
	r, c := reconcile(t, exp)
	// Even if the identity "changed" (it cannot at runtime), a rejected experiment stays rejected.
	r.Identity.ClusterID = "prod-eu-1"
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: "sticky"}}); err != nil {
		t.Fatal(err)
	}
	if got := get(t, c, ns, "sticky"); got.Status.Phase != chaosv1.PhaseRejected {
		t.Fatalf("terminal phase must not change: %s", got.Status.Phase)
	}
}

func TestMessagesAreBounded(t *testing.T) {
	exp := experiment("long", func(e *chaosv1.ChaosExperiment) { e.Spec.ClusterID = strings.Repeat("x", 5000) })
	_, c := reconcile(t, exp)
	if got := get(t, c, ns, "long"); len(got.Status.Message) > 1024 {
		t.Fatalf("status message length %d exceeds 1024", len(got.Status.Message))
	}
}
