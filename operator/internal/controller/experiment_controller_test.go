package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"

	"github.com/kubechaos/kubechaos/operator/internal/identity"
)

const ns = "kubechaos-system"

// ---------------------------------------------------------------- fixtures -----------

func experiment(name string, mutate func(*chaosv1.ChaosExperiment)) *chaosv1.ChaosExperiment {
	zero := int32(0)
	e := &chaosv1.ChaosExperiment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Generation: 1},
		Spec: chaosv1.ChaosExperimentSpec{
			ClusterID:   "dev-kind-01",
			RequestedBy: chaosv1.Requester{Issuer: "https://idp", Subject: "alice"},
			MaxDuration: "2m",
			Steps: []chaosv1.Step{
				{Fault: &chaosv1.FaultStep{
					Type:    chaosv1.FaultPodKill,
					Target:  chaosv1.Target{Namespace: "demo", Selector: map[string]chaosv1.LabelValue{"app": "web"}},
					PodKill: &chaosv1.PodKillParams{Count: 1, GracePeriodSeconds: &zero},
				}},
				{Wait: &chaosv1.WaitStep{Duration: "10s"}},
			},
		},
	}
	if mutate != nil {
		mutate(e)
	}
	return e
}

func namespace(name string, labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

var optedIn = map[string]string{chaosv1.LabelEnabled: "true"}

func webPod(name string) *corev1.Pod {
	t := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo", Name: name, UID: types.UID("uid-" + name), Labels: map[string]string{"app": "web"},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "web-rs", UID: "rs-web", Controller: &t}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
}

type harness struct {
	t     *testing.T
	r     *ExperimentReconciler
	c     client.Client
	clock time.Time
}

func newHarness(t *testing.T, env identity.Environment, objs ...client.Object) *harness {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = chaosv1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).WithStatusSubresource(&chaosv1.ChaosExperiment{}).Build()
	h := &harness{t: t, c: c, clock: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)}
	h.r = &ExperimentReconciler{Client: c, Reader: c, Namespace: ns,
		Identity: identity.Identity{ClusterID: "dev-kind-01", Environment: env},
		Now:      func() time.Time { return h.clock }}
	return h
}

func (h *harness) reconcile(name string) ctrl.Result {
	h.t.Helper()
	res, err := h.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}})
	if err != nil {
		h.t.Fatalf("reconcile: %v", err)
	}
	return res
}

func (h *harness) get(name string) chaosv1.ChaosExperiment {
	h.t.Helper()
	var e chaosv1.ChaosExperiment
	if err := h.c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &e); err != nil {
		h.t.Fatal(err)
	}
	return e
}

func (h *harness) podCount() int {
	var l corev1.PodList
	_ = h.c.List(context.Background(), &l, client.InNamespace("demo"))
	return len(l.Items)
}

func reason(e chaosv1.ChaosExperiment, typ string) string {
	if c := meta.FindStatusCondition(e.Status.Conditions, typ); c != nil {
		return c.Reason
	}
	return ""
}

// ---------------------------------------------------------------- admission ----------

func TestAdmissionDecisions(t *testing.T) {
	cases := []struct {
		name   string
		env    identity.Environment
		exp    *chaosv1.ChaosExperiment
		ns     *corev1.Namespace
		phase  chaosv1.ExperimentPhase
		reason string
	}{
		{"other cluster", identity.Development, experiment("e", func(e *chaosv1.ChaosExperiment) { e.Spec.ClusterID = "prod-eu-1" }),
			namespace("demo", optedIn), chaosv1.PhaseRejected, ReasonClusterMismatch},
		{"wrong namespace", identity.Development, experiment("e", func(e *chaosv1.ChaosExperiment) { e.Namespace = "default" }),
			namespace("demo", optedIn), chaosv1.PhaseRejected, ReasonWrongNamespace},
		{"invalid (defence in depth)", identity.Development, experiment("e", func(e *chaosv1.ChaosExperiment) { e.Spec.Steps[0].Fault.PodKill.Count = 10000 }),
			namespace("demo", optedIn), chaosv1.PhaseRejected, ReasonInvalidSpec},
		{"cancelled before start", identity.Development, experiment("e", func(e *chaosv1.ChaosExperiment) { e.Spec.Cancel = true }),
			namespace("demo", optedIn), chaosv1.PhaseAborted, ReasonCancelledByUser},
		{"production: execution disabled", identity.Production, experiment("e", nil),
			namespace("demo", optedIn), chaosv1.PhasePending, ReasonExecutionDisabled},
		{"staging: execution disabled", identity.Staging, experiment("e", nil),
			namespace("demo", optedIn), chaosv1.PhasePending, ReasonExecutionDisabled},
		{"namespace missing / not granted", identity.Development, experiment("e", nil),
			nil, chaosv1.PhaseRejected, ReasonNamespaceNotOptedIn},
		{"namespace without opt-in label", identity.Development, experiment("e", nil),
			namespace("demo", nil), chaosv1.PhaseRejected, ReasonNamespaceNotOptedIn},
		{"namespace label not exactly true", identity.Development, experiment("e", nil),
			namespace("demo", map[string]string{chaosv1.LabelEnabled: "yes"}), chaosv1.PhaseRejected, ReasonNamespaceNotOptedIn},
		{"protected namespace", identity.Development, experiment("e", nil),
			namespace("demo", map[string]string{chaosv1.LabelEnabled: "true", chaosv1.LabelProtected: "true"}), chaosv1.PhaseRejected, ReasonNamespaceProtected},
		{"accepted", identity.Development, experiment("e", nil),
			namespace("demo", optedIn), chaosv1.PhaseRunning, ReasonAccepted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			objs := []client.Object{c.exp, webPod("a"), webPod("b")}
			if c.ns != nil {
				objs = append(objs, c.ns)
			}
			h := newHarness(t, c.env, objs...)
			res, err := h.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: c.exp.Namespace, Name: "e"}})
			if err != nil {
				t.Fatal(err)
			}
			_ = res
			var got chaosv1.ChaosExperiment
			_ = h.c.Get(context.Background(), types.NamespacedName{Namespace: c.exp.Namespace, Name: "e"}, &got)
			if got.Status.Phase != c.phase || reason(got, chaosv1.ConditionAccepted) != c.reason {
				t.Fatalf("phase=%s reason=%s (want %s %s): %s", got.Status.Phase, reason(got, chaosv1.ConditionAccepted), c.phase, c.reason, got.Status.Message)
			}
			if h.podCount() != 2 {
				t.Fatal("admission must never delete pods")
			}
		})
	}
}

// ---------------------------------------------------------------- execution ----------

func TestPodKillLifecycle(t *testing.T) {
	h := newHarness(t, identity.Development, experiment("e", nil), namespace("demo", optedIn), webPod("a"), webPod("b"), webPod("c"))

	h.reconcile("e") // admit -> Running
	if e := h.get("e"); e.Status.Phase != chaosv1.PhaseRunning || len(e.Status.Steps) != 2 {
		t.Fatalf("not started: %+v", e.Status)
	}

	h.reconcile("e") // step 0: plan, record intent, delete, Observing
	e := h.get("e")
	st := e.Status.Steps[0]
	if st.Phase != chaosv1.StepObserving || len(st.Targets) != 1 || st.ReadyBefore != 3 || st.InjectedAt == nil {
		t.Fatalf("after injection: %+v", st)
	}
	if h.podCount() != 2 {
		t.Fatalf("exactly one pod must be deleted, %d left", h.podCount())
	}

	h.clock = h.clock.Add(2 * time.Second)
	h.reconcile("e") // still only 2 Ready -> keep observing
	if h.get("e").Status.Steps[0].Phase != chaosv1.StepObserving {
		t.Fatal("must keep observing until recovered")
	}

	// The ReplicaSet "recreates" the pod.
	if err := h.c.Create(context.Background(), webPod("d")); err != nil {
		t.Fatal(err)
	}
	h.clock = h.clock.Add(3 * time.Second)
	h.reconcile("e") // recovered -> step 1
	e = h.get("e")
	if e.Status.Steps[0].Phase != chaosv1.StepSucceeded || e.Status.Steps[0].RecoveryMillis == nil || *e.Status.Steps[0].RecoveryMillis != 5000 {
		t.Fatalf("recovery not recorded: %+v", e.Status.Steps[0])
	}

	h.reconcile("e") // wait starts
	res := h.reconcile("e")
	if res.RequeueAfter <= 0 || h.get("e").Status.Steps[1].Phase != chaosv1.StepRunning {
		t.Fatalf("wait must requeue: %+v", res)
	}
	h.clock = h.clock.Add(10 * time.Second)
	h.reconcile("e") // wait done
	h.reconcile("e") // all steps done
	e = h.get("e")
	if e.Status.Phase != chaosv1.PhaseCompleted || reason(e, chaosv1.ConditionFinished) != ReasonCompleted ||
		e.Status.CompletedAt == nil || !strings.Contains(e.Status.Message, "recovered in 5000ms") {
		t.Fatalf("not completed: phase=%s msg=%s", e.Status.Phase, e.Status.Message)
	}
	h.reconcile("e") // terminal: no-op
	if h.podCount() != 3 {
		t.Fatal("a completed experiment must not touch pods again")
	}
}

func TestInterruptedInjectionIsNotRetried(t *testing.T) {
	started := metav1.NewTime(time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC))
	exp := experiment("e", nil)
	exp.Status = chaosv1.ChaosExperimentStatus{
		Phase: chaosv1.PhaseRunning, StartedAt: &started,
		Steps: []chaosv1.StepStatus{
			{Phase: chaosv1.StepInjecting, Targets: []chaosv1.PodRef{{Namespace: "demo", Name: "a", UID: "uid-a"}}},
			{Phase: chaosv1.StepPending},
		},
	}
	h := newHarness(t, identity.Development, exp, namespace("demo", optedIn), webPod("a"), webPod("b"))
	h.reconcile("e")
	e := h.get("e")
	if e.Status.Phase != chaosv1.PhaseFailed || reason(e, chaosv1.ConditionFinished) != ReasonInterrupted ||
		e.Status.Steps[0].Phase != chaosv1.StepFailed || e.Status.Steps[1].Phase != chaosv1.StepSkipped {
		t.Fatalf("status %+v", e.Status)
	}
	if h.podCount() != 2 {
		t.Fatal("an interrupted injection must never be retried")
	}
}

func TestCancelDuringWait(t *testing.T) {
	exp := experiment("e", func(e *chaosv1.ChaosExperiment) {
		e.Spec.Steps = []chaosv1.Step{{Wait: &chaosv1.WaitStep{Duration: "30s"}}, e.Spec.Steps[0]}
	})
	h := newHarness(t, identity.Development, exp, namespace("demo", optedIn), webPod("a"), webPod("b"))
	h.reconcile("e") // start
	h.reconcile("e") // wait running
	e := h.get("e")
	e.Spec.Cancel = true
	if err := h.c.Update(context.Background(), &e); err != nil {
		t.Fatal(err)
	}
	h.clock = h.clock.Add(time.Second)
	h.reconcile("e")
	e = h.get("e")
	if e.Status.Phase != chaosv1.PhaseAborted || e.Status.Steps[0].Phase != chaosv1.StepSkipped || e.Status.Steps[1].Phase != chaosv1.StepSkipped {
		t.Fatalf("status %+v", e.Status)
	}
	if h.podCount() != 2 {
		t.Fatal("cancelled experiment must not kill pods")
	}
}

func TestMaxDurationWhileObserving(t *testing.T) {
	exp := experiment("e", func(e *chaosv1.ChaosExperiment) { e.Spec.MaxDuration = "30s"; e.Spec.Steps = e.Spec.Steps[:1] })
	h := newHarness(t, identity.Development, exp, namespace("demo", optedIn), webPod("a"), webPod("b"))
	h.reconcile("e") // start
	h.reconcile("e") // inject (2 -> 1 Ready; never recovers)
	h.clock = h.clock.Add(31 * time.Second)
	h.reconcile("e")
	e := h.get("e")
	if e.Status.Phase != chaosv1.PhaseFailed || reason(e, chaosv1.ConditionFinished) != ReasonMaxDuration ||
		e.Status.Steps[0].Phase != chaosv1.StepFailed {
		t.Fatalf("status %+v", e.Status)
	}
}

func TestBlastRadiusAtExecutionDeletesNothing(t *testing.T) {
	exp := experiment("e", func(e *chaosv1.ChaosExperiment) { e.Spec.Steps[0].Fault.PodKill.Count = 2 })
	h := newHarness(t, identity.Development, exp, namespace("demo", optedIn), webPod("a"), webPod("b"))
	h.reconcile("e") // start
	h.reconcile("e") // plan fails: 2 of 2 would empty the workload
	e := h.get("e")
	if e.Status.Phase != chaosv1.PhaseFailed || !strings.Contains(e.Status.Message, "blast radius exceeded") ||
		e.Status.Steps[0].Phase != chaosv1.StepFailed || len(e.Status.Steps[0].Targets) != 0 {
		t.Fatalf("status %+v", e.Status)
	}
	if h.podCount() != 2 {
		t.Fatal("no pod may be deleted when the blast radius is exceeded")
	}
}

func TestTerminalPhaseIsSticky(t *testing.T) {
	h := newHarness(t, identity.Development, experiment("e", func(e *chaosv1.ChaosExperiment) { e.Spec.ClusterID = "prod-eu-1" }), namespace("demo", optedIn))
	h.reconcile("e")
	h.r.Identity.ClusterID = "prod-eu-1"
	h.reconcile("e")
	if h.get("e").Status.Phase != chaosv1.PhaseRejected {
		t.Fatal("terminal phase must not change")
	}
}

func TestMessagesAreBounded(t *testing.T) {
	h := newHarness(t, identity.Development, experiment("e", func(e *chaosv1.ChaosExperiment) { e.Spec.ClusterID = strings.Repeat("x", 5000) }))
	h.reconcile("e")
	if got := h.get("e"); len(got.Status.Message) > 1024 {
		t.Fatalf("status message length %d exceeds 1024", len(got.Status.Message))
	}
}
