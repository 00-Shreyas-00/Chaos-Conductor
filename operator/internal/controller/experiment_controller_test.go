package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
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
	"github.com/kubechaos/kubechaos/pkg/chaosapi/attestation"

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

func policyFor(env string, mutate func(*chaosv1.ChaosPolicy)) *chaosv1.ChaosPolicy {
	p := &chaosv1.ChaosPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: chaosv1.PolicyName},
		Spec: chaosv1.ChaosPolicySpec{
			Environment: env, AllowedFaults: []chaosv1.FaultType{chaosv1.FaultPodKill}, AllowedNamespaces: []string{"demo"},
			Limits:   chaosv1.PolicyLimits{MaxPodKillCount: 2, MaxDuration: "5m", MaxConcurrentExperiments: 1, MinReadyReplicas: 1},
			Approval: chaosv1.ApprovalPolicy{Required: chaosv1.ApprovalNever},
		},
	}
	if mutate != nil {
		mutate(p)
	}
	return p
}

func devPolicy() *chaosv1.ChaosPolicy { return policyFor("development", nil) }

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
	h := &harness{t: t, c: c, clock: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)}
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

func lock() *chaosv1.ChaosLock {
	return &chaosv1.ChaosLock{ObjectMeta: metav1.ObjectMeta{Name: "emergency"},
		Spec: chaosv1.ChaosLockSpec{Reason: "incident", EngagedBy: "oncall"}}
}

// ---------------------------------------------------------------- admission ----------

func TestAdmissionDecisions(t *testing.T) {
	running := experiment("other", nil)
	running.Status.Phase = chaosv1.PhaseRunning
	cases := []struct {
		name   string
		env    identity.Environment
		exp    *chaosv1.ChaosExperiment
		extra  []client.Object
		phase  chaosv1.ExperimentPhase
		reason string
	}{
		{"other cluster", identity.Development, experiment("e", func(e *chaosv1.ChaosExperiment) { e.Spec.ClusterID = "prod-eu-1" }),
			[]client.Object{devPolicy(), namespace("demo", optedIn)}, chaosv1.PhaseRejected, ReasonClusterMismatch},
		{"wrong namespace", identity.Development, experiment("e", func(e *chaosv1.ChaosExperiment) { e.Namespace = "default" }),
			[]client.Object{devPolicy(), namespace("demo", optedIn)}, chaosv1.PhaseRejected, ReasonWrongNamespace},
		{"invalid (defence in depth)", identity.Development, experiment("e", func(e *chaosv1.ChaosExperiment) { e.Spec.Steps[0].Fault.PodKill.Count = 10000 }),
			[]client.Object{devPolicy(), namespace("demo", optedIn)}, chaosv1.PhaseRejected, ReasonInvalidSpec},
		{"cancelled before start", identity.Development, experiment("e", func(e *chaosv1.ChaosExperiment) { e.Spec.Cancel = true }),
			[]client.Object{devPolicy(), namespace("demo", optedIn)}, chaosv1.PhaseAborted, ReasonCancelledByUser},
		{"emergency stop engaged", identity.Development, experiment("e", nil),
			[]client.Object{devPolicy(), namespace("demo", optedIn), lock()}, chaosv1.PhaseRejected, ReasonSystemLocked},
		{"no policy", identity.Development, experiment("e", nil),
			[]client.Object{namespace("demo", optedIn)}, chaosv1.PhaseRejected, ReasonPolicyUnavailable},
		{"policy for another environment", identity.Development, experiment("e", nil),
			[]client.Object{policyFor("staging", nil), namespace("demo", optedIn)}, chaosv1.PhaseRejected, ReasonPolicyViolation},
		{"namespace not in policy", identity.Development, experiment("e", nil),
			[]client.Object{policyFor("development", func(p *chaosv1.ChaosPolicy) { p.Spec.AllowedNamespaces = []string{"other"} }), namespace("demo", optedIn)},
			chaosv1.PhaseRejected, ReasonPolicyViolation},
		{"count above policy", identity.Development, experiment("e", func(e *chaosv1.ChaosExperiment) { e.Spec.Steps[0].Fault.PodKill.Count = 3 }),
			[]client.Object{devPolicy(), namespace("demo", optedIn)}, chaosv1.PhaseRejected, ReasonPolicyViolation},
		{"concurrency limit", identity.Development, experiment("e", nil),
			[]client.Object{devPolicy(), namespace("demo", optedIn), running}, chaosv1.PhasePending, ReasonConcurrencyLimit},
		{"production without approval", identity.Production, experiment("e", nil),
			[]client.Object{policyFor("production", func(p *chaosv1.ChaosPolicy) {
				p.Spec.Approval = chaosv1.ApprovalPolicy{Required: chaosv1.ApprovalAlways, MinApprovals: 1}
			}), namespace("demo", optedIn)}, chaosv1.PhaseRejected, ReasonApprovalRequired},
		{"namespace missing / not granted", identity.Development, experiment("e", nil),
			[]client.Object{devPolicy()}, chaosv1.PhaseRejected, ReasonNamespaceNotOptedIn},
		{"namespace without opt-in label", identity.Development, experiment("e", nil),
			[]client.Object{devPolicy(), namespace("demo", nil)}, chaosv1.PhaseRejected, ReasonNamespaceNotOptedIn},
		{"protected namespace", identity.Development, experiment("e", nil),
			[]client.Object{devPolicy(), namespace("demo", map[string]string{chaosv1.LabelEnabled: "true", chaosv1.LabelProtected: "true"})},
			chaosv1.PhaseRejected, ReasonNamespaceProtected},
		{"accepted", identity.Development, experiment("e", nil),
			[]client.Object{devPolicy(), namespace("demo", optedIn)}, chaosv1.PhaseRunning, ReasonAccepted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			objs := append([]client.Object{c.exp, webPod("a"), webPod("b")}, c.extra...)
			h := newHarness(t, c.env, objs...)
			if _, err := h.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: c.exp.Namespace, Name: "e"}}); err != nil {
				t.Fatal(err)
			}
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

// ---------------------------------------------------------------- approvals ----------

type approvalFixture struct {
	priv ed25519.PrivateKey
	key  chaosv1.TrustedKey
}

func newApprovalFixture(t *testing.T) approvalFixture {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return approvalFixture{priv: priv, key: chaosv1.TrustedKey{KID: "approver-1", PublicKey: base64.StdEncoding.EncodeToString(pub)}}
}

func (f approvalFixture) sign(t *testing.T, e *chaosv1.ChaosExperiment, now time.Time, jti, group, approver string) string {
	tok, err := attestation.Sign(f.priv, f.key.KID, attestation.Claims{
		Claims: jwt.Claims{Issuer: attestation.Issuer, Audience: jwt.Audience{attestation.Audience("dev-kind-01")}, ID: jti,
			IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Hour))},
		ClusterID: "dev-kind-01", Environment: "production", Namespaces: []string{"demo"},
		SpecSHA256: attestation.SpecSHA256(&e.Spec), Requester: e.Spec.RequestedBy, ApproverGroup: group,
		Approvals: []attestation.Approval{{Issuer: "https://idp", Subject: approver, AuthTime: now.Unix(), At: now.Unix()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestApprovalGate(t *testing.T) {
	const group = "/teams/demo/head-developers"
	nsWithGroup := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "demo", Labels: optedIn,
		Annotations: map[string]string{chaosv1.AnnotationApproverGroup: group}}}

	run := func(t *testing.T, f approvalFixture, mutate func(e *chaosv1.ChaosExperiment, now time.Time), extra ...client.Object) (chaosv1.ChaosExperiment, *harness) {
		pol := policyFor("production", func(p *chaosv1.ChaosPolicy) {
			p.Spec.Approval = chaosv1.ApprovalPolicy{Required: chaosv1.ApprovalAlways, MinApprovals: 1, MaxAttestationAge: "1h",
				TrustedKeys: []chaosv1.TrustedKey{f.key}}
		})
		e := experiment("e", nil)
		h := newHarness(t, identity.Production)
		if mutate != nil {
			mutate(e, h.clock)
		}
		for _, o := range append([]client.Object{pol, nsWithGroup, e, webPod("a"), webPod("b")}, extra...) {
			o = o.DeepCopyObject().(client.Object) // fixtures are shared between subtests
			o.SetResourceVersion("")
			if err := h.c.Create(context.Background(), o); err != nil {
				t.Fatal(err)
			}
		}
		h.reconcile("e")
		return h.get("e"), h
	}
	f := newApprovalFixture(t)

	t.Run("valid attestation is accepted and consumed", func(t *testing.T) {
		got, h := run(t, f, func(e *chaosv1.ChaosExperiment, now time.Time) {
			e.Annotations = map[string]string{chaosv1.AnnotationApproval: f.sign(t, e, now, "jti-ok", group, "bob")}
		})
		if got.Status.Phase != chaosv1.PhaseRunning {
			t.Fatalf("phase=%s: %s", got.Status.Phase, got.Status.Message)
		}
		var use chaosv1.ChaosAttestationUse
		if err := h.c.Get(context.Background(), types.NamespacedName{Name: "jti-jti-ok"}, &use); err != nil {
			t.Fatal("attestation use must be recorded")
		}
	})
	t.Run("replayed attestation is rejected", func(t *testing.T) {
		used := &chaosv1.ChaosAttestationUse{ObjectMeta: metav1.ObjectMeta{Name: "jti-jti-replay"}}
		got, _ := run(t, f, func(e *chaosv1.ChaosExperiment, now time.Time) {
			e.Annotations = map[string]string{chaosv1.AnnotationApproval: f.sign(t, e, now, "jti-replay", group, "bob")}
		}, used)
		if got.Status.Phase != chaosv1.PhaseRejected || !strings.Contains(got.Status.Message, "replay") {
			t.Fatalf("phase=%s msg=%s", got.Status.Phase, got.Status.Message)
		}
	})
	t.Run("wrong approver group", func(t *testing.T) {
		got, _ := run(t, f, func(e *chaosv1.ChaosExperiment, now time.Time) {
			e.Annotations = map[string]string{chaosv1.AnnotationApproval: f.sign(t, e, now, "jti-g", "/teams/other/leads", "bob")}
		})
		if got.Status.Phase != chaosv1.PhaseRejected || reason(got, chaosv1.ConditionAccepted) != ReasonApprovalInvalid {
			t.Fatalf("phase=%s msg=%s", got.Status.Phase, got.Status.Message)
		}
	})
	t.Run("self approval", func(t *testing.T) {
		got, _ := run(t, f, func(e *chaosv1.ChaosExperiment, now time.Time) {
			e.Annotations = map[string]string{chaosv1.AnnotationApproval: f.sign(t, e, now, "jti-s", group, "alice")}
		})
		if got.Status.Phase != chaosv1.PhaseRejected || !strings.Contains(got.Status.Message, "own experiment") {
			t.Fatalf("phase=%s msg=%s", got.Status.Phase, got.Status.Message)
		}
	})
	t.Run("signed by an untrusted key", func(t *testing.T) {
		other := newApprovalFixture(t)
		got, _ := run(t, f, func(e *chaosv1.ChaosExperiment, now time.Time) {
			e.Annotations = map[string]string{chaosv1.AnnotationApproval: other.sign(t, e, now, "jti-k", group, "bob")}
		})
		if got.Status.Phase != chaosv1.PhaseRejected || reason(got, chaosv1.ConditionAccepted) != ReasonApprovalInvalid {
			t.Fatalf("phase=%s msg=%s", got.Status.Phase, got.Status.Message)
		}
	})
}

// ---------------------------------------------------------------- execution ----------

func TestPodKillLifecycleWithCriteria(t *testing.T) {
	exp := experiment("e", func(e *chaosv1.ChaosExperiment) {
		e.Spec.SuccessCriteria = []chaosv1.Criterion{
			{Metric: chaosv1.MetricAvailableReplicas, Operator: "ge", Value: "3", Weight: 3},
			{Metric: chaosv1.MetricRecoveryTime, Operator: "lt", Value: "2s", Weight: 1}, // recovery takes 5s: fails
		}
	})
	h := newHarness(t, identity.Development, exp, devPolicy(), namespace("demo", optedIn), webPod("a"), webPod("b"), webPod("c"))

	h.reconcile("e") // admit -> Running
	if e := h.get("e"); e.Status.Phase != chaosv1.PhaseRunning || len(e.Status.Steps) != 2 {
		t.Fatalf("not started: %+v", e.Status)
	}
	h.reconcile("e") // step 0: plan, record intent, delete, Observing
	st := h.get("e").Status.Steps[0]
	if st.Phase != chaosv1.StepObserving || len(st.Targets) != 1 || st.ReadyBefore != 3 || st.InjectedAt == nil || h.podCount() != 2 {
		t.Fatalf("after injection: %+v pods=%d", st, h.podCount())
	}
	h.clock = h.clock.Add(2 * time.Second)
	h.reconcile("e")
	if h.get("e").Status.Steps[0].Phase != chaosv1.StepObserving {
		t.Fatal("must keep observing until recovered")
	}
	if err := h.c.Create(context.Background(), webPod("d")); err != nil { // the ReplicaSet "recreates" the pod
		t.Fatal(err)
	}
	h.clock = h.clock.Add(3 * time.Second)
	h.reconcile("e") // recovered
	if r := h.get("e").Status.Steps[0].RecoveryMillis; r == nil || *r != 5000 {
		t.Fatalf("recovery not recorded: %v", r)
	}
	h.reconcile("e") // wait starts
	h.clock = h.clock.Add(10 * time.Second)
	h.reconcile("e") // wait done
	h.reconcile("e") // finish + criteria
	e := h.get("e")
	if e.Status.Phase != chaosv1.PhaseCompleted || e.Status.Result != "Failed" || e.Status.Score == nil || *e.Status.Score != 75 ||
		len(e.Status.Criteria) != 2 || !e.Status.Criteria[0].Passed || e.Status.Criteria[1].Passed {
		t.Fatalf("phase=%s result=%s score=%v criteria=%+v", e.Status.Phase, e.Status.Result, e.Status.Score, e.Status.Criteria)
	}
	if !strings.Contains(e.Status.Message, "resilience score 75/100") {
		t.Fatalf("message %q", e.Status.Message)
	}
	h.reconcile("e") // terminal: no-op
	if h.podCount() != 3 {
		t.Fatal("a completed experiment must not touch pods again")
	}
}

func TestEmergencyStopAbortsRunningExperiment(t *testing.T) {
	exp := experiment("e", func(e *chaosv1.ChaosExperiment) {
		e.Spec.Steps = []chaosv1.Step{{Wait: &chaosv1.WaitStep{Duration: "30s"}}, e.Spec.Steps[0]}
	})
	h := newHarness(t, identity.Development, exp, devPolicy(), namespace("demo", optedIn), webPod("a"), webPod("b"))
	h.reconcile("e") // start
	h.reconcile("e") // wait running
	if err := h.c.Create(context.Background(), lock()); err != nil {
		t.Fatal(err)
	}
	h.clock = h.clock.Add(time.Second)
	h.reconcile("e")
	e := h.get("e")
	if e.Status.Phase != chaosv1.PhaseAborted || reason(e, chaosv1.ConditionFinished) != ReasonSystemLocked {
		t.Fatalf("phase=%s reason=%s", e.Status.Phase, reason(e, chaosv1.ConditionFinished))
	}
	if h.podCount() != 2 {
		t.Fatal("locked experiment must not kill pods")
	}
	reqs := h.r.allActive(context.Background(), nil)
	if len(reqs) != 0 {
		t.Fatalf("aborted experiment must not be re-queued by lock events: %v", reqs)
	}
}

func TestPolicyRemovedMidRunStopsInjection(t *testing.T) {
	exp := experiment("e", func(e *chaosv1.ChaosExperiment) {
		e.Spec.Steps = []chaosv1.Step{{Wait: &chaosv1.WaitStep{Duration: "5s"}}, e.Spec.Steps[0]}
	})
	pol := devPolicy()
	h := newHarness(t, identity.Development, exp, pol, namespace("demo", optedIn), webPod("a"), webPod("b"))
	h.reconcile("e") // start
	h.reconcile("e") // wait
	if err := h.c.Delete(context.Background(), pol); err != nil {
		t.Fatal(err)
	}
	h.clock = h.clock.Add(6 * time.Second)
	h.reconcile("e") // wait done
	h.reconcile("e") // fault step: policy gone -> fail
	e := h.get("e")
	if e.Status.Phase != chaosv1.PhaseFailed || reason(e, chaosv1.ConditionFinished) != ReasonPolicyUnavailable || h.podCount() != 2 {
		t.Fatalf("phase=%s reason=%s pods=%d", e.Status.Phase, reason(e, chaosv1.ConditionFinished), h.podCount())
	}
}

func TestInterruptedInjectionIsNotRetried(t *testing.T) {
	started := metav1.NewTime(time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC))
	exp := experiment("e", nil)
	exp.Status = chaosv1.ChaosExperimentStatus{
		Phase: chaosv1.PhaseRunning, StartedAt: &started,
		Steps: []chaosv1.StepStatus{
			{Phase: chaosv1.StepInjecting, Targets: []chaosv1.PodRef{{Namespace: "demo", Name: "a", UID: "uid-a"}}},
			{Phase: chaosv1.StepPending},
		},
	}
	h := newHarness(t, identity.Development, exp, devPolicy(), namespace("demo", optedIn), webPod("a"), webPod("b"))
	h.reconcile("e")
	e := h.get("e")
	if e.Status.Phase != chaosv1.PhaseFailed || reason(e, chaosv1.ConditionFinished) != ReasonInterrupted ||
		e.Status.Steps[0].Phase != chaosv1.StepFailed || e.Status.Steps[1].Phase != chaosv1.StepSkipped || h.podCount() != 2 {
		t.Fatalf("status %+v", e.Status)
	}
}

func TestCancelDuringWait(t *testing.T) {
	exp := experiment("e", func(e *chaosv1.ChaosExperiment) {
		e.Spec.Steps = []chaosv1.Step{{Wait: &chaosv1.WaitStep{Duration: "30s"}}, e.Spec.Steps[0]}
	})
	h := newHarness(t, identity.Development, exp, devPolicy(), namespace("demo", optedIn), webPod("a"), webPod("b"))
	h.reconcile("e")
	h.reconcile("e")
	e := h.get("e")
	e.Spec.Cancel = true
	if err := h.c.Update(context.Background(), &e); err != nil {
		t.Fatal(err)
	}
	h.clock = h.clock.Add(time.Second)
	h.reconcile("e")
	e = h.get("e")
	if e.Status.Phase != chaosv1.PhaseAborted || e.Status.Steps[0].Phase != chaosv1.StepSkipped || e.Status.Steps[1].Phase != chaosv1.StepSkipped || h.podCount() != 2 {
		t.Fatalf("status %+v", e.Status)
	}
}

func TestMaxDurationWhileObserving(t *testing.T) {
	exp := experiment("e", func(e *chaosv1.ChaosExperiment) { e.Spec.MaxDuration = "30s"; e.Spec.Steps = e.Spec.Steps[:1] })
	h := newHarness(t, identity.Development, exp, devPolicy(), namespace("demo", optedIn), webPod("a"), webPod("b"))
	h.reconcile("e")
	h.reconcile("e")
	h.clock = h.clock.Add(31 * time.Second)
	h.reconcile("e")
	e := h.get("e")
	if e.Status.Phase != chaosv1.PhaseFailed || reason(e, chaosv1.ConditionFinished) != ReasonMaxDuration || e.Status.Steps[0].Phase != chaosv1.StepFailed {
		t.Fatalf("status %+v", e.Status)
	}
}

func TestBlastRadiusAtExecutionDeletesNothing(t *testing.T) {
	exp := experiment("e", func(e *chaosv1.ChaosExperiment) { e.Spec.Steps[0].Fault.PodKill.Count = 2 })
	h := newHarness(t, identity.Development, exp, devPolicy(), namespace("demo", optedIn), webPod("a"), webPod("b"))
	h.reconcile("e")
	h.reconcile("e")
	e := h.get("e")
	if e.Status.Phase != chaosv1.PhaseFailed || !strings.Contains(e.Status.Message, "blast radius exceeded") ||
		e.Status.Steps[0].Phase != chaosv1.StepFailed || len(e.Status.Steps[0].Targets) != 0 || h.podCount() != 2 {
		t.Fatalf("status %+v", e.Status)
	}
}

func TestTerminalPhaseIsSticky(t *testing.T) {
	h := newHarness(t, identity.Development, experiment("e", func(e *chaosv1.ChaosExperiment) { e.Spec.ClusterID = "prod-eu-1" }), devPolicy(), namespace("demo", optedIn))
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
