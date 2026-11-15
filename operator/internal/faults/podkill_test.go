package faults

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
)

type podOpt func(*corev1.Pod)

func owner(uid string) podOpt {
	return func(p *corev1.Pod) {
		t := true
		p.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: uid, UID: types.UID(uid), Controller: &t}}
	}
}
func notReady(p *corev1.Pod)  { p.Status.Conditions[0].Status = corev1.ConditionFalse }
func pending(p *corev1.Pod)   { p.Status.Phase = corev1.PodPending }
func protected(p *corev1.Pod) { p.Labels[chaosv1.LabelProtected] = "true" }
func mirror(p *corev1.Pod)    { p.Annotations = map[string]string{corev1.MirrorPodAnnotationKey: "x"} }
func terminating(p *corev1.Pod) {
	now := metav1.Now()
	p.DeletionTimestamp = &now
	p.Finalizers = []string{"test/hold"}
}
func label(k, v string) podOpt { return func(p *corev1.Pod) { p.Labels[k] = v } }

func pod(name string, opts ...podOpt) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: name, UID: types.UID("uid-" + name), Labels: map[string]string{"app": "web"}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

func step(count int32) *chaosv1.FaultStep {
	return &chaosv1.FaultStep{
		Type:    chaosv1.FaultPodKill,
		Target:  chaosv1.Target{Namespace: "demo", Selector: map[string]chaosv1.LabelValue{"app": "web"}},
		PodKill: &chaosv1.PodKillParams{Count: count},
	}
}

func reader(pods ...*corev1.Pod) client.Client {
	objs := make([]client.Object, len(pods))
	for i, p := range pods {
		objs[i] = p
	}
	return fake.NewClientBuilder().WithObjects(objs...).Build()
}

func TestPlanPodKill(t *testing.T) {
	ctx := context.Background()
	three := []*corev1.Pod{pod("a", owner("rs1")), pod("b", owner("rs1")), pod("c", owner("rs1"))}

	t.Run("kills requested count, records ready-before", func(t *testing.T) {
		plan, err := PlanPodKill(ctx, reader(three...), step(2))
		if err != nil || len(plan.Targets) != 2 || plan.ReadyBefore != 3 {
			t.Fatalf("plan=%+v err=%v", plan, err)
		}
	})

	t.Run("never kills the last ready replica", func(t *testing.T) {
		_, err := PlanPodKill(ctx, reader(three...), step(3))
		if !errors.Is(err, ErrBlastRadius) {
			t.Fatalf("want ErrBlastRadius, got %v", err)
		}
		_, err = PlanPodKill(ctx, reader(pod("solo", owner("rs-solo"))), step(1))
		if !errors.Is(err, ErrBlastRadius) {
			t.Fatalf("single replica: want ErrBlastRadius, got %v", err)
		}
	})

	t.Run("last-replica rule is per workload", func(t *testing.T) {
		// rs1 has 2 ready (1 killable), rs2 has 2 ready (1 killable) => 2 total, never 2 from one workload.
		pods := []*corev1.Pod{pod("a", owner("rs1")), pod("b", owner("rs1")), pod("c", owner("rs2")), pod("d", owner("rs2"))}
		for i := 0; i < 50; i++ {
			plan, err := PlanPodKill(ctx, reader(pods...), step(2))
			if err != nil {
				t.Fatal(err)
			}
			owners := map[string]int{}
			for _, tgt := range plan.Targets {
				if tgt.Name == "a" || tgt.Name == "b" {
					owners["rs1"]++
				} else {
					owners["rs2"]++
				}
			}
			if owners["rs1"] != 1 || owners["rs2"] != 1 {
				t.Fatalf("killed %v — would empty a workload", owners)
			}
		}
		if _, err := PlanPodKill(ctx, reader(pods...), step(3)); !errors.Is(err, ErrBlastRadius) {
			t.Fatalf("3 of 4 across two 2-replica workloads must be rejected, got %v", err)
		}
	})

	t.Run("ineligible pods are never chosen", func(t *testing.T) {
		pods := []*corev1.Pod{
			pod("ok1", owner("rs1")), pod("ok2", owner("rs1")),
			pod("bare"),                             // no controller: would never come back
			pod("prot", owner("rs1"), protected),    // protected label
			pod("mirror", owner("rs1"), mirror),     // static pod
			pod("notready", owner("rs1"), notReady), // not Ready
			pod("pending", owner("rs1"), pending),   // not Running
			pod("dying", owner("rs1"), terminating), // already terminating
			pod("other", owner("rs1"), label("app", "other")),
		}
		for i := 0; i < 50; i++ {
			plan, err := PlanPodKill(ctx, reader(pods...), step(1))
			if err != nil {
				t.Fatal(err)
			}
			if n := plan.Targets[0].Name; n != "ok1" && n != "ok2" {
				t.Fatalf("chose ineligible pod %q", n)
			}
		}
	})

	t.Run("protected pods still count as ready survivors", func(t *testing.T) {
		// rs1: one eligible + one protected, both Ready => the eligible one may be killed.
		plan, err := PlanPodKill(ctx, reader(pod("ok", owner("rs1")), pod("prot", owner("rs1"), protected)), step(1))
		if err != nil || plan.Targets[0].Name != "ok" {
			t.Fatalf("plan=%+v err=%v", plan, err)
		}
	})

	t.Run("no matches and no eligible pods are errors", func(t *testing.T) {
		if _, err := PlanPodKill(ctx, reader(), step(1)); !errors.Is(err, ErrNoTargets) {
			t.Fatalf("want ErrNoTargets, got %v", err)
		}
		if _, err := PlanPodKill(ctx, reader(pod("bare"), pod("bare2")), step(1)); !errors.Is(err, ErrNoEligible) {
			t.Fatalf("want ErrNoEligible, got %v", err)
		}
	})

	t.Run("other namespaces are never considered", func(t *testing.T) {
		other := pod("x", owner("rs9"))
		other.Namespace = "prod"
		if _, err := PlanPodKill(ctx, reader(other, pod("y", owner("rs9"))), step(1)); !errors.Is(err, ErrNoEligible) && !errors.Is(err, ErrBlastRadius) {
			t.Fatalf("got %v", err)
		}
	})
}

// The controller-runtime fake client ignores delete preconditions, so this interceptor asserts
// that every delete carries the exact UID precondition and grace period, and emulates the API
// server's 409 on a UID mismatch. The real API server behaviour is verified live in kind.
func TestInjectPodKillUsesUIDPrecondition(t *testing.T) {
	ctx := context.Background()
	base := reader(pod("a", owner("rs1")), pod("b", owner("rs1")))
	c := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
		Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			do := &client.DeleteOptions{}
			do.ApplyOptions(opts)
			if do.Preconditions == nil || do.Preconditions.UID == nil {
				t.Fatalf("delete of %s without UID precondition", obj.GetName())
			}
			if do.GracePeriodSeconds == nil || *do.GracePeriodSeconds != 7 {
				t.Fatalf("delete of %s without the requested grace period", obj.GetName())
			}
			var live corev1.Pod
			if err := cl.Get(ctx, client.ObjectKeyFromObject(obj), &live); err != nil {
				return err
			}
			if live.UID != *do.Preconditions.UID {
				return apierrors.NewConflict(corev1.Resource("pods"), obj.GetName(), errors.New("UID precondition failed"))
			}
			return cl.Delete(ctx, obj, opts...)
		},
	})
	res, err := InjectPodKill(ctx, c, []chaosv1.PodRef{
		{Namespace: "demo", Name: "a", UID: "uid-a"},
		{Namespace: "demo", Name: "b", UID: "uid-REPLACED"}, // same name, different pod
		{Namespace: "demo", Name: "gone", UID: "uid-gone"},
	}, 7)
	if err != nil {
		t.Fatal(err)
	}
	if !res[0].Deleted || res[1].Deleted || res[2].Deleted {
		t.Fatalf("results %+v", res)
	}
	var p corev1.Pod
	if err := base.Get(ctx, types.NamespacedName{Namespace: "demo", Name: "b"}, &p); err != nil {
		t.Fatal("pod b (UID mismatch) must not be deleted")
	}
}

func TestReadyCountExcludesKilled(t *testing.T) {
	c := reader(pod("a", owner("rs1")), pod("b", owner("rs1")), pod("c", owner("rs1"), notReady))
	n, err := ReadyCount(context.Background(), c, step(1).Target, []chaosv1.PodRef{{UID: "uid-a"}})
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}
