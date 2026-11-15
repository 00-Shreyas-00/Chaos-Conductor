// Package faults implements the finite set of failure primitives. Each primitive separates
// planning (read-only: choose targets, check blast radius) from injection (destructive) so
// the plan can be recorded before anything is changed (at-most-once execution).
package faults

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sort"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
)

// PodKill describes the primitive (architecture §7 primitive interface).
var PodKill = Descriptor{
	Name:        chaosv1.FaultPodKill,
	Description: "Deletes up to `count` Ready, controller-managed pods matching the selector.",
	Risk:        RiskMedium,
	// Exactly what the operator needs per opted-in namespace (deploy/helm/.../targets-rbac.yaml).
	RequiredPermissions: []string{"pods: get, list, delete (target namespace only)"},
}

// RiskLevel of a primitive.
type RiskLevel string

const (
	RiskLow      RiskLevel = "Low"
	RiskMedium   RiskLevel = "Medium"
	RiskHigh     RiskLevel = "High"
	RiskCritical RiskLevel = "Critical"
)

// Descriptor documents a primitive.
type Descriptor struct {
	Name                chaosv1.FaultType
	Description         string
	Risk                RiskLevel
	RequiredPermissions []string
}

// Plan errors. Each one rejects the step; none leads to "best effort" execution.
var (
	ErrNoTargets   = errors.New("selector matches no pods")
	ErrNoEligible  = errors.New("no eligible pods: targets must be Running, Ready, controller-managed and not protected")
	ErrBlastRadius = errors.New("blast radius exceeded")
)

// PodKillPlan is the read-only result of planning.
type PodKillPlan struct {
	Targets     []chaosv1.PodRef
	ReadyBefore int32
}

// PlanPodKill chooses the pods to delete. Rules (fail closed):
//   - only pods matching every selector label in the single target namespace;
//   - only Running, Ready, not-terminating pods with a controller owner (a bare pod would
//     never come back) and without the protected label; never static/mirror pods;
//   - per owning controller at least one Ready pod must survive (never kill the last ready
//     replica, D6). If `count` pods cannot be chosen under these rules the step is rejected —
//     it never silently kills fewer.
//
// Selection among eligible pods is uniformly random (crypto/rand).
func PlanPodKill(ctx context.Context, r client.Reader, f *chaosv1.FaultStep) (PodKillPlan, error) {
	if f == nil || f.Type != chaosv1.FaultPodKill || f.PodKill == nil {
		return PodKillPlan{}, errors.New("not a PodKill step")
	}
	pods, err := listTargets(ctx, r, f.Target)
	if err != nil {
		return PodKillPlan{}, err
	}
	if len(pods) == 0 {
		return PodKillPlan{}, ErrNoTargets
	}

	var plan PodKillPlan
	readyPerOwner := map[types.UID]int{}
	var eligible []corev1.Pod
	for _, p := range pods {
		if !isReady(&p) {
			continue
		}
		plan.ReadyBefore++
		owner := controllerUID(&p)
		if owner != "" {
			readyPerOwner[owner]++
		}
		if owner != "" && !isProtected(&p) && !isMirror(&p) {
			eligible = append(eligible, p)
		}
	}
	if len(eligible) == 0 {
		return PodKillPlan{}, ErrNoEligible
	}

	if err := shuffle(eligible); err != nil {
		return PodKillPlan{}, err
	}
	want := int(f.PodKill.Count)
	killedPerOwner := map[types.UID]int{}
	for _, p := range eligible {
		if len(plan.Targets) == want {
			break
		}
		o := controllerUID(&p)
		if killedPerOwner[o]+1 >= readyPerOwner[o] { // would leave this workload with no Ready pod
			continue
		}
		killedPerOwner[o]++
		plan.Targets = append(plan.Targets, chaosv1.PodRef{Namespace: p.Namespace, Name: p.Name, UID: string(p.UID)})
	}
	if len(plan.Targets) < want {
		return PodKillPlan{}, fmt.Errorf("%w: requested %d pod(s), but only %d can be killed without leaving a workload with no Ready replica",
			ErrBlastRadius, want, len(plan.Targets))
	}
	sort.Slice(plan.Targets, func(i, j int) bool { return plan.Targets[i].Name < plan.Targets[j].Name })
	return plan, nil
}

// KillResult reports what happened to one target.
type KillResult struct {
	Pod     chaosv1.PodRef
	Deleted bool
	Note    string
}

// InjectPodKill deletes exactly the planned pods. Each delete carries a UID precondition, so a
// replacement pod that reused the name is never hit. Pods already gone are reported, not
// retried. Any other error stops further deletions.
func InjectPodKill(ctx context.Context, w client.Writer, targets []chaosv1.PodRef, gracePeriodSeconds int64) ([]KillResult, error) {
	var results []KillResult
	for _, t := range targets {
		uid := types.UID(t.UID)
		pod := &corev1.Pod{}
		pod.Namespace, pod.Name = t.Namespace, t.Name
		err := w.Delete(ctx, pod, client.GracePeriodSeconds(gracePeriodSeconds), client.Preconditions{UID: &uid})
		switch {
		case err == nil:
			results = append(results, KillResult{Pod: t, Deleted: true})
		case apierrors.IsNotFound(err), apierrors.IsConflict(err):
			results = append(results, KillResult{Pod: t, Note: "pod no longer exists (or was replaced); not deleted"})
		default:
			return results, fmt.Errorf("delete pod %s/%s: %w", t.Namespace, t.Name, err)
		}
	}
	return results, nil
}

// ReadyCount counts Ready pods matching the target selector, excluding the given UIDs (the
// killed pods, which may linger while terminating). Used to observe recovery.
func ReadyCount(ctx context.Context, r client.Reader, target chaosv1.Target, exclude []chaosv1.PodRef) (int32, error) {
	pods, err := listTargets(ctx, r, target)
	if err != nil {
		return 0, err
	}
	skip := map[string]bool{}
	for _, e := range exclude {
		skip[e.UID] = true
	}
	var n int32
	for _, p := range pods {
		if !skip[string(p.UID)] && isReady(&p) {
			n++
		}
	}
	return n, nil
}

func listTargets(ctx context.Context, r client.Reader, t chaosv1.Target) ([]corev1.Pod, error) {
	sel := client.MatchingLabels{}
	for k, v := range t.Selector {
		sel[k] = string(v)
	}
	var list corev1.PodList
	if err := r.List(ctx, &list, client.InNamespace(t.Namespace), sel); err != nil {
		return nil, fmt.Errorf("list pods in %s: %w", t.Namespace, err)
	}
	return list.Items, nil
}

func isReady(p *corev1.Pod) bool {
	if p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func controllerUID(p *corev1.Pod) types.UID {
	for _, o := range p.OwnerReferences {
		if o.Controller != nil && *o.Controller {
			return o.UID
		}
	}
	return ""
}

func isProtected(p *corev1.Pod) bool { return p.Labels[chaosv1.LabelProtected] == "true" }

func isMirror(p *corev1.Pod) bool {
	_, ok := p.Annotations[corev1.MirrorPodAnnotationKey]
	return ok
}

// shuffle performs a Fisher–Yates shuffle with crypto/rand.
func shuffle(pods []corev1.Pod) error {
	for i := len(pods) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		k := int(j.Int64())
		pods[i], pods[k] = pods[k], pods[i]
	}
	return nil
}
