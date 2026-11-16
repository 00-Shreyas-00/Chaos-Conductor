// Package clusterstest provides an in-memory clusters.Connector for tests.
package clusterstest

import (
	"context"
	"errors"
	"fmt"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
)

// Fake is a programmable connector.
type Fake struct {
	mu          sync.Mutex
	ID          string
	Pol         *chaosv1.ChaosPolicy
	LockList    []chaosv1.ChaosLock
	Submitted   []*chaosv1.ChaosExperiment
	Cancelled   []string
	SubmitErr   error
	Unavailable bool
}

// New returns a Fake with a permissive development policy for namespace "demo".
func New() *Fake {
	return &Fake{ID: "dev-kind-01", Pol: &chaosv1.ChaosPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "default", ResourceVersion: "42"},
		Spec: chaosv1.ChaosPolicySpec{
			Environment: "development", AllowedFaults: []chaosv1.FaultType{chaosv1.FaultPodKill}, AllowedNamespaces: []string{"demo"},
			Limits:   chaosv1.PolicyLimits{MaxPodKillCount: 3, MaxDuration: "10m", MaxConcurrentExperiments: 2},
			Approval: chaosv1.ApprovalPolicy{Required: chaosv1.ApprovalNever},
		},
	}}
}

var errDown = errors.New("cluster down")

func (f *Fake) ClusterID() string { return f.ID }

func (f *Fake) Policy(context.Context) (*chaosv1.ChaosPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Unavailable {
		return nil, errDown
	}
	return f.Pol, nil
}

func (f *Fake) Locks(context.Context) ([]chaosv1.ChaosLock, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Unavailable {
		return nil, errDown
	}
	return f.LockList, nil
}

func (f *Fake) Submit(_ context.Context, e *chaosv1.ChaosExperiment) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.SubmitErr != nil {
		return f.SubmitErr
	}
	f.Submitted = append(f.Submitted, e.DeepCopy())
	return nil
}

func (f *Fake) Cancel(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Cancelled = append(f.Cancelled, name)
	return nil
}

func (f *Fake) EngageLock(_ context.Context, reason, by string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name := fmt.Sprintf("web-emergency-stop-%d", len(f.LockList)+1)
	f.LockList = append(f.LockList, chaosv1.ChaosLock{ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: chaosv1.ChaosLockSpec{Reason: reason, EngagedBy: by}})
	return name, nil
}

func (f *Fake) Watch(ctx context.Context, _ func(*chaosv1.ChaosExperiment)) error {
	<-ctx.Done()
	return ctx.Err()
}
