// Package clusters connects the control plane to a cluster (architecture §11). The interface
// keeps phase 2 (agent dialling out over mTLS gRPC) a new implementation, not a rewrite. The CRD
// implementation uses a dedicated, narrowly scoped ServiceAccount: it can request experiments,
// read policy and engage the lock — nothing else.
package clusters

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
)

// Connector is the control plane's view of one cluster.
type Connector interface {
	ClusterID() string
	// Policy returns the cluster's ChaosPolicy, or nil if none is installed.
	Policy(ctx context.Context) (*chaosv1.ChaosPolicy, error)
	Locks(ctx context.Context) ([]chaosv1.ChaosLock, error)
	// Submit creates the ChaosExperiment with strict field validation.
	Submit(ctx context.Context, exp *chaosv1.ChaosExperiment) error
	// Cancel sets spec.cancel=true.
	Cancel(ctx context.Context, name string) error
	// EngageLock creates a ChaosLock and returns its name.
	EngageLock(ctx context.Context, reason, by string) (string, error)
	// Watch calls fn for every experiment now and on every change until ctx ends.
	Watch(ctx context.Context, fn func(*chaosv1.ChaosExperiment)) error
}

// ErrUnavailable means the cluster could not be reached.
var ErrUnavailable = errors.New("cluster unavailable")

// CRDConnector implements Connector with Kubernetes CRDs (development/phase 1).
type CRDConnector struct {
	c         client.WithWatch
	clusterID string
	log       *slog.Logger
}

// NewCRDConnector builds a connector from a kubeconfig file (the control plane's SA token).
func NewCRDConnector(kubeconfig, clusterID string, log *slog.Logger) (*CRDConnector, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	cfg.UserAgent = "kubechaos-api"
	cfg.Timeout = 15 * time.Second
	s := runtime.NewScheme()
	if err := chaosv1.AddToScheme(s); err != nil {
		return nil, err
	}
	c, err := client.NewWithWatch(cfg, client.Options{Scheme: s})
	if err != nil {
		return nil, err
	}
	return &CRDConnector{c: c, clusterID: clusterID, log: log}, nil
}

// NewCRDConnectorFromClient is used by tests.
func NewCRDConnectorFromClient(c client.WithWatch, clusterID string, log *slog.Logger) *CRDConnector {
	return &CRDConnector{c: c, clusterID: clusterID, log: log}
}

func (k *CRDConnector) ClusterID() string { return k.clusterID }

func (k *CRDConnector) Policy(ctx context.Context) (*chaosv1.ChaosPolicy, error) {
	var p chaosv1.ChaosPolicy
	err := k.c.Get(ctx, types.NamespacedName{Name: chaosv1.PolicyName}, &p)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: read policy: %v", ErrUnavailable, err)
	}
	return &p, nil
}

func (k *CRDConnector) Locks(ctx context.Context) ([]chaosv1.ChaosLock, error) {
	var l chaosv1.ChaosLockList
	if err := k.c.List(ctx, &l); err != nil {
		return nil, fmt.Errorf("%w: list locks: %v", ErrUnavailable, err)
	}
	return l.Items, nil
}

func (k *CRDConnector) Submit(ctx context.Context, exp *chaosv1.ChaosExperiment) error {
	exp.Namespace = chaosv1.ExperimentNamespace
	// Strict: unknown fields are rejected instead of silently pruned (architecture §6).
	if err := k.c.Create(ctx, exp, client.FieldValidation(metav1.FieldValidationStrict)); err != nil {
		if apierrors.IsInvalid(err) || apierrors.IsForbidden(err) || apierrors.IsBadRequest(err) {
			return fmt.Errorf("cluster rejected the experiment: %w", err)
		}
		return fmt.Errorf("%w: create experiment: %v", ErrUnavailable, err)
	}
	return nil
}

func (k *CRDConnector) Cancel(ctx context.Context, name string) error {
	exp := &chaosv1.ChaosExperiment{ObjectMeta: metav1.ObjectMeta{Namespace: chaosv1.ExperimentNamespace, Name: name}}
	patch := client.RawPatch(types.MergePatchType, []byte(`{"spec":{"cancel":true}}`))
	if err := k.c.Patch(ctx, exp, patch); err != nil {
		return fmt.Errorf("%w: cancel: %v", ErrUnavailable, err)
	}
	return nil
}

func (k *CRDConnector) EngageLock(ctx context.Context, reason, by string) (string, error) {
	l := &chaosv1.ChaosLock{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "web-emergency-stop-"},
		Spec:       chaosv1.ChaosLockSpec{Reason: reason, EngagedBy: by},
	}
	if err := k.c.Create(ctx, l, client.FieldValidation(metav1.FieldValidationStrict)); err != nil {
		return "", fmt.Errorf("%w: engage lock: %v", ErrUnavailable, err)
	}
	return l.Name, nil
}

// Watch lists then watches experiments, re-listing on any disconnect.
func (k *CRDConnector) Watch(ctx context.Context, fn func(*chaosv1.ChaosExperiment)) error {
	for ctx.Err() == nil {
		if err := k.watchOnce(ctx, fn); err != nil && ctx.Err() == nil {
			k.log.Warn("experiment watch interrupted; re-listing", slog.Any("error", err))
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
		}
	}
	return ctx.Err()
}

func (k *CRDConnector) watchOnce(ctx context.Context, fn func(*chaosv1.ChaosExperiment)) error {
	var list chaosv1.ChaosExperimentList
	if err := k.c.List(ctx, &list, client.InNamespace(chaosv1.ExperimentNamespace)); err != nil {
		return err
	}
	for i := range list.Items {
		fn(&list.Items[i])
	}
	w, err := k.c.Watch(ctx, &chaosv1.ChaosExperimentList{}, client.InNamespace(chaosv1.ExperimentNamespace),
		&client.ListOptions{Raw: &metav1.ListOptions{ResourceVersion: list.ResourceVersion}})
	if err != nil {
		return err
	}
	defer w.Stop()
	resync := time.NewTimer(5 * time.Minute)
	defer resync.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-resync.C:
			return errors.New("periodic resync")
		case ev, ok := <-w.ResultChan():
			if !ok {
				return errors.New("watch closed")
			}
			switch ev.Type {
			case watch.Added, watch.Modified:
				if e, ok := ev.Object.(*chaosv1.ChaosExperiment); ok {
					fn(e)
				}
			case watch.Error:
				return fmt.Errorf("watch error: %v", ev.Object)
			}
		}
	}
}
