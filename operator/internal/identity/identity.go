// Package identity loads the operator's cluster identity: which cluster it acts on and in
// which environment. Every experiment will be checked against it (clusterID mismatch,
// environment-specific policy), so it is loaded once at startup and the operator refuses to
// run without a valid one (fail closed).
package identity

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ConfigMapName is the only ConfigMap the operator may read (RBAC resourceNames). It is
// written by cluster administrators (Helm values), never by the control plane.
const ConfigMapName = "kubechaos-cluster-identity"

// Environment of the cluster the operator runs in.
type Environment string

const (
	Development Environment = "development"
	Staging     Environment = "staging"
	Production  Environment = "production"
)

// Identity is the validated cluster identity.
type Identity struct {
	ClusterID   string
	Environment Environment
}

// Same rule as app.clusters.id in the control-plane database (DNS-1123 label).
var clusterIDRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Parse validates the ConfigMap data. Unknown keys are rejected so typos cannot silently
// leave a setting at a default.
func Parse(data map[string]string) (Identity, error) {
	var errs []error
	for k := range data {
		if k != "clusterID" && k != "environment" {
			errs = append(errs, fmt.Errorf("unknown key %q", k))
		}
	}
	id := Identity{ClusterID: data["clusterID"], Environment: Environment(data["environment"])}
	if !clusterIDRe.MatchString(id.ClusterID) {
		errs = append(errs, fmt.Errorf("clusterID %q must be a DNS-1123 label", id.ClusterID))
	}
	switch id.Environment {
	case Development, Staging, Production:
	default:
		errs = append(errs, fmt.Errorf("environment %q must be development|staging|production", id.Environment))
	}
	if err := errors.Join(errs...); err != nil {
		return Identity{}, fmt.Errorf("invalid cluster identity: %w", err)
	}
	return id, nil
}

// Load reads and validates the identity ConfigMap from namespace using a direct (uncached)
// reader, so the operator needs only `get` on this single object — no list/watch.
func Load(ctx context.Context, r client.Reader, namespace string) (Identity, error) {
	var cm corev1.ConfigMap
	err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: ConfigMapName}, &cm)
	if apierrors.IsNotFound(err) {
		return Identity{}, fmt.Errorf("cluster identity ConfigMap %s/%s not found", namespace, ConfigMapName)
	}
	if err != nil {
		return Identity{}, fmt.Errorf("read cluster identity: %w", err)
	}
	if len(cm.BinaryData) > 0 {
		return Identity{}, errors.New("invalid cluster identity: binaryData is not allowed")
	}
	return Parse(cm.Data)
}
