// Package v1alpha1 contains the KubeChaos API types (group chaos.kubechaos.io), shared by the
// control plane (which creates experiment requests) and the operator (which validates and
// executes them). The CRD schema is generated from these types: `make generate`.
//
// +kubebuilder:object:generate=true
// +groupName=chaos.kubechaos.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupVersion is the API group and version of these types.
var GroupVersion = schema.GroupVersion{Group: "chaos.kubechaos.io", Version: "v1alpha1"}

var (
	// SchemeBuilder registers the types with a runtime.Scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	// AddToScheme adds the types to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion,
		&ChaosExperiment{}, &ChaosExperimentList{},
		&ChaosPolicy{}, &ChaosPolicyList{},
		&ChaosLock{}, &ChaosLockList{},
		&ChaosAttestationUse{}, &ChaosAttestationUseList{},
	)
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}
