package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PolicyName is the only accepted ChaosPolicy name: exactly one policy per cluster.
const PolicyName = "default"

// ChaosPolicy is the cluster's security ceiling for chaos experiments. It is written by
// cluster administrators (GitOps/Helm) and is read-only for every KubeChaos component.
// Without it nothing executes (fail closed).
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=chaospol,categories=kubechaos
// +kubebuilder:printcolumn:name="Environment",type=string,JSONPath=`.spec.environment`
// +kubebuilder:printcolumn:name="Approval",type=string,JSONPath=`.spec.approval.required`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default'",message="the ChaosPolicy must be named 'default' (one policy per cluster)"
type ChaosPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ChaosPolicySpec `json:"spec"`
}

// ChaosPolicySpec defines what may run on this cluster.
//
// +kubebuilder:validation:XValidation:rule="self.environment != 'production' || (self.approval.required == 'Always' && self.approval.minApprovals >= 1)",message="production requires approval.required=Always and minApprovals >= 1"
// +kubebuilder:validation:XValidation:rule="self.approval.required == 'Never' || size(self.approval.trustedKeys) >= 1",message="approval requires at least one trusted approver key"
type ChaosPolicySpec struct {
	// Environment must equal the operator's cluster identity, or every experiment is denied.
	// +kubebuilder:validation:Enum=development;staging;production
	Environment string `json:"environment"`

	// AllowedFaults lists the primitives permitted here. Empty = none.
	// +kubebuilder:validation:MaxItems=16
	// +listType=set
	AllowedFaults []FaultType `json:"allowedFaults"`

	// AllowedNamespaces lists namespaces experiments may target. Namespaces must ALSO be
	// opted in (label + operator RBAC grant). Empty = none.
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`
	AllowedNamespaces []string `json:"allowedNamespaces"`

	Limits PolicyLimits `json:"limits"`

	Approval ApprovalPolicy `json:"approval"`

	// +optional
	Observability *ObservabilityPolicy `json:"observability,omitempty"`
}

// PolicyLimits are the blast-radius limits. They may only narrow the API's hard limits.
type PolicyLimits struct {
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10
	MaxPodKillCount int32 `json:"maxPodKillCount"`

	// +kubebuilder:validation:MaxLength=16
	// +kubebuilder:validation:Pattern=`^([0-9]{1,4}(s|m|h)){1,3}$`
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('10s') && duration(self) <= duration('1h')",message="maxDuration must be between 10s and 1h"
	MaxDuration string `json:"maxDuration"`

	// MaxConcurrentExperiments running at the same time on this cluster.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10
	MaxConcurrentExperiments int32 `json:"maxConcurrentExperiments"`

	// MinReadyReplicas that must survive per workload (default 1: never the last one).
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=1
	// +optional
	MinReadyReplicas int32 `json:"minReadyReplicas,omitempty"`
}

// ApprovalRequirement says when an approval attestation is required.
// +kubebuilder:validation:Enum=Never;RiskAtLeast;Always
type ApprovalRequirement string

const (
	ApprovalNever       ApprovalRequirement = "Never"
	ApprovalRiskAtLeast ApprovalRequirement = "RiskAtLeast"
	ApprovalAlways      ApprovalRequirement = "Always"
)

// RiskLevel of a fault primitive.
// +kubebuilder:validation:Enum=Low;Medium;High;Critical
type RiskLevel string

const (
	RiskLow      RiskLevel = "Low"
	RiskMedium   RiskLevel = "Medium"
	RiskHigh     RiskLevel = "High"
	RiskCritical RiskLevel = "Critical"
)

// ApprovalPolicy configures four-eyes approval (architecture §15).
type ApprovalPolicy struct {
	Required ApprovalRequirement `json:"required"`
	// RiskAtLeast applies when Required is RiskAtLeast.
	// +optional
	RiskAtLeast RiskLevel `json:"riskAtLeast,omitempty"`
	// MinApprovals is the number of distinct approvers (never the requester).
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=5
	// +optional
	MinApprovals int32 `json:"minApprovals,omitempty"`
	// MaxAttestationAge bounds how old an approval may be when execution starts.
	// +kubebuilder:validation:Pattern=`^([0-9]{1,4}(s|m|h)){1,3}$`
	// +kubebuilder:default="1h"
	// +optional
	MaxAttestationAge string `json:"maxAttestationAge,omitempty"`
	// TrustedKeys are the approval service's Ed25519 public keys.
	// +kubebuilder:validation:MaxItems=8
	// +optional
	TrustedKeys []TrustedKey `json:"trustedKeys,omitempty"`
}

// TrustedKey is one approval-service public key.
type TrustedKey struct {
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9._-]{1,64}$`
	KID string `json:"kid"`
	// PublicKey is the base64 (std) encoding of a 32-byte Ed25519 public key.
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9+/]{43}=$`
	PublicKey string `json:"publicKey"`
}

// ObservabilityPolicy configures optional metric providers.
type ObservabilityPolicy struct {
	// +optional
	Prometheus *PrometheusProvider `json:"prometheus,omitempty"`
}

// PrometheusProvider enables Prometheus-backed success criteria. Queries are built only from
// server-side templates; no field anywhere accepts PromQL.
type PrometheusProvider struct {
	// +kubebuilder:validation:Pattern=`^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._/-]*)?$`
	// +kubebuilder:validation:MaxLength=256
	URL string `json:"url"`
	// MetricFamily selects the server-side template set for HTTP metrics.
	// +kubebuilder:validation:Enum=istio;ingress-nginx;otel
	MetricFamily string `json:"metricFamily"`
}

// ChaosPolicyList is a list of ChaosPolicies.
//
// +kubebuilder:object:root=true
type ChaosPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ChaosPolicy `json:"items"`
}

// ChaosLock is the emergency stop. While ANY ChaosLock exists, no experiment starts and
// running experiments are aborted. Creating one is cheap to allow (web UI admins, kubechaosctl);
// deleting one (unlocking) is reserved for cluster administrators (kubechaosctl unlock).
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=chaoslock,categories=kubechaos
// +kubebuilder:printcolumn:name="EngagedBy",type=string,JSONPath=`.spec.engagedBy`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.spec.reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type ChaosLock struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ChaosLockSpec `json:"spec"`
}

// ChaosLockSpec records why and by whom the system was locked.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="a ChaosLock is immutable; delete it to unlock"
type ChaosLockSpec struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=512
	Reason string `json:"reason"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	EngagedBy string `json:"engagedBy"`
}

// ChaosLockList is a list of ChaosLocks.
//
// +kubebuilder:object:root=true
type ChaosLockList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ChaosLock `json:"items"`
}

// ChaosAttestationUse records that an approval attestation (by its jti, the object name) has
// been consumed. Creation fails with AlreadyExists on replay. Only the operator may create it.
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,categories=kubechaos
type ChaosAttestationUse struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ChaosAttestationUseSpec `json:"spec"`
}

// ChaosAttestationUseSpec links the consumed attestation to its experiment.
type ChaosAttestationUseSpec struct {
	// +kubebuilder:validation:MaxLength=253
	Experiment string `json:"experiment"`
	// +kubebuilder:validation:MaxLength=64
	SpecSHA256 string `json:"specSHA256"`
}

// ChaosAttestationUseList is a list of ChaosAttestationUses.
//
// +kubebuilder:object:root=true
type ChaosAttestationUseList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ChaosAttestationUse `json:"items"`
}
