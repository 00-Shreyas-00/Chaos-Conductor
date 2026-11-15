package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The validation markers below become the CRD's OpenAPI schema and CEL rules, so the
// Kubernetes API server itself rejects malformed experiments before any KubeChaos code runs.
// ValidateSpec (validation.go) re-checks the same constraints in Go as defence in depth.

// ExperimentNamespace is the only namespace in which ChaosExperiments may exist (enforced by
// the ValidatingAdmissionPolicy in deploy/crds and by the operator).
const ExperimentNamespace = "kubechaos-system"

// ProtectedNamespaces can never be targeted, whatever any policy says.
var ProtectedNamespaces = []string{"kube-system", "kube-public", "kube-node-lease", ExperimentNamespace}

// Labels with security meaning, set by cluster administrators.
const (
	// LabelEnabled must be "true" on a namespace before it can be targeted (opt-in, D5).
	LabelEnabled = "chaos.kubechaos.io/enabled"
	// LabelProtected = "true" on a namespace or pod excludes it from every experiment.
	LabelProtected = "chaos.kubechaos.io/protected"
)

// Hard upper bounds of the API. Cluster policy (ChaosPolicy, later) may only narrow them.
const (
	MaxSteps           = 20
	MaxPodKillCount    = 10
	MaxGracePeriodSecs = 300
	MinMaxDuration     = "10s"
	MaxMaxDuration     = "1h"
	MinWait            = "1s"
	MaxWait            = "10m"
)

// FaultType is one of the finite, typed failure primitives. There is deliberately no
// "custom", "script" or "command" type.
// +kubebuilder:validation:Enum=PodKill
type FaultType string

const (
	// FaultPodKill deletes up to `count` pods selected by the target.
	FaultPodKill FaultType = "PodKill"
)

// ChaosExperiment is a request to run a bounded, declarative chaos experiment on this cluster.
// It is created by the control plane in kubechaos-system; only the operator acts on it.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=chaosexp,categories=kubechaos
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterID`
// +kubebuilder:printcolumn:name="Requested-By",type=string,JSONPath=`.spec.requestedBy.subject`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type ChaosExperiment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ChaosExperimentSpec   `json:"spec"`
	Status ChaosExperimentStatus `json:"status,omitempty"`
}

// ChaosExperimentSpec describes the experiment. It is immutable after creation except for
// spec.cancel, which may only change from false to true.
//
// +kubebuilder:validation:XValidation:rule="self.clusterID == oldSelf.clusterID && self.requestedBy == oldSelf.requestedBy && self.maxDuration == oldSelf.maxDuration && self.steps == oldSelf.steps",message="spec is immutable; only spec.cancel may change"
// +kubebuilder:validation:XValidation:rule="!oldSelf.cancel || self.cancel",message="spec.cancel cannot be reverted once set"
type ChaosExperimentSpec struct {
	// ClusterID must equal the operator's cluster identity, or the experiment is rejected.
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`
	ClusterID string `json:"clusterID"`

	// RequestedBy is asserted by the control plane and is informational to the operator;
	// it is never used to grant anything (threat model T4).
	RequestedBy Requester `json:"requestedBy"`

	// MaxDuration is a hard ceiling: the operator aborts the experiment after this long.
	// +kubebuilder:validation:MaxLength=16
	// +kubebuilder:validation:Pattern=`^([0-9]{1,4}(s|m|h)){1,3}$`
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('10s') && duration(self) <= duration('1h')",message="maxDuration must be between 10s and 1h"
	MaxDuration string `json:"maxDuration"`

	// Steps run in order. Each step is exactly one fault or one wait.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=20
	Steps []Step `json:"steps"`

	// Cancel requests cancellation. It can be set to true but never back to false.
	// +kubebuilder:default=false
	// +optional
	Cancel bool `json:"cancel"`
}

// Requester identifies the human who requested the experiment (OIDC issuer + subject).
type Requester struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=512
	Issuer string `json:"issuer"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Subject string `json:"subject"`
}

// Step is one entry of the experiment: a fault or a wait (exactly one).
//
// +kubebuilder:validation:XValidation:rule="has(self.fault) != has(self.wait)",message="each step must set exactly one of fault or wait"
type Step struct {
	// +optional
	Fault *FaultStep `json:"fault,omitempty"`
	// +optional
	Wait *WaitStep `json:"wait,omitempty"`
}

// FaultStep injects one typed failure primitive into one target.
//
// +kubebuilder:validation:XValidation:rule="self.type != 'PodKill' || has(self.podKill)",message="type PodKill requires podKill parameters"
type FaultStep struct {
	Type   FaultType `json:"type"`
	Target Target    `json:"target"`

	// PodKill parameters (required when type is PodKill).
	// +optional
	PodKill *PodKillParams `json:"podKill,omitempty"`
}

// Target selects workloads in exactly one namespace by labels. Cluster-wide or
// all-namespace targets are not expressible.
type Target struct {
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`
	// +kubebuilder:validation:XValidation:rule="!(self in ['kube-system', 'kube-public', 'kube-node-lease', 'kubechaos-system'])",message="this namespace is protected and can never be targeted"
	Namespace string `json:"namespace"`

	// Selector is an equality label selector (all labels must match). It may not be empty:
	// an empty selector would match every pod in the namespace.
	// +kubebuilder:validation:MinProperties=1
	// +kubebuilder:validation:MaxProperties=10
	// +kubebuilder:validation:XValidation:rule="self.all(k, k.matches('^([a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?/)?[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$'))",message="selector keys must be valid label keys"
	Selector map[string]LabelValue `json:"selector"`
}

// LabelValue is a Kubernetes label value.
// +kubebuilder:validation:MaxLength=63
// +kubebuilder:validation:Pattern=`^([A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?)?$`
type LabelValue string

// PodKillParams are the typed parameters of the PodKill primitive.
type PodKillParams struct {
	// Count is how many matching pods to delete. The API caps it at 10; policy may cap lower.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10
	Count int32 `json:"count"`

	// GracePeriodSeconds passed to the pod deletion (0 = immediate kill).
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=300
	// +kubebuilder:default=30
	// +optional
	GracePeriodSeconds *int32 `json:"gracePeriodSeconds,omitempty"`
}

// WaitStep pauses between faults (observation continues).
type WaitStep struct {
	// +kubebuilder:validation:MaxLength=16
	// +kubebuilder:validation:Pattern=`^([0-9]{1,4}(s|m|h)){1,3}$`
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('1s') && duration(self) <= duration('10m')",message="wait duration must be between 1s and 10m"
	Duration string `json:"duration"`
}

// ExperimentPhase is the coarse lifecycle state, owned by the operator.
// +kubebuilder:validation:Enum=Pending;Rejected;Running;Completed;Failed;Aborted
type ExperimentPhase string

const (
	PhasePending   ExperimentPhase = "Pending"
	PhaseRejected  ExperimentPhase = "Rejected"
	PhaseRunning   ExperimentPhase = "Running"
	PhaseCompleted ExperimentPhase = "Completed"
	PhaseFailed    ExperimentPhase = "Failed"
	PhaseAborted   ExperimentPhase = "Aborted"
)

// Condition types.
const (
	// ConditionAccepted reports whether the operator accepted the experiment for execution.
	ConditionAccepted = "Accepted"
	// ConditionFinished is set when the experiment ends after starting (True only on success).
	ConditionFinished = "Finished"
)

// ChaosExperimentStatus is written only by the operator (status subresource).
type ChaosExperimentStatus struct {
	// +optional
	Phase ExperimentPhase `json:"phase,omitempty"`
	// ObservedGeneration is the spec generation the status refers to.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	Message string `json:"message,omitempty"`
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=16
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// StartedAt is when execution began; maxDuration is measured from here.
	// +optional
	StartedAt *metav1.Time `json:"startedAt,omitempty"`
	// CompletedAt is when the experiment reached a terminal phase after starting.
	// +optional
	CompletedAt *metav1.Time `json:"completedAt,omitempty"`
	// CurrentStep is the index of the step being executed.
	// +optional
	CurrentStep int32 `json:"currentStep,omitempty"`
	// Steps mirrors spec.steps one-to-one once execution has started.
	// +optional
	// +kubebuilder:validation:MaxItems=20
	Steps []StepStatus `json:"steps,omitempty"`
}

// StepPhase is the progress of one step.
// +kubebuilder:validation:Enum=Pending;Running;Injecting;Observing;Succeeded;Failed;Skipped
type StepPhase string

const (
	StepPending StepPhase = "Pending"
	StepRunning StepPhase = "Running" // waits
	// StepInjecting is written (with the chosen targets) BEFORE any destructive call. Finding a
	// step still Injecting after a restart means the outcome is unknown: it is failed, never
	// retried (at-most-once execution, architecture §6 / D7).
	StepInjecting StepPhase = "Injecting"
	StepObserving StepPhase = "Observing"
	StepSucceeded StepPhase = "Succeeded"
	StepFailed    StepPhase = "Failed"
	StepSkipped   StepPhase = "Skipped"
)

// StepStatus records what happened in one step.
type StepStatus struct {
	Phase StepPhase `json:"phase"`
	// +optional
	StartedAt *metav1.Time `json:"startedAt,omitempty"`
	// +optional
	FinishedAt *metav1.Time `json:"finishedAt,omitempty"`
	// WaitUntil is the end of a wait step.
	// +optional
	WaitUntil *metav1.Time `json:"waitUntil,omitempty"`
	// Targets are the exact pods chosen for a fault step (recorded before injection).
	// +optional
	// +kubebuilder:validation:MaxItems=10
	Targets []PodRef `json:"targets,omitempty"`
	// ReadyBefore is the number of Ready pods matching the selector before injection.
	// +optional
	ReadyBefore int32 `json:"readyBefore,omitempty"`
	// InjectedAt is when the destructive action was issued.
	// +optional
	InjectedAt *metav1.Time `json:"injectedAt,omitempty"`
	// RecoveryMillis is the time from injection until ReadyBefore pods were Ready again.
	// +optional
	RecoveryMillis *int64 `json:"recoveryMillis,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=512
	Message string `json:"message,omitempty"`
}

// PodRef identifies one pod precisely (UID guards against same-name replacements).
type PodRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}

// ChaosExperimentList is a list of ChaosExperiments.
//
// +kubebuilder:object:root=true
type ChaosExperimentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ChaosExperiment `json:"items"`
}
