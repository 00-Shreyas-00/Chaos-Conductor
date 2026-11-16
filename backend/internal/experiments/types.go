// Package experiments is the control plane's experiment service: it authorizes and validates
// requests, records intent and audit atomically, submits to the cluster, and mirrors the
// operator's status back into the database and to live (SSE) subscribers.
package experiments

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/kubechaos/kubechaos/backend/internal/audit"
	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
)

// Experiment is the control plane's record.
type Experiment struct {
	ID              string                         `json:"id"`
	Name            string                         `json:"name"`
	ClusterID       string                         `json:"clusterId"`
	RequesterID     string                         `json:"-"`
	RequesterIssuer string                         `json:"requesterIssuer"`
	RequesterSubj   string                         `json:"requesterSubject"`
	RequesterName   string                         `json:"requesterName,omitempty"`
	Description     string                         `json:"description"`
	Spec            chaosv1.ChaosExperimentSpec    `json:"spec"`
	SpecSHA256      string                         `json:"specSha256"`
	Risk            chaosv1.RiskLevel              `json:"risk"`
	State           string                         `json:"state"` // see States
	ApprovalRequest string                         `json:"approvalRequestId,omitempty"`
	Phase           string                         `json:"phase"`
	Result          string                         `json:"result,omitempty"`
	Score           *int32                         `json:"score,omitempty"`
	Status          *chaosv1.ChaosExperimentStatus `json:"status,omitempty"`
	CancelRequested bool                           `json:"cancelRequested"`
	CreatedAt       time.Time                      `json:"createdAt"`
	UpdatedAt       time.Time                      `json:"updatedAt"`
}

// TimelineEvent is one entry of an experiment's timeline.
type TimelineEvent struct {
	ID         int64     `json:"id"`
	OccurredAt time.Time `json:"occurredAt"`
	Type       string    `json:"type"`
	Message    string    `json:"message"`
}

// States.
const (
	StateSubmitting   = "Submitting"
	StateSubmitted    = "Submitted"
	StateSubmitFailed = "SubmitFailed"
	// Approval workflow (approval service): nothing exists in the cluster until approved.
	StatePendingApproval  = "PendingApproval"
	StateApprovalRejected = "ApprovalRejected"
	StateApprovalExpired  = "ApprovalExpired"
)

// ApprovalClient is the control plane's view of the approval service.
type ApprovalClient interface {
	Request(ctx context.Context, in ApprovalInput) (string, error)
	Status(ctx context.Context, requestID string) (ApprovalStatus, error)
}

// ApprovalInput is what the approval service needs to route and record a request.
type ApprovalInput struct {
	ExperimentID  string                      `json:"experimentId"`
	ClusterID     string                      `json:"clusterId"`
	Environment   string                      `json:"environment"`
	Spec          chaosv1.ChaosExperimentSpec `json:"spec"`
	RequesterName string                      `json:"requesterName"`
}

// ApprovalStatus is a request's state; Attestation is set once Approved.
type ApprovalStatus struct {
	ID          string `json:"id"`
	State       string `json:"state"` // Pending | Approved | Rejected | Expired
	Attestation string `json:"attestation"`
}

// Store persists experiments. Create commits the experiment and its audit event atomically.
type Store interface {
	CreateWithAudit(ctx context.Context, e *Experiment, ev audit.Event) error
	SetState(ctx context.Context, id, state string) error
	Get(ctx context.Context, id string) (*Experiment, error)
	GetByName(ctx context.Context, name string) (*Experiment, error)
	List(ctx context.Context, limit int) ([]*Experiment, error)
	ApplyClusterStatus(ctx context.Context, id string, status *chaosv1.ChaosExperimentStatus, events []TimelineEvent) ([]TimelineEvent, error)
	SetCancelRequested(ctx context.Context, id string) error
	Events(ctx context.Context, id string) ([]TimelineEvent, error)
	SetApprovalRequest(ctx context.Context, id, requestID string) error
	ListPendingApproval(ctx context.Context) ([]*Experiment, error)
}

// Auditor appends audit events (outside a store transaction).
type Auditor interface {
	Append(ctx context.Context, e audit.Event) error
}

// ErrNotFound is returned when an experiment does not exist.
var ErrNotFound = errors.New("experiment not found")

// Error kinds the API maps to HTTP responses.
var (
	ErrForbidden            = errors.New("forbidden")
	ErrInvalid              = errors.New("invalid experiment")
	ErrPolicy               = errors.New("not permitted by cluster policy")
	ErrLocked               = errors.New("emergency stop engaged")
	ErrStepUpRequired       = errors.New("step-up authentication required")
	ErrConfirmationRequired = errors.New("explicit confirmation required")
	ErrApprovalRequired     = errors.New("approval required")
	ErrConflict             = errors.New("conflict")
	ErrUnavailable          = errors.New("cluster unavailable")
)

// DetailedError carries user-facing reasons (validation or policy violations).
type DetailedError struct {
	Kind    error
	Reasons []string
}

func (e *DetailedError) Error() string { return e.Kind.Error() }
func (e *DetailedError) Unwrap() error { return e.Kind }

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
