// Package schedules implements scheduled chaos (Chaos Monkey style): opt-in schedules that
// start ordinary experiments at random times inside a weekly window, with a mean and a
// minimum gap between runs. Every run goes through the full experiment pipeline (policy,
// emergency stop, approval, survivors, audit), so scheduling adds no new way to bypass a gate.
package schedules

import (
	"context"
	"time"

	"github.com/kubechaos/kubechaos/backend/internal/audit"
	"github.com/kubechaos/kubechaos/backend/internal/auth"
	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
)

// States.
const (
	StateActive   = "Active"
	StatePaused   = "Paused"
	StateFinished = "Finished" // expired or reached maxRuns
	StateDeleted  = "Deleted"
)

// Run outcomes.
const (
	OutcomeStarted = "Started"
	OutcomeSkipped = "Skipped" // previous run still active, or the emergency stop is engaged
	OutcomeDenied  = "Denied"  // policy, authorization or validation refused the run
	OutcomeFailed  = "Failed"  // cluster or approval service unavailable
)

// MaxConsecutiveDenials pauses a schedule that keeps being refused (e.g. the policy changed).
const MaxConsecutiveDenials = 3

// MaxLifetime bounds how long a schedule may run before someone must renew it.
const MaxLifetime = 90 * 24 * time.Hour

// Template is the experiment each run submits.
type Template struct {
	MaxDuration     string              `json:"maxDuration"`
	Steps           []chaosv1.Step      `json:"steps"`
	SuccessCriteria []chaosv1.Criterion `json:"successCriteria,omitempty"`
}

// Schedule is a stored schedule.
type Schedule struct {
	ID                  string      `json:"id"`
	Name                string      `json:"name"`
	ClusterID           string      `json:"clusterId"`
	OwnerID             string      `json:"-"`
	OwnerIssuer         string      `json:"ownerIssuer"`
	OwnerSubject        string      `json:"ownerSubject"`
	OwnerName           string      `json:"ownerName,omitempty"`
	OwnerRoles          []auth.Role `json:"-"`
	Description         string      `json:"description"`
	Template            Template    `json:"template"`
	Risk                string      `json:"risk"`
	MinIntervalSeconds  int         `json:"minIntervalSeconds"`
	MeanIntervalSeconds int         `json:"meanIntervalSeconds"`
	Window              Window      `json:"window"`
	ExpiresAt           time.Time   `json:"expiresAt"`
	MaxRuns             int         `json:"maxRuns"`
	Runs                int         `json:"runs"`
	ConsecutiveDenials  int         `json:"consecutiveDenials"`
	State               string      `json:"state"`
	StateReason         string      `json:"stateReason,omitempty"`
	NextRunAt           *time.Time  `json:"nextRunAt,omitempty"`
	LastRunAt           *time.Time  `json:"lastRunAt,omitempty"`
	LastExperimentID    string      `json:"lastExperimentId,omitempty"`
	CreatedAt           time.Time   `json:"createdAt"`
	UpdatedAt           time.Time   `json:"updatedAt"`
}

// Run is one entry of a schedule's history.
type Run struct {
	ID           int64     `json:"id"`
	ScheduleID   string    `json:"scheduleId"`
	OccurredAt   time.Time `json:"occurredAt"`
	Outcome      string    `json:"outcome"`
	ExperimentID string    `json:"experimentId,omitempty"`
	Reason       string    `json:"reason,omitempty"`
}

// CreateRequest is the user's request.
type CreateRequest struct {
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	Template     Template  `json:"template"`
	MinInterval  string    `json:"minInterval"`  // Go duration of window time, e.g. "6h"
	MeanInterval string    `json:"meanInterval"` // Go duration of window time, e.g. "12h"
	Window       Window    `json:"window"`
	ExpiresAt    time.Time `json:"expiresAt"`
	MaxRuns      int       `json:"maxRuns"` // 0 = unlimited until expiry
	Confirm      bool      `json:"confirm"`
}

// Store persists schedules and their run history.
type Store interface {
	CreateWithAudit(ctx context.Context, s *Schedule, ev audit.Event) error
	Get(ctx context.Context, id string) (*Schedule, error)
	List(ctx context.Context, limit int) ([]*Schedule, error)
	// Due returns Active schedules whose next run is at or before now.
	Due(ctx context.Context, now time.Time, limit int) ([]*Schedule, error)
	// Claim moves next_run_at from expected to next only if the schedule is still Active and
	// unchanged, so exactly one control-plane replica fires each run.
	Claim(ctx context.Context, id string, expected time.Time, next *time.Time) (bool, error)
	// RecordRun appends a run and stores the schedule's counters and state.
	RecordRun(ctx context.Context, s *Schedule, r Run) error
	// SetState changes state (and next run) if the current state is one of from.
	SetState(ctx context.Context, id string, from []string, state, reason string, next *time.Time, roles []auth.Role) (bool, error)
	Runs(ctx context.Context, id string, limit int) ([]Run, error)
}
