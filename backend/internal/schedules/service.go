package schedules

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/kubechaos/kubechaos/backend/internal/audit"
	"github.com/kubechaos/kubechaos/backend/internal/auth"
	"github.com/kubechaos/kubechaos/backend/internal/authorization"
	"github.com/kubechaos/kubechaos/backend/internal/experiments"
	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
	"github.com/kubechaos/kubechaos/pkg/chaosapi/attestation"
)

// Service implements the schedule use cases and the scheduler loop.
type Service struct {
	Store Store
	Exp   *experiments.Service
	Audit experiments.Auditor
	Log   *slog.Logger
	Now   func() time.Time
	// Uniform returns a uniform float64 in (0, 1]; crypto/rand by default (tests inject).
	Uniform func() float64
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) uniform() float64 {
	if s.Uniform != nil {
		return s.Uniform()
	}
	return cryptoUniform()
}

var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// MinIntervalFloor is the smallest permitted minimum gap: 1 minute in development (fast
// feedback), 1 hour elsewhere.
func MinIntervalFloor(environment string) time.Duration {
	if environment == "development" {
		return time.Minute
	}
	return time.Hour
}

func invalid(reasons ...string) error {
	return &experiments.DetailedError{Kind: experiments.ErrInvalid, Reasons: reasons}
}

func (s *Service) next(sch *Schedule, from time.Time) *time.Time {
	c, err := sch.Window.compile()
	if err != nil {
		return nil
	}
	d := sampleDelay(time.Duration(sch.MinIntervalSeconds)*time.Second, time.Duration(sch.MeanIntervalSeconds)*time.Second, s.uniform())
	t, ok := c.nextRun(from, d)
	if !ok || !t.Before(sch.ExpiresAt) {
		return nil
	}
	return &t
}

func (s *Service) event(p auth.Principal, action string, sch *Schedule, meta experiments.RequestMeta) audit.Event {
	params, _ := json.Marshal(map[string]any{"schedule": sch.ID, "name": sch.Name, "minIntervalSeconds": sch.MinIntervalSeconds,
		"meanIntervalSeconds": sch.MeanIntervalSeconds, "window": sch.Window, "expiresAt": sch.ExpiresAt, "maxRuns": sch.MaxRuns})
	return audit.Event{Action: action, ActorIssuer: p.Issuer, ActorSubject: p.Subject, ActorName: p.DisplayName, AuthLevel: p.ACR,
		SourceIP: meta.SourceIP, ClusterID: sch.ClusterID, Resource: "schedule/" + sch.Name, Parameters: params}
}

// Create validates and stores a schedule. The template must pass the same admission checks
// as a one-off experiment now; high-risk templates need a fresh login (step-up) because no
// one will be present when the runs happen.
func (s *Service) Create(ctx context.Context, p auth.Principal, req CreateRequest, meta experiments.RequestMeta) (*Schedule, error) {
	now := s.now()
	sch := &Schedule{ID: newUUID(), Name: req.Name, ClusterID: s.Exp.Conn.ClusterID(), OwnerID: p.IdentityID, OwnerIssuer: p.Issuer,
		OwnerSubject: p.Subject, OwnerName: p.DisplayName, OwnerRoles: p.Roles, Description: req.Description, Template: req.Template,
		Window: req.Window, ExpiresAt: req.ExpiresAt.UTC(), MaxRuns: req.MaxRuns, State: StateActive}
	deny := func(err error) (*Schedule, error) {
		var d *experiments.DetailedError
		if errors.As(err, &d) && !errors.Is(err, experiments.ErrStepUpRequired) && !errors.Is(err, experiments.ErrConfirmationRequired) {
			ev := s.event(p, "schedule.create", sch, meta)
			ev.Decision, ev.DecisionReasons, ev.Result = "deny", d.Reasons, "denied"
			if aerr := s.Audit.Append(ctx, ev); aerr != nil {
				s.Log.Error("audit write failed for schedule denial", slog.Any("error", aerr))
			}
		}
		return nil, err
	}

	spec, pol, err := s.Exp.Preflight(ctx, p, experiments.CreateRequest{Description: req.Description,
		MaxDuration: req.Template.MaxDuration, Steps: req.Template.Steps, SuccessCriteria: req.Template.SuccessCriteria})
	if err != nil {
		return deny(err)
	}
	var reasons []string
	if !nameRe.MatchString(req.Name) {
		reasons = append(reasons, "name: lowercase letters, digits and '-', at most 63 characters")
	}
	min, errMin := time.ParseDuration(req.MinInterval)
	mean, errMean := time.ParseDuration(req.MeanInterval)
	floor := MinIntervalFloor(pol.Spec.Environment)
	switch {
	case errMin != nil || errMean != nil:
		reasons = append(reasons, "minInterval and meanInterval must be durations such as 30m or 6h")
	case min < floor:
		reasons = append(reasons, fmt.Sprintf("minInterval: at least %s in a %s cluster", floor, pol.Spec.Environment))
	case mean < min:
		reasons = append(reasons, "meanInterval must be at least minInterval")
	case mean > 30*24*time.Hour:
		reasons = append(reasons, "meanInterval: at most 720h")
	}
	if _, err := req.Window.compile(); err != nil {
		reasons = append(reasons, err.Error())
	}
	if !req.ExpiresAt.After(now) || req.ExpiresAt.After(now.Add(MaxLifetime)) {
		reasons = append(reasons, "expiresAt: must be in the future and at most 90 days away")
	}
	if req.MaxRuns < 0 || req.MaxRuns > 1000 {
		reasons = append(reasons, "maxRuns: 0 (unlimited) to 1000")
	}
	if len(reasons) > 0 {
		return deny(invalid(reasons...))
	}
	sch.MinIntervalSeconds, sch.MeanIntervalSeconds = int(min/time.Second), int(mean/time.Second)
	sch.Risk = string(chaosv1.SpecRisk(spec))

	if experiments.Dangerous(spec, pol) && (p.AuthTime == nil || now.Sub(*p.AuthTime) > experiments.StepUpMaxAge) {
		return nil, &experiments.DetailedError{Kind: experiments.ErrStepUpRequired,
			Reasons: []string{"this schedule runs a high-risk experiment unattended: sign in again to confirm it is you"}}
	}
	if !req.Confirm {
		return nil, &experiments.DetailedError{Kind: experiments.ErrConfirmationRequired, Reasons: []string{"set confirm=true to create this schedule"}}
	}
	sch.NextRunAt = s.next(sch, now)
	if sch.NextRunAt == nil {
		return deny(invalid("the window does not open (for the minimum interval) before the schedule expires"))
	}
	ev := s.event(p, "schedule.create", sch, meta)
	ev.Decision, ev.Result, ev.Namespace = "allow", "created", strings.Join(attestation.TargetNamespaces(spec), ",")
	if err := s.Store.CreateWithAudit(ctx, sch, ev); err != nil {
		return nil, fmt.Errorf("record schedule: %w", err)
	}
	s.Log.Info("schedule created", slog.String("schedule", sch.Name), slog.String("owner", p.Subject), slog.Time("next_run", *sch.NextRunAt))
	return sch, nil
}

// Pause stops future runs. Like cancelling, pausing is cheap to allow (D8): the owner, an
// approver or an admin may pause.
func (s *Service) Pause(ctx context.Context, p auth.Principal, id string, meta experiments.RequestMeta) (*Schedule, error) {
	return s.transition(ctx, p, id, meta, "schedule.pause", []string{StateActive}, StatePaused, "paused by "+p.Subject)
}

// Delete ends a schedule permanently (kept for history). Same authority as Pause.
func (s *Service) Delete(ctx context.Context, p auth.Principal, id string, meta experiments.RequestMeta) (*Schedule, error) {
	return s.transition(ctx, p, id, meta, "schedule.delete", []string{StateActive, StatePaused, StateFinished}, StateDeleted, "deleted by "+p.Subject)
}

func (s *Service) transition(ctx context.Context, p auth.Principal, id string, meta experiments.RequestMeta, action string, from []string, to, reason string) (*Schedule, error) {
	sch, err := s.Store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	ev := s.event(p, action, sch, meta)
	if !authorization.CanCancel(p, sch.OwnerIssuer, sch.OwnerSubject) {
		ev.Decision, ev.Result = "deny", "denied"
		_ = s.Audit.Append(ctx, ev)
		return nil, &experiments.DetailedError{Kind: experiments.ErrForbidden, Reasons: []string{"only the owner, an approver or an admin may do this"}}
	}
	ev.Decision, ev.Result = "allow", to
	if err := s.Audit.Append(ctx, ev); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	ok, err := s.Store.SetState(ctx, id, from, to, reason, nil, nil)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, &experiments.DetailedError{Kind: experiments.ErrConflict, Reasons: []string{"schedule is " + sch.State}}
	}
	return s.Store.Get(ctx, id)
}

// Resume re-activates a paused schedule. Only the owner may resume, and the template is
// re-checked against the current policy with the owner's current roles (which become the
// new snapshot), with step-up for high-risk templates.
func (s *Service) Resume(ctx context.Context, p auth.Principal, id string, meta experiments.RequestMeta) (*Schedule, error) {
	sch, err := s.Store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if p.Issuer != sch.OwnerIssuer || p.Subject != sch.OwnerSubject {
		return nil, &experiments.DetailedError{Kind: experiments.ErrForbidden, Reasons: []string{"only the schedule's owner may resume it"}}
	}
	if sch.State != StatePaused {
		return nil, &experiments.DetailedError{Kind: experiments.ErrConflict, Reasons: []string{"schedule is " + sch.State}}
	}
	spec, pol, err := s.Exp.Preflight(ctx, p, experiments.CreateRequest{MaxDuration: sch.Template.MaxDuration,
		Steps: sch.Template.Steps, SuccessCriteria: sch.Template.SuccessCriteria})
	if err != nil {
		return nil, err
	}
	now := s.now()
	if experiments.Dangerous(spec, pol) && (p.AuthTime == nil || now.Sub(*p.AuthTime) > experiments.StepUpMaxAge) {
		return nil, &experiments.DetailedError{Kind: experiments.ErrStepUpRequired, Reasons: []string{"sign in again to resume a high-risk schedule"}}
	}
	next := s.next(sch, now)
	if next == nil {
		return nil, &experiments.DetailedError{Kind: experiments.ErrConflict, Reasons: []string{"the schedule has no run left before it expires"}}
	}
	ev := s.event(p, "schedule.resume", sch, meta)
	ev.Decision, ev.Result = "allow", StateActive
	if err := s.Audit.Append(ctx, ev); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	ok, err := s.Store.SetState(ctx, id, []string{StatePaused}, StateActive, "", next, p.Roles)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, &experiments.DetailedError{Kind: experiments.ErrConflict, Reasons: []string{"schedule changed concurrently"}}
	}
	return s.Store.Get(ctx, id)
}

// Tick fires every due schedule once. Safe to call from several replicas concurrently.
func (s *Service) Tick(ctx context.Context) {
	now := s.now()
	due, err := s.Store.Due(ctx, now, 20)
	if err != nil {
		s.Log.Warn("schedules: list due", slog.Any("error", err))
		return
	}
	for _, sch := range due {
		if sch.NextRunAt == nil {
			continue
		}
		expected := *sch.NextRunAt
		finished := ""
		switch {
		case !now.Before(sch.ExpiresAt):
			finished = "expired"
		case sch.MaxRuns > 0 && sch.Runs >= sch.MaxRuns:
			finished = "reached maxRuns"
		}
		if finished != "" {
			if ok, _ := s.Store.SetState(ctx, sch.ID, []string{StateActive}, StateFinished, finished, nil, nil); ok {
				_ = s.Audit.Append(ctx, audit.Event{Action: "schedule.finished", ActorSubject: "system:scheduler", ClusterID: sch.ClusterID,
					Resource: "schedule/" + sch.Name, Result: finished})
			}
			continue
		}
		next := s.next(sch, now)
		won, err := s.Store.Claim(ctx, sch.ID, expected, next)
		if err != nil || !won {
			continue // another replica fired it, or it was paused meanwhile
		}
		sch.NextRunAt = next
		s.fire(ctx, sch, now)
	}
}

func (s *Service) fire(ctx context.Context, sch *Schedule, now time.Time) {
	run := Run{ScheduleID: sch.ID, OccurredAt: now}
	sysEvent := func(action, result string) {
		_ = s.Audit.Append(ctx, audit.Event{Action: action, ActorSubject: "system:scheduler", ClusterID: sch.ClusterID,
			Resource: "schedule/" + sch.Name, Result: truncate(result, 500)})
	}

	// One run at a time per schedule (Chaos Monkey: at most one kill per group).
	if sch.LastExperimentID != "" {
		if prev, err := s.Exp.Store.Get(ctx, sch.LastExperimentID); err == nil && !experiments.IsTerminal(prev) {
			run.Outcome, run.Reason = OutcomeSkipped, "previous run "+prev.Name+" is still active"
		}
	}
	if run.Outcome == "" {
		owner := auth.Principal{IdentityID: sch.OwnerID, Issuer: sch.OwnerIssuer, Subject: sch.OwnerSubject,
			DisplayName: sch.OwnerName, Roles: sch.OwnerRoles}
		desc := "Scheduled run of " + sch.Name
		if sch.Description != "" {
			desc += ": " + sch.Description
		}
		exp, err := s.Exp.CreateWith(ctx, owner, experiments.CreateRequest{Description: truncate(desc, 500),
			MaxDuration: sch.Template.MaxDuration, Steps: sch.Template.Steps, SuccessCriteria: sch.Template.SuccessCriteria, Confirm: true},
			experiments.RequestMeta{}, experiments.CreateOptions{ScheduleID: sch.ID, Scheduled: true})
		var d *experiments.DetailedError
		switch {
		case err == nil:
			run.Outcome, run.ExperimentID = OutcomeStarted, exp.ID
			sch.Runs++
			sch.LastExperimentID, sch.ConsecutiveDenials = exp.ID, 0
			sch.LastRunAt = &now
		case errors.Is(err, experiments.ErrLocked):
			run.Outcome, run.Reason = OutcomeSkipped, "emergency stop engaged"
		case errors.Is(err, experiments.ErrUnavailable) || !errors.As(err, &d):
			run.Outcome, run.Reason = OutcomeFailed, truncate(err.Error(), 500)
		default:
			run.Outcome, run.Reason = OutcomeDenied, truncate(fmt.Sprint(d.Reasons), 500)
			sch.ConsecutiveDenials++
			if sch.ConsecutiveDenials >= MaxConsecutiveDenials {
				sch.State, sch.StateReason = StatePaused, fmt.Sprintf("paused after %d consecutive denials: %s", sch.ConsecutiveDenials, run.Reason)
				sch.NextRunAt = nil
			}
		}
	}
	if run.Outcome == OutcomeSkipped || run.Outcome == OutcomeFailed {
		sysEvent("schedule.run."+lower(run.Outcome), run.Reason)
	}
	if sch.State == StatePaused {
		sysEvent("schedule.paused", sch.StateReason)
	} else if sch.NextRunAt == nil {
		sch.State, sch.StateReason = StateFinished, "no run fits before expiry"
	} else if sch.MaxRuns > 0 && sch.Runs >= sch.MaxRuns {
		sch.State, sch.StateReason, sch.NextRunAt = StateFinished, "reached maxRuns", nil
	}
	if err := s.Store.RecordRun(ctx, sch, run); err != nil {
		s.Log.Error("schedules: record run", slog.String("schedule", sch.Name), slog.Any("error", err))
	}
	s.Log.Info("schedule fired", slog.String("schedule", sch.Name), slog.String("outcome", run.Outcome),
		slog.String("experiment", run.ExperimentID), slog.String("reason", run.Reason))
}

// Run ticks every interval until ctx ends.
func (s *Service) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Tick(ctx)
		}
	}
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
