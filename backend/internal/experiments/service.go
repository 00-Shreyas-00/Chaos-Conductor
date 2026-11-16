package experiments

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubechaos/kubechaos/backend/internal/audit"
	"github.com/kubechaos/kubechaos/backend/internal/auth"
	"github.com/kubechaos/kubechaos/backend/internal/authorization"
	"github.com/kubechaos/kubechaos/backend/internal/clusters"
	"github.com/kubechaos/kubechaos/backend/internal/events"
	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
	"github.com/kubechaos/kubechaos/pkg/chaosapi/attestation"
)

// StepUpMaxAge is how recent an interactive authentication must be for dangerous submissions.
const StepUpMaxAge = 5 * time.Minute

// Service implements the experiment use cases.
type Service struct {
	Store  Store
	Conn   clusters.Connector
	Audit  Auditor
	Broker *events.Broker
	Log    *slog.Logger
	// Approvals is the approval service client; nil means approval-required experiments are denied.
	Approvals ApprovalClient
	Now       func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// CreateRequest is the user's request. It mirrors the CRD spec, minus fields the server sets
// (clusterID, requestedBy) — clients cannot assert identity or target cluster.
type CreateRequest struct {
	Description     string              `json:"description"`
	MaxDuration     string              `json:"maxDuration"`
	Steps           []chaosv1.Step      `json:"steps"`
	SuccessCriteria []chaosv1.Criterion `json:"successCriteria,omitempty"`
	// Confirm must be true: an explicit "yes, run this" (the UI also asks the user to type the
	// target namespace). It is not a security boundary — authorization and policy are.
	Confirm bool `json:"confirm"`
}

// RequestMeta carries request context for the audit log.
type RequestMeta struct {
	SourceIP string
}

// Dangerous reports whether a submission requires a fresh interactive login (step-up, D11).
func Dangerous(spec *chaosv1.ChaosExperimentSpec, pol *chaosv1.ChaosPolicy) bool {
	return chaosv1.RiskAtLeast(chaosv1.SpecRisk(spec), chaosv1.RiskHigh) ||
		(pol != nil && pol.Spec.Environment == "production")
}

// CreateOptions mark submissions made by the scheduler on a schedule owner's behalf.
type CreateOptions struct {
	// ScheduleID links the experiment to the schedule that started it.
	ScheduleID string
	// Scheduled skips the interactive step-up check: the owner stepped up when creating the
	// schedule, and nobody is present for a scheduled run. Every other gate still applies.
	Scheduled bool
}

// Create authorizes, validates, policy-checks, records (with audit) and submits an experiment.
// Every denial is audited too.
func (s *Service) Create(ctx context.Context, p auth.Principal, req CreateRequest, meta RequestMeta) (*Experiment, error) {
	return s.CreateWith(ctx, p, req, meta, CreateOptions{})
}

// CreateWith is Create with scheduler options.
func (s *Service) CreateWith(ctx context.Context, p auth.Principal, req CreateRequest, meta RequestMeta, opts CreateOptions) (*Experiment, error) {
	spec := chaosv1.ChaosExperimentSpec{
		ClusterID:       s.Conn.ClusterID(),
		RequestedBy:     chaosv1.Requester{Issuer: p.Issuer, Subject: p.Subject},
		MaxDuration:     req.MaxDuration,
		Steps:           req.Steps,
		SuccessCriteria: req.SuccessCriteria,
	}
	base := audit.Event{
		Action: "experiment.create", ActorIssuer: p.Issuer, ActorSubject: p.Subject, ActorName: p.DisplayName,
		AuthLevel: p.ACR, SourceIP: meta.SourceIP, ClusterID: spec.ClusterID,
		Parameters: mustJSON(spec), RequestedBlastRadius: mustJSON(blastRadius(&spec)),
	}
	if ns := attestation.TargetNamespaces(&spec); len(ns) > 0 {
		base.Namespace = strings.Join(ns, ",")
	}
	if ft := faultTypes(&spec); ft != "" {
		base.FaultType = ft
	}
	if opts.ScheduleID != "" {
		base.Action, base.ActorName = "experiment.create.scheduled", truncate(p.DisplayName+" (schedule "+opts.ScheduleID+")", 255)
	}
	deny := func(kind error, reasons ...string) (*Experiment, error) {
		ev := base
		ev.Decision, ev.DecisionReasons, ev.Result = "deny", reasons, "denied"
		if err := s.Audit.Append(ctx, ev); err != nil {
			s.Log.Error("audit write failed for denial", slog.Any("error", err))
		}
		return nil, &DetailedError{Kind: kind, Reasons: reasons}
	}

	if !authorization.Allowed(p, authorization.CreateExperiment) {
		return deny(ErrForbidden, "role does not permit creating experiments")
	}
	if len(req.Description) > 500 {
		return deny(ErrInvalid, "description: at most 500 characters")
	}
	if errs := chaosv1.ValidateSpec(&spec); len(errs) > 0 {
		reasons := make([]string, len(errs))
		for i, e := range errs {
			reasons[i] = e.Error()
		}
		return deny(ErrInvalid, reasons...)
	}

	locks, err := s.Conn.Locks(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if len(locks) > 0 {
		return deny(ErrLocked, fmt.Sprintf("emergency stop engaged by %s: %s", locks[0].Spec.EngagedBy, locks[0].Spec.Reason))
	}
	pol, err := s.Conn.Policy(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if pol == nil {
		return deny(ErrPolicy, "no ChaosPolicy is installed on the cluster; nothing may run")
	}
	base.PolicyVersion = pol.ResourceVersion
	if v := chaosv1.CheckPolicy(&spec, pol, pol.Spec.Environment); len(v) > 0 {
		reasons := make([]string, len(v))
		for i, x := range v {
			reasons[i] = x.Field + ": " + x.Message
		}
		return deny(ErrPolicy, reasons...)
	}
	needApproval := chaosv1.ApprovalRequired(&spec, pol)
	if needApproval && s.Approvals == nil {
		return deny(ErrApprovalRequired, fmt.Sprintf("cluster policy requires %d approval(s) for this experiment, and no approval service is configured", chaosv1.MinApprovals(pol)))
	}
	if !opts.Scheduled && Dangerous(&spec, pol) && (p.AuthTime == nil || s.now().Sub(*p.AuthTime) > StepUpMaxAge) {
		// Not audited as a denial: the user is asked to re-authenticate and retry.
		return nil, &DetailedError{Kind: ErrStepUpRequired, Reasons: []string{"this experiment is high-risk: sign in again to confirm it is you"}}
	}
	if !req.Confirm {
		return nil, &DetailedError{Kind: ErrConfirmationRequired, Reasons: []string{"set confirm=true to run this experiment"}}
	}

	exp := &Experiment{
		ID: newUUID(), ClusterID: spec.ClusterID, RequesterID: p.IdentityID, RequesterIssuer: p.Issuer,
		RequesterSubj: p.Subject, RequesterName: p.DisplayName, Description: req.Description, Spec: spec,
		SpecSHA256: attestation.SpecSHA256(&spec), Risk: chaosv1.SpecRisk(&spec), State: StateSubmitting, ScheduleID: opts.ScheduleID,
	}
	exp.Name = "exp-" + strings.ReplaceAll(exp.ID, "-", "")[:12]
	ev := base
	ev.ExperimentID, ev.Resource, ev.Decision, ev.Result = exp.ID, "chaosexperiment/"+exp.Name, "allow", "accepted"
	if needApproval {
		exp.State, ev.Result = StatePendingApproval, "pending approval"
	}
	// Intent and its audit record commit together; if auditing fails, nothing is submitted.
	if err := s.Store.CreateWithAudit(ctx, exp, ev); err != nil {
		return nil, fmt.Errorf("record experiment: %w", err)
	}

	if needApproval {
		// Nothing is created in the cluster yet: the approval poller submits the CR with the
		// signed attestation once the namespace's approver group approves.
		reqID, err := s.Approvals.Request(ctx, ApprovalInput{ExperimentID: exp.ID, ClusterID: spec.ClusterID,
			Environment: pol.Spec.Environment, Spec: spec, RequesterName: p.DisplayName})
		if err != nil {
			_ = s.Store.SetState(ctx, exp.ID, StateSubmitFailed)
			fail := ev
			fail.Action, fail.Result = "experiment.approval_request", "failed: "+truncate(err.Error(), 200)
			_ = s.Audit.Append(ctx, fail)
			return nil, fmt.Errorf("%w: approval service: %v", ErrUnavailable, err)
		}
		if err := s.Store.SetApprovalRequest(ctx, exp.ID, reqID); err != nil {
			return nil, fmt.Errorf("record approval request: %w", err)
		}
		exp.ApprovalRequest = reqID
		s.Log.Info("experiment awaiting approval", slog.String("experiment", exp.Name), slog.String("approval_request", reqID))
		return exp, nil
	}
	if err := s.submit(ctx, exp, ev, ""); err != nil {
		return nil, err
	}
	s.Log.Info("experiment submitted", slog.String("experiment", exp.Name), slog.String("subject", p.Subject), slog.String("risk", string(exp.Risk)))
	return exp, nil
}

// submit creates the ChaosExperiment (with the attestation annotation when approved).
func (s *Service) submit(ctx context.Context, exp *Experiment, ev audit.Event, attestationToken string) error {
	cr := &chaosv1.ChaosExperiment{ObjectMeta: metav1.ObjectMeta{Name: exp.Name,
		Labels: map[string]string{"app.kubernetes.io/managed-by": "kubechaos-api"}}, Spec: exp.Spec}
	if attestationToken != "" {
		cr.Annotations = map[string]string{chaosv1.AnnotationApproval: attestationToken}
	}
	if err := s.Conn.Submit(ctx, cr); err != nil {
		_ = s.Store.SetState(ctx, exp.ID, StateSubmitFailed)
		fail := ev
		fail.Action, fail.Result = "experiment.submit", "failed: "+truncate(err.Error(), 200)
		_ = s.Audit.Append(ctx, fail)
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if err := s.Store.SetState(ctx, exp.ID, StateSubmitted); err != nil {
		s.Log.Error("record submitted state", slog.Any("error", err))
	}
	exp.State = StateSubmitted
	return nil
}

// PollApprovals checks every experiment awaiting approval once: approved ones are submitted
// with their attestation, rejected/expired ones are closed. Errors are retried next round.
func (s *Service) PollApprovals(ctx context.Context) {
	if s.Approvals == nil {
		return
	}
	pending, err := s.Store.ListPendingApproval(ctx)
	if err != nil {
		s.Log.Warn("approvals: list pending", slog.Any("error", err))
		return
	}
	for _, exp := range pending {
		if exp.ApprovalRequest == "" {
			continue
		}
		st, err := s.Approvals.Status(ctx, exp.ApprovalRequest)
		if err != nil {
			s.Log.Warn("approvals: status", slog.String("experiment", exp.Name), slog.Any("error", err))
			continue
		}
		ev := audit.Event{ActorSubject: "system:approval-service", ClusterID: exp.ClusterID, ExperimentID: exp.ID,
			Resource: "chaosexperiment/" + exp.Name, Parameters: mustJSON(map[string]string{"approvalRequestId": exp.ApprovalRequest})}
		switch st.State {
		case "Approved":
			if st.Attestation == "" {
				continue
			}
			ev.Action, ev.Decision, ev.Result = "experiment.approved", "allow", "submitted with attestation"
			if err := s.Audit.Append(ctx, ev); err != nil {
				s.Log.Error("audit write failed for approval", slog.Any("error", err))
				continue // fail closed: do not submit what cannot be audited
			}
			if err := s.submit(ctx, exp, ev, st.Attestation); err != nil {
				s.Log.Warn("approvals: submit", slog.String("experiment", exp.Name), slog.Any("error", err))
				continue
			}
			s.Log.Info("approved experiment submitted", slog.String("experiment", exp.Name))
		case "Rejected", "Expired":
			state := StateApprovalRejected
			if st.State == "Expired" {
				state = StateApprovalExpired
			}
			ev.Action, ev.Decision, ev.Result = "experiment.approval_"+strings.ToLower(st.State), "deny", strings.ToLower(st.State)
			_ = s.Audit.Append(ctx, ev)
			if err := s.Store.SetState(ctx, exp.ID, state); err != nil {
				s.Log.Warn("approvals: set state", slog.Any("error", err))
				continue
			}
			exp.State = state
		default:
			continue
		}
		if s.Broker != nil {
			if cur, err := s.Store.Get(ctx, exp.ID); err == nil {
				s.Broker.Publish(exp.ID, events.Message{Type: "experiment", Data: cur})
			}
		}
	}
}

// RunApprovals polls the approval service until ctx ends.
func (s *Service) RunApprovals(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.PollApprovals(ctx)
		}
	}
}

// Cancel requests cancellation. Owners (experimenter) or approver/admin may cancel; cancelling
// never needs approval or step-up (stopping is cheap to allow, D8).
func (s *Service) Cancel(ctx context.Context, p auth.Principal, id string, meta RequestMeta) (*Experiment, error) {
	exp, err := s.Store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	ev := audit.Event{Action: "experiment.cancel", ActorIssuer: p.Issuer, ActorSubject: p.Subject, ActorName: p.DisplayName,
		AuthLevel: p.ACR, SourceIP: meta.SourceIP, ClusterID: exp.ClusterID, ExperimentID: exp.ID, Resource: "chaosexperiment/" + exp.Name}
	if !authorization.CanCancel(p, exp.RequesterIssuer, exp.RequesterSubj) {
		ev.Decision, ev.Result = "deny", "denied"
		_ = s.Audit.Append(ctx, ev)
		return nil, &DetailedError{Kind: ErrForbidden, Reasons: []string{"only the requester, an approver or an admin may cancel"}}
	}
	if exp.State != StateSubmitted || isTerminal(exp.Phase) {
		return nil, &DetailedError{Kind: ErrConflict, Reasons: []string{"experiment is not running"}}
	}
	ev.Decision = "allow"
	if err := s.Audit.Append(ctx, ev); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	if err := s.Conn.Cancel(ctx, exp.Name); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	_ = s.Store.SetCancelRequested(ctx, exp.ID)
	exp.CancelRequested = true
	return exp, nil
}

// Sync mirrors one ChaosExperiment from the cluster into the database and to subscribers.
// Unknown CRs (not created by this control plane) are ignored.
func (s *Service) Sync(ctx context.Context, cr *chaosv1.ChaosExperiment) {
	exp, err := s.Store.GetByName(ctx, cr.Name)
	if errors.Is(err, ErrNotFound) {
		return
	}
	if err != nil {
		s.Log.Warn("sync: load experiment", slog.String("experiment", cr.Name), slog.Any("error", err))
		return
	}
	newEvents := Timeline(exp.Status, &cr.Status, s.now())
	if len(newEvents) == 0 && exp.Status != nil && exp.Phase == string(cr.Status.Phase) {
		return
	}
	stored, err := s.Store.ApplyClusterStatus(ctx, exp.ID, &cr.Status, newEvents)
	if err != nil {
		s.Log.Warn("sync: store status", slog.String("experiment", cr.Name), slog.Any("error", err))
		return
	}
	wasTerminal := isTerminal(exp.Phase)
	exp.Phase, exp.Result, exp.Score, exp.Status = string(cr.Status.Phase), cr.Status.Result, cr.Status.Score, cr.Status.DeepCopy()
	if s.Broker != nil {
		s.Broker.Publish(exp.ID, events.Message{Type: "experiment", Data: exp})
		for _, e := range stored {
			s.Broker.Publish(exp.ID, events.Message{Type: "timeline", Data: e})
		}
	}
	if !wasTerminal && isTerminal(exp.Phase) {
		var affected []chaosv1.PodRef
		for _, st := range cr.Status.Steps {
			affected = append(affected, st.Targets...)
		}
		ev := audit.Event{Action: "experiment.finished", ActorSubject: "system:operator", ClusterID: exp.ClusterID,
			ExperimentID: exp.ID, Resource: "chaosexperiment/" + exp.Name, Result: exp.Phase + " " + exp.Result + ": " + truncate(cr.Status.Message, 300),
			AffectedResources: mustJSON(affected)}
		if err := s.Audit.Append(ctx, ev); err != nil {
			s.Log.Error("audit write failed for experiment result", slog.Any("error", err))
		}
	}
}

// Run watches the cluster until ctx ends.
func (s *Service) Run(ctx context.Context) {
	_ = s.Conn.Watch(ctx, func(cr *chaosv1.ChaosExperiment) { s.Sync(ctx, cr) })
}

func isTerminal(phase string) bool {
	switch chaosv1.ExperimentPhase(phase) {
	case chaosv1.PhaseCompleted, chaosv1.PhaseFailed, chaosv1.PhaseAborted, chaosv1.PhaseRejected:
		return true
	}
	return false
}

func blastRadius(s *chaosv1.ChaosExperimentSpec) map[string]any {
	pods := int32(0)
	for _, st := range s.Steps {
		if st.Fault != nil && st.Fault.PodKill != nil {
			pods += st.Fault.PodKill.Count
		}
	}
	return map[string]any{"maxPodsAffected": pods, "namespaces": attestation.TargetNamespaces(s), "maxDuration": s.MaxDuration}
}

func faultTypes(s *chaosv1.ChaosExperimentSpec) string {
	seen := map[chaosv1.FaultType]bool{}
	var out []string
	for _, st := range s.Steps {
		if st.Fault != nil && !seen[st.Fault.Type] {
			seen[st.Fault.Type] = true
			out = append(out, string(st.Fault.Type))
		}
	}
	return strings.Join(out, ",")
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Preflight runs the admission checks of Create without recording or submitting anything:
// authorization, validation, cluster policy and approval availability. Schedules use it
// so a schedule that could never run is refused when it is created. The lock is ignored
// (runs during a lock are skipped, not refused).
func (s *Service) Preflight(ctx context.Context, p auth.Principal, req CreateRequest) (*chaosv1.ChaosExperimentSpec, *chaosv1.ChaosPolicy, error) {
	spec := &chaosv1.ChaosExperimentSpec{
		ClusterID: s.Conn.ClusterID(), RequestedBy: chaosv1.Requester{Issuer: p.Issuer, Subject: p.Subject},
		MaxDuration: req.MaxDuration, Steps: req.Steps, SuccessCriteria: req.SuccessCriteria,
	}
	if !authorization.Allowed(p, authorization.CreateExperiment) {
		return nil, nil, &DetailedError{Kind: ErrForbidden, Reasons: []string{"role does not permit creating experiments"}}
	}
	if len(req.Description) > 500 {
		return nil, nil, &DetailedError{Kind: ErrInvalid, Reasons: []string{"description: at most 500 characters"}}
	}
	if errs := chaosv1.ValidateSpec(spec); len(errs) > 0 {
		reasons := make([]string, len(errs))
		for i, e := range errs {
			reasons[i] = e.Error()
		}
		return nil, nil, &DetailedError{Kind: ErrInvalid, Reasons: reasons}
	}
	pol, err := s.Conn.Policy(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if pol == nil {
		return nil, nil, &DetailedError{Kind: ErrPolicy, Reasons: []string{"no ChaosPolicy is installed on the cluster; nothing may run"}}
	}
	if v := chaosv1.CheckPolicy(spec, pol, pol.Spec.Environment); len(v) > 0 {
		reasons := make([]string, len(v))
		for i, x := range v {
			reasons[i] = x.Field + ": " + x.Message
		}
		return nil, nil, &DetailedError{Kind: ErrPolicy, Reasons: reasons}
	}
	if chaosv1.ApprovalRequired(spec, pol) && s.Approvals == nil {
		return nil, nil, &DetailedError{Kind: ErrApprovalRequired, Reasons: []string{"cluster policy requires approval and no approval service is configured"}}
	}
	return spec, pol, nil
}

// IsTerminal reports whether an experiment has finished (or can never run).
func IsTerminal(e *Experiment) bool {
	switch e.State {
	case StateSubmitFailed, StateApprovalRejected, StateApprovalExpired:
		return true
	}
	return isTerminal(e.Phase)
}
