// Package approval is the Approval Service (architecture §15): an independent trust domain
// that collects four-eyes approvals from the namespace's approver group and signs attestations
// the operator verifies. It holds the only signing key and has no Kubernetes credentials.
package approval

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/kubechaos/kubechaos/backend/internal/auth"
	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
	"github.com/kubechaos/kubechaos/pkg/chaosapi/attestation"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrations returns the approval database migrations.
func Migrations() fs.FS {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		panic(err)
	}
	return sub
}

// States.
const (
	StatePending  = "Pending"
	StateApproved = "Approved"
	StateRejected = "Rejected"
	StateExpired  = "Expired"
)

// Request is one approval request.
type Request struct {
	ID               string                      `json:"id"`
	ExperimentID     string                      `json:"experimentId"`
	ClusterID        string                      `json:"clusterId"`
	Environment      string                      `json:"environment"`
	Namespaces       []string                    `json:"namespaces"`
	ApproverGroup    string                      `json:"approverGroup"`
	Spec             chaosv1.ChaosExperimentSpec `json:"spec"`
	SpecSHA256       string                      `json:"specSha256"`
	Risk             string                      `json:"risk"`
	RequesterIssuer  string                      `json:"requesterIssuer"`
	RequesterSubject string                      `json:"requesterSubject"`
	RequesterName    string                      `json:"requesterName"`
	MinApprovals     int                         `json:"minApprovals"`
	State            string                      `json:"state"`
	Attestation      string                      `json:"attestation,omitempty"`
	CreatedAt        time.Time                   `json:"createdAt"`
	ExpiresAt        time.Time                   `json:"expiresAt"`
	DecidedAt        *time.Time                  `json:"decidedAt,omitempty"`
	Decisions        []Decision                  `json:"decisions"`
}

// Decision is one approver's decision.
type Decision struct {
	ApproverIssuer  string    `json:"approverIssuer"`
	ApproverSubject string    `json:"approverSubject"`
	ApproverName    string    `json:"approverName"`
	Decision        string    `json:"decision"` // approve | reject
	Comment         string    `json:"comment"`
	AuthTime        time.Time `json:"authTime"`
	DecidedAt       time.Time `json:"decidedAt"`
}

// SubmitInput is what the control plane sends. The hash is NOT taken from the caller: it is
// recomputed from the spec here.
type SubmitInput struct {
	ExperimentID  string                      `json:"experimentId"`
	ClusterID     string                      `json:"clusterId"`
	Environment   string                      `json:"environment"`
	Spec          chaosv1.ChaosExperimentSpec `json:"spec"`
	RequesterName string                      `json:"requesterName"`
}

// Store persists requests and decisions.
type Store interface {
	Create(ctx context.Context, r *Request) (*Request, error) // idempotent per experiment
	Get(ctx context.Context, id string) (*Request, error)
	ListForGroups(ctx context.Context, groups []string, limit int) ([]*Request, error)
	AddDecision(ctx context.Context, id string, d Decision) error
	Finish(ctx context.Context, id, state, attestation string) error
}

// Errors.
var (
	ErrNotFound       = errors.New("approval request not found")
	ErrInvalid        = errors.New("invalid approval request")
	ErrForbidden      = errors.New("forbidden")
	ErrStepUpRequired = errors.New("step-up authentication required")
	ErrConflict       = errors.New("request already decided or expired")
)

// Config configures the service.
type Config struct {
	ClusterID      string
	Environment    string
	Routes         map[string]string // namespace -> IdP group path allowed to approve
	MinApprovals   int
	RequestTTL     time.Duration
	AttestationTTL time.Duration
	StepUpMaxAge   time.Duration
	KID            string
	Key            ed25519.PrivateKey
}

// Service implements the approval workflow.
type Service struct {
	Cfg   Config
	Store Store
	Log   *slog.Logger
	Now   func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Submit records a request from the control plane after re-validating it independently.
func (s *Service) Submit(ctx context.Context, in SubmitInput) (*Request, error) {
	if in.ClusterID != s.Cfg.ClusterID || in.Environment != s.Cfg.Environment {
		return nil, fmt.Errorf("%w: this approval service serves cluster %q (%s)", ErrInvalid, s.Cfg.ClusterID, s.Cfg.Environment)
	}
	if in.Spec.ClusterID != in.ClusterID || !isUUID(in.ExperimentID) {
		return nil, fmt.Errorf("%w: cluster or experiment id mismatch", ErrInvalid)
	}
	if errs := chaosv1.ValidateSpec(&in.Spec); len(errs) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrInvalid, errs.ToAggregate().Error())
	}
	namespaces := attestation.TargetNamespaces(&in.Spec)
	group := ""
	for _, ns := range namespaces {
		g := s.Cfg.Routes[ns]
		if g == "" {
			return nil, fmt.Errorf("%w: no approver group is routed for namespace %q", ErrInvalid, ns)
		}
		if group != "" && g != group {
			return nil, fmt.Errorf("%w: namespaces have different approver groups; split the experiment", ErrInvalid)
		}
		group = g
	}
	now := s.now()
	r := &Request{
		ID: newUUID(), ExperimentID: in.ExperimentID, ClusterID: in.ClusterID, Environment: in.Environment,
		Namespaces: namespaces, ApproverGroup: group, Spec: in.Spec,
		SpecSHA256: attestation.SpecSHA256(&in.Spec), // recomputed, never trusted from the caller
		Risk:       string(chaosv1.SpecRisk(&in.Spec)), RequesterIssuer: in.Spec.RequestedBy.Issuer,
		RequesterSubject: in.Spec.RequestedBy.Subject, RequesterName: truncate(in.RequesterName, 255),
		MinApprovals: max(1, s.Cfg.MinApprovals), State: StatePending, CreatedAt: now, ExpiresAt: now.Add(s.Cfg.RequestTTL),
	}
	out, err := s.Store.Create(ctx, r)
	if err != nil {
		return nil, err
	}
	s.Log.InfoContext(ctx, "approval requested", slog.String("request", out.ID), slog.String("experiment", out.ExperimentID),
		slog.String("group", out.ApproverGroup), slog.String("requester", out.RequesterSubject))
	return out, nil
}

// Get returns a request, expiring it if its time has passed.
func (s *Service) Get(ctx context.Context, id string) (*Request, error) {
	r, err := s.Store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if r.State == StatePending && !s.now().Before(r.ExpiresAt) {
		if err := s.Store.Finish(ctx, r.ID, StateExpired, ""); err != nil {
			return nil, err
		}
		r.State = StateExpired
	}
	return r, nil
}

// CanView reports whether p may see a request: approvers of its group, or its requester.
func CanView(p auth.Principal, r *Request) bool {
	return p.InGroup(r.ApproverGroup) || (p.Issuer == r.RequesterIssuer && p.Subject == r.RequesterSubject)
}

// Decide records an approver's decision and, once enough distinct approvals exist, signs the
// attestation. Rules: approver must be in the routed group, must not be the requester, and
// must have authenticated interactively within StepUpMaxAge.
func (s *Service) Decide(ctx context.Context, p auth.Principal, id string, approve bool, comment string) (*Request, error) {
	r, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	switch {
	case !p.InGroup(r.ApproverGroup):
		return nil, fmt.Errorf("%w: only members of %s may decide", ErrForbidden, r.ApproverGroup)
	case p.Issuer == r.RequesterIssuer && p.Subject == r.RequesterSubject:
		return nil, fmt.Errorf("%w: you cannot approve your own experiment (four-eyes)", ErrForbidden)
	case r.State != StatePending:
		return nil, ErrConflict
	case p.AuthTime == nil || s.now().Sub(*p.AuthTime) > s.Cfg.StepUpMaxAge:
		return nil, ErrStepUpRequired
	}
	for _, d := range r.Decisions {
		if d.ApproverIssuer == p.Issuer && d.ApproverSubject == p.Subject {
			return nil, fmt.Errorf("%w: you have already decided", ErrConflict)
		}
	}
	dec := Decision{ApproverIssuer: p.Issuer, ApproverSubject: p.Subject, ApproverName: truncate(p.DisplayName, 255),
		Decision: "reject", Comment: truncate(strings.TrimSpace(comment), 1000), AuthTime: *p.AuthTime, DecidedAt: s.now()}
	if approve {
		dec.Decision = "approve"
	}
	if err := s.Store.AddDecision(ctx, r.ID, dec); err != nil {
		return nil, err
	}
	r.Decisions = append(r.Decisions, dec)
	s.Log.InfoContext(ctx, "approval decision", slog.String("request", r.ID), slog.String("approver", p.Subject), slog.String("decision", dec.Decision))

	if !approve {
		if err := s.Store.Finish(ctx, r.ID, StateRejected, ""); err != nil {
			return nil, err
		}
		r.State = StateRejected
		return r, nil
	}
	var approvals []attestation.Approval
	for _, d := range r.Decisions {
		if d.Decision == "approve" {
			approvals = append(approvals, attestation.Approval{Issuer: d.ApproverIssuer, Subject: d.ApproverSubject,
				Name: d.ApproverName, AuthTime: d.AuthTime.Unix(), At: d.DecidedAt.Unix()})
		}
	}
	if len(approvals) < r.MinApprovals {
		return r, nil // waiting for more approvers
	}
	now := s.now()
	tok, err := attestation.Sign(s.Cfg.Key, s.Cfg.KID, attestation.Claims{
		Claims: jwt.Claims{Issuer: attestation.Issuer, Audience: jwt.Audience{attestation.Audience(r.ClusterID)}, ID: newUUID(),
			IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(s.Cfg.AttestationTTL))},
		ClusterID: r.ClusterID, Environment: r.Environment, Namespaces: r.Namespaces, SpecSHA256: r.SpecSHA256,
		Requester: chaosv1.Requester{Issuer: r.RequesterIssuer, Subject: r.RequesterSubject}, Approvals: approvals, ApproverGroup: r.ApproverGroup,
	})
	if err != nil {
		return nil, fmt.Errorf("sign attestation: %w", err)
	}
	if err := s.Store.Finish(ctx, r.ID, StateApproved, tok); err != nil {
		return nil, err
	}
	r.State, r.Attestation = StateApproved, tok
	s.Log.InfoContext(ctx, "attestation issued", slog.String("request", r.ID), slog.String("experiment", r.ExperimentID), slog.Int("approvals", len(approvals)))
	return r, nil
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
