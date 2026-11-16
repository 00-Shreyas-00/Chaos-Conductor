package approval

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/kubechaos/kubechaos/backend/internal/auth"
	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
	"github.com/kubechaos/kubechaos/pkg/chaosapi/attestation"
)

const group = "/teams/demo/head-developers"

var now = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

func newService(t *testing.T) (*Service, chaosv1.TrustedKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &Service{
		Cfg: Config{ClusterID: "dev-kind-01", Environment: "development", Routes: map[string]string{"demo": group},
			MinApprovals: 1, RequestTTL: time.Hour, AttestationTTL: time.Hour, StepUpMaxAge: 5 * time.Minute, KID: "k1", Key: priv},
		Store: NewMemStore(), Log: slog.New(slog.NewJSONHandler(io.Discard, nil)), Now: func() time.Time { return now },
	}, chaosv1.TrustedKey{KID: "k1", PublicKey: base64.StdEncoding.EncodeToString(pub)}
}

func input() SubmitInput {
	return SubmitInput{ExperimentID: "11111111-2222-4333-8444-555555555555", ClusterID: "dev-kind-01", Environment: "development",
		Spec: chaosv1.ChaosExperimentSpec{ClusterID: "dev-kind-01", RequestedBy: chaosv1.Requester{Issuer: "https://idp", Subject: "alice"},
			MaxDuration: "2m", Steps: []chaosv1.Step{{Fault: &chaosv1.FaultStep{Type: chaosv1.FaultPodKill,
				Target: chaosv1.Target{Namespace: "demo", Selector: map[string]chaosv1.LabelValue{"app": "web"}}, PodKill: &chaosv1.PodKillParams{Count: 2}}}}}}
}

func approver(subject string, authAge time.Duration, groups ...string) auth.Principal {
	at := now.Add(-authAge)
	return auth.Principal{Issuer: "https://idp", Subject: subject, DisplayName: subject, AuthTime: &at, Groups: groups}
}

func TestApproveIssuesVerifiableAttestation(t *testing.T) {
	s, key := newService(t)
	r, err := s.Submit(context.Background(), input())
	if err != nil {
		t.Fatal(err)
	}
	in0 := input()
	if r.ApproverGroup != group || r.SpecSHA256 != attestation.SpecSHA256(&in0.Spec) || r.Risk != "High" {
		t.Fatalf("request %+v", r)
	}
	out, err := s.Decide(context.Background(), approver("bob", time.Minute, group), r.ID, true, "ok")
	if err != nil || out.State != StateApproved || out.Attestation == "" {
		t.Fatalf("decide: %v %+v", err, out)
	}
	spec := input().Spec
	c, err := attestation.Verify(out.Attestation, []chaosv1.TrustedKey{key}, attestation.Expectations{
		ClusterID: "dev-kind-01", Environment: "development", Spec: &spec, MinApprovals: 1, MaxAge: time.Hour, Now: now})
	if err != nil || c.ApproverGroup != group || c.Approvals[0].Subject != "bob" {
		t.Fatalf("operator-side verification failed: %v %+v", err, c)
	}
}

func TestDecideRules(t *testing.T) {
	cases := map[string]struct {
		p    auth.Principal
		want error
	}{
		"not in the routed group":  {approver("eve", time.Minute, "/teams/other/head-developers"), ErrForbidden},
		"requester self-approval":  {approver("alice", time.Minute, group), ErrForbidden},
		"stale login (no step-up)": {approver("bob", time.Hour, group), ErrStepUpRequired},
		"no auth time":             {auth.Principal{Issuer: "https://idp", Subject: "bob", Groups: []string{group}}, ErrStepUpRequired},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s, _ := newService(t)
			r, _ := s.Submit(context.Background(), input())
			if _, err := s.Decide(context.Background(), c.p, r.ID, true, ""); !errors.Is(err, c.want) {
				t.Fatalf("got %v want %v", err, c.want)
			}
			got, _ := s.Get(context.Background(), r.ID)
			if got.State != StatePending || got.Attestation != "" {
				t.Fatal("request must remain pending without an attestation")
			}
		})
	}
}

func TestRejectAndDoubleDecision(t *testing.T) {
	s, _ := newService(t)
	r, _ := s.Submit(context.Background(), input())
	out, err := s.Decide(context.Background(), approver("bob", time.Minute, group), r.ID, false, "too risky")
	if err != nil || out.State != StateRejected || out.Attestation != "" {
		t.Fatalf("%v %+v", err, out)
	}
	if _, err := s.Decide(context.Background(), approver("carol", time.Minute, group), r.ID, true, ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("decided requests are final: %v", err)
	}
}

func TestFourEyesWithTwoApprovals(t *testing.T) {
	s, _ := newService(t)
	s.Cfg.MinApprovals = 2
	r, _ := s.Submit(context.Background(), input())
	out, _ := s.Decide(context.Background(), approver("bob", time.Minute, group), r.ID, true, "")
	if out.State != StatePending {
		t.Fatal("one approval of two must not sign")
	}
	if _, err := s.Decide(context.Background(), approver("bob", time.Minute, group), r.ID, true, ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("the same approver must not count twice: %v", err)
	}
	out, _ = s.Decide(context.Background(), approver("carol", time.Minute, group), r.ID, true, "")
	if out.State != StateApproved {
		t.Fatalf("two distinct approvals must sign: %s", out.State)
	}
}

func TestSubmitValidation(t *testing.T) {
	s, _ := newService(t)
	bad := map[string]func(*SubmitInput){
		"other cluster":      func(in *SubmitInput) { in.ClusterID = "prod-01"; in.Spec.ClusterID = "prod-01" },
		"other environment":  func(in *SubmitInput) { in.Environment = "production" },
		"unrouted namespace": func(in *SubmitInput) { in.Spec.Steps[0].Fault.Target.Namespace = "ledger" },
		"invalid spec":       func(in *SubmitInput) { in.Spec.Steps[0].Fault.PodKill.Count = 99 },
		"bad experiment id":  func(in *SubmitInput) { in.ExperimentID = "x" },
	}
	for name, mutate := range bad {
		in := input()
		mutate(&in)
		if _, err := s.Submit(context.Background(), in); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	a, _ := s.Submit(context.Background(), input())
	b, _ := s.Submit(context.Background(), input())
	if a.ID != b.ID {
		t.Fatal("submission must be idempotent per experiment")
	}
}

func TestExpiry(t *testing.T) {
	s, _ := newService(t)
	r, _ := s.Submit(context.Background(), input())
	s.Now = func() time.Time { return now.Add(2 * time.Hour) }
	got, _ := s.Get(context.Background(), r.ID)
	if got.State != StateExpired {
		t.Fatalf("state %s", got.State)
	}
	if _, err := s.Decide(context.Background(), approver("bob", 0, group), r.ID, true, ""); !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "decided or expired") {
		t.Fatalf("expired requests cannot be approved: %v", err)
	}
}
