package experiments

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubechaos/kubechaos/backend/internal/auth"
	"github.com/kubechaos/kubechaos/backend/internal/clusters/clusterstest"
	"github.com/kubechaos/kubechaos/backend/internal/events"
	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
)

var now = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

func setup() (*Service, *MemStore, *clusterstest.Fake) {
	store, conn := NewMemStore(), clusterstest.New()
	return &Service{Store: store, Conn: conn, Audit: store, Broker: events.NewBroker(5),
		Log: slog.New(slog.NewJSONHandler(io.Discard, nil)), Now: func() time.Time { return now }}, store, conn
}

func alice(roles ...auth.Role) auth.Principal {
	at := now.Add(-time.Minute)
	if roles == nil {
		roles = []auth.Role{auth.RoleExperimenter}
	}
	return auth.Principal{IdentityID: "id-alice", Issuer: "https://idp", Subject: "alice", DisplayName: "Alice", Roles: roles, ACR: "1", AuthTime: &at}
}

func request(count int32) CreateRequest {
	zero := int32(0)
	return CreateRequest{
		Description: "kill one web pod", MaxDuration: "2m", Confirm: true,
		Steps: []chaosv1.Step{{Fault: &chaosv1.FaultStep{Type: chaosv1.FaultPodKill,
			Target:  chaosv1.Target{Namespace: "demo", Selector: map[string]chaosv1.LabelValue{"app": "web"}},
			PodKill: &chaosv1.PodKillParams{Count: count, GracePeriodSeconds: &zero}}}},
	}
}

func kind(err error) error {
	var d *DetailedError
	if errors.As(err, &d) {
		return d.Kind
	}
	return err
}

func TestCreateSubmitsWithServerSetIdentityAndAudits(t *testing.T) {
	s, store, conn := setup()
	exp, err := s.Create(context.Background(), alice(), request(1), RequestMeta{SourceIP: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(conn.Submitted) != 1 {
		t.Fatal("not submitted")
	}
	cr := conn.Submitted[0]
	if cr.Spec.ClusterID != "dev-kind-01" || cr.Spec.RequestedBy.Subject != "alice" || cr.Name != exp.Name || exp.State != StateSubmitted {
		t.Fatalf("cr=%+v exp=%+v", cr.Spec, exp)
	}
	if len(store.Audits) != 1 || store.Audits[0].Decision != "allow" || store.Audits[0].ExperimentID != exp.ID ||
		store.Audits[0].PolicyVersion != "42" || store.Audits[0].SourceIP != "10.0.0.1" || store.Audits[0].Namespace != "demo" {
		t.Fatalf("audit %+v", store.Audits)
	}
}

func TestCreateDenials(t *testing.T) {
	cases := map[string]struct {
		p     auth.Principal
		req   func() CreateRequest
		setup func(*clusterstest.Fake, *MemStore)
		want  error
		audit bool // denial must be audited
	}{
		"viewer cannot create":  {p: alice(auth.RoleViewer), req: func() CreateRequest { return request(1) }, want: ErrForbidden, audit: true},
		"auditor cannot create": {p: alice(auth.RoleAuditor), req: func() CreateRequest { return request(1) }, want: ErrForbidden, audit: true},
		"invalid spec":          {p: alice(), req: func() CreateRequest { return request(50) }, want: ErrInvalid, audit: true},
		"protected namespace": {p: alice(), req: func() CreateRequest {
			r := request(1)
			r.Steps[0].Fault.Target.Namespace = "kube-system"
			return r
		}, want: ErrInvalid, audit: true},
		"locked": {p: alice(), req: func() CreateRequest { return request(1) }, setup: func(f *clusterstest.Fake, _ *MemStore) {
			f.LockList = []chaosv1.ChaosLock{{Spec: chaosv1.ChaosLockSpec{Reason: "incident", EngagedBy: "oncall"}}}
		}, want: ErrLocked, audit: true},
		"no policy": {p: alice(), req: func() CreateRequest { return request(1) }, setup: func(f *clusterstest.Fake, _ *MemStore) { f.Pol = nil }, want: ErrPolicy, audit: true},
		"policy namespace": {p: alice(), req: func() CreateRequest {
			r := request(1)
			r.Steps[0].Fault.Target.Namespace = "ledger"
			return r
		}, want: ErrPolicy, audit: true},
		"approval required": {p: alice(), req: func() CreateRequest { return request(1) }, setup: func(f *clusterstest.Fake, _ *MemStore) {
			f.Pol.Spec.Approval.Required = chaosv1.ApprovalAlways
		}, want: ErrApprovalRequired, audit: true},
		"step-up for high risk (count 2) with stale login": {p: func() auth.Principal {
			p := alice()
			old := now.Add(-time.Hour)
			p.AuthTime = &old
			return p
		}(), req: func() CreateRequest { return request(2) }, want: ErrStepUpRequired},
		"step-up when auth_time unknown": {p: func() auth.Principal { p := alice(); p.AuthTime = nil; return p }(), req: func() CreateRequest { return request(2) }, want: ErrStepUpRequired},
		"no confirmation":                {p: alice(), req: func() CreateRequest { r := request(1); r.Confirm = false; return r }, want: ErrConfirmationRequired},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s, store, conn := setup()
			if c.setup != nil {
				c.setup(conn, store)
			}
			_, err := s.Create(context.Background(), c.p, c.req(), RequestMeta{})
			if kind(err) != c.want {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if len(conn.Submitted) != 0 {
				t.Fatal("nothing may be submitted")
			}
			denied := len(store.Audits) == 1 && store.Audits[0].Decision == "deny"
			if c.audit && !denied {
				t.Fatalf("denial not audited: %+v", store.Audits)
			}
		})
	}
}

func TestStepUpFreshLoginAllowsHighRisk(t *testing.T) {
	s, _, conn := setup()
	if _, err := s.Create(context.Background(), alice(), request(2), RequestMeta{}); err != nil || len(conn.Submitted) != 1 {
		t.Fatalf("fresh login must allow high-risk submission: %v", err)
	}
}

func TestCreateFailsClosedWhenAuditFails(t *testing.T) {
	s, store, conn := setup()
	store.AuditErr = errors.New("db down")
	if _, err := s.Create(context.Background(), alice(), request(1), RequestMeta{}); err == nil || len(conn.Submitted) != 0 {
		t.Fatalf("an experiment that cannot be audited must not be submitted (err=%v)", err)
	}
}

func TestCreateClusterUnavailable(t *testing.T) {
	s, _, conn := setup()
	conn.Unavailable = true
	if _, err := s.Create(context.Background(), alice(), request(1), RequestMeta{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
	s, store, conn := setup()
	conn.SubmitErr = errors.New("connection refused")
	if _, err := s.Create(context.Background(), alice(), request(1), RequestMeta{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
	list, _ := store.List(context.Background(), 10)
	if len(list) != 1 || list[0].State != StateSubmitFailed {
		t.Fatalf("failed submission must be recorded: %+v", list)
	}
}

func TestCancelAuthorization(t *testing.T) {
	s, store, conn := setup()
	exp, _ := s.Create(context.Background(), alice(), request(1), RequestMeta{})
	bob := auth.Principal{Issuer: "https://idp", Subject: "bob", Roles: []auth.Role{auth.RoleExperimenter}}
	if _, err := s.Cancel(context.Background(), bob, exp.ID, RequestMeta{}); kind(err) != ErrForbidden {
		t.Fatalf("other experimenter must not cancel: %v", err)
	}
	if _, err := s.Cancel(context.Background(), alice(), exp.ID, RequestMeta{}); err != nil || len(conn.Cancelled) != 1 {
		t.Fatalf("owner cancel: %v", err)
	}
	admin := auth.Principal{Issuer: "https://idp", Subject: "carol", Roles: []auth.Role{auth.RoleAdmin}}
	if _, err := s.Cancel(context.Background(), admin, exp.ID, RequestMeta{}); err != nil {
		t.Fatalf("admin cancel: %v", err)
	}
	last := store.Audits[len(store.Audits)-1]
	if last.Action != "experiment.cancel" || last.ActorSubject != "carol" || last.Decision != "allow" {
		t.Fatalf("cancel not audited: %+v", last)
	}
	if _, err := s.Cancel(context.Background(), admin, "00000000-0000-0000-0000-000000000000", RequestMeta{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
}

func TestSyncTimelineAndFinishAudit(t *testing.T) {
	s, store, _ := setup()
	exp, _ := s.Create(context.Background(), alice(), request(1), RequestMeta{})
	ch, cancel, _ := s.Broker.Subscribe(exp.ID, "alice")
	defer cancel()

	started := metav1.NewTime(now)
	injected := metav1.NewTime(now.Add(time.Second))
	fin := metav1.NewTime(now.Add(6 * time.Second))
	rec := int64(5000)
	score := int32(100)
	cr := &chaosv1.ChaosExperiment{ObjectMeta: metav1.ObjectMeta{Name: exp.Name}}
	cr.Status = chaosv1.ChaosExperimentStatus{Phase: chaosv1.PhaseRunning, StartedAt: &started,
		Steps: []chaosv1.StepStatus{{Phase: chaosv1.StepObserving, StartedAt: &started, InjectedAt: &injected,
			Targets: []chaosv1.PodRef{{Namespace: "demo", Name: "web-1"}}, ReadyBefore: 3}}}
	s.Sync(context.Background(), cr)
	cr.Status.Steps[0].Phase, cr.Status.Steps[0].RecoveryMillis, cr.Status.Steps[0].FinishedAt = chaosv1.StepSucceeded, &rec, &fin
	cr.Status.Phase, cr.Status.Result, cr.Status.Score, cr.Status.CompletedAt = chaosv1.PhaseCompleted, "Passed", &score, &fin
	s.Sync(context.Background(), cr)
	s.Sync(context.Background(), cr) // idempotent: no duplicate events

	evs, _ := store.Events(context.Background(), exp.ID)
	var types []string
	for _, e := range evs {
		types = append(types, e.Type)
	}
	got := strings.Join(types, ",")
	if got != "Started,TargetSelected,PodTerminated,Recovered,Completed" {
		t.Fatalf("timeline %s", got)
	}
	if !strings.Contains(evs[3].Message, "recovery time 5s") || !evs[2].OccurredAt.Equal(injected.Time) {
		t.Fatalf("timeline detail %+v", evs)
	}
	stored, _ := store.Get(context.Background(), exp.ID)
	if stored.Phase != "Completed" || stored.Result != "Passed" || *stored.Score != 100 {
		t.Fatalf("status not mirrored: %+v", stored)
	}
	finished := 0
	for _, a := range store.Audits {
		if a.Action == "experiment.finished" {
			finished++
		}
	}
	if finished != 1 {
		t.Fatalf("exactly one finish audit expected, got %d", finished)
	}
	if len(ch) == 0 {
		t.Fatal("subscribers must receive updates")
	}
}

func TestSyncIgnoresUnknownExperiments(t *testing.T) {
	s, store, _ := setup()
	s.Sync(context.Background(), &chaosv1.ChaosExperiment{ObjectMeta: metav1.ObjectMeta{Name: "exp-created-by-hand"}})
	if len(store.Audits) != 0 {
		t.Fatal("CRs not created by the control plane must be ignored")
	}
}
