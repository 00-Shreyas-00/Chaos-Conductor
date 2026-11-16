package schedules

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/kubechaos/kubechaos/backend/internal/auth"
	"github.com/kubechaos/kubechaos/backend/internal/clusters/clusterstest"
	"github.com/kubechaos/kubechaos/backend/internal/events"
	"github.com/kubechaos/kubechaos/backend/internal/experiments"
	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
)

// Monday 16 Nov 2026, 11:00 UTC.
var t0 = time.Date(2026, 11, 16, 11, 0, 0, 0, time.UTC)

type env struct {
	svc   *Service
	store *MemStore
	exps  *experiments.MemStore
	conn  *clusterstest.Fake
	clock *time.Time
}

func setup(t *testing.T) *env {
	t.Helper()
	exps, conn := experiments.NewMemStore(), clusterstest.New()
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	clock := t0
	now := func() time.Time { return clock }
	expSvc := &experiments.Service{Store: exps, Conn: conn, Audit: exps, Broker: events.NewBroker(5), Log: log, Now: now}
	store := NewMemStore(exps)
	return &env{svc: &Service{Store: store, Exp: expSvc, Audit: exps, Log: log, Now: now, Uniform: func() float64 { return 1 }},
		store: store, exps: exps, conn: conn, clock: &clock}
}

func (e *env) advance(d time.Duration) { *e.clock = e.clock.Add(d) }

func owner(roles ...auth.Role) auth.Principal {
	at := t0.Add(-time.Minute)
	if roles == nil {
		roles = []auth.Role{auth.RoleExperimenter}
	}
	return auth.Principal{IdentityID: "id-alice", Issuer: "https://idp", Subject: "alice", DisplayName: "Alice", Roles: roles, AuthTime: &at}
}

func req() CreateRequest {
	zero := int32(0)
	return CreateRequest{Name: "web-pod-kill", Description: "kill a web pod now and then", MinInterval: "1h", MeanInterval: "1h",
		Window:    Window{Days: []string{"Mon", "Tue", "Wed", "Thu", "Fri"}, From: "09:00", To: "17:00", TimeZone: "UTC"},
		ExpiresAt: t0.Add(30 * 24 * time.Hour), Confirm: true,
		Template: Template{MaxDuration: "2m", Steps: []chaosv1.Step{{Fault: &chaosv1.FaultStep{Type: chaosv1.FaultPodKill,
			Target: chaosv1.Target{Namespace: "demo", Selector: map[string]chaosv1.LabelValue{"app": "web"}}, PodKill: &chaosv1.PodKillParams{Count: 1, GracePeriodSeconds: &zero}}}}}}
}

func kind(err error) error {
	var d *experiments.DetailedError
	if errors.As(err, &d) {
		return d.Kind
	}
	return err
}

func TestCreateComputesFirstRunInsideWindow(t *testing.T) {
	e := setup(t)
	s, err := e.svc.Create(context.Background(), owner(), req(), experiments.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if s.State != StateActive || s.NextRunAt == nil || !s.NextRunAt.Equal(t0.Add(time.Hour)) || s.Risk != "Medium" && s.Risk != "Low" {
		t.Fatalf("schedule %+v next %v", s, s.NextRunAt)
	}
	if len(e.exps.Audits) != 1 || e.exps.Audits[0].Action != "schedule.create" || e.exps.Audits[0].Decision != "allow" {
		t.Fatalf("audit %+v", e.exps.Audits)
	}
	if len(e.conn.Submitted) != 0 {
		t.Fatal("creating a schedule must not run anything")
	}
}

func TestCreateValidation(t *testing.T) {
	cases := map[string]struct {
		p      auth.Principal
		mutate func(*CreateRequest)
		setup  func(*clusterstest.Fake)
		want   error
	}{
		"viewer":               {p: owner(auth.RoleViewer), want: experiments.ErrForbidden},
		"bad name":             {mutate: func(r *CreateRequest) { r.Name = "Web Pods!" }, want: experiments.ErrInvalid},
		"min below floor":      {mutate: func(r *CreateRequest) { r.MinInterval, r.MeanInterval = "30s", "1h" }, want: experiments.ErrInvalid},
		"mean below min":       {mutate: func(r *CreateRequest) { r.MinInterval, r.MeanInterval = "2h", "1h" }, want: experiments.ErrInvalid},
		"not a duration":       {mutate: func(r *CreateRequest) { r.MinInterval = "daily" }, want: experiments.ErrInvalid},
		"expiry too far":       {mutate: func(r *CreateRequest) { r.ExpiresAt = t0.Add(100 * 24 * time.Hour) }, want: experiments.ErrInvalid},
		"expiry in the past":   {mutate: func(r *CreateRequest) { r.ExpiresAt = t0.Add(-time.Hour) }, want: experiments.ErrInvalid},
		"bad window":           {mutate: func(r *CreateRequest) { r.Window.TimeZone = "Nowhere/Land" }, want: experiments.ErrInvalid},
		"window never in time": {mutate: func(r *CreateRequest) { r.ExpiresAt = t0.Add(30 * time.Minute) }, want: experiments.ErrInvalid},
		"policy namespace":     {mutate: func(r *CreateRequest) { r.Template.Steps[0].Fault.Target.Namespace = "ledger" }, want: experiments.ErrPolicy},
		"invalid template":     {mutate: func(r *CreateRequest) { r.Template.Steps[0].Fault.PodKill.Count = 50 }, want: experiments.ErrInvalid},
		"no confirmation":      {mutate: func(r *CreateRequest) { r.Confirm = false }, want: experiments.ErrConfirmationRequired},
		"too many runs":        {mutate: func(r *CreateRequest) { r.MaxRuns = 5000 }, want: experiments.ErrInvalid},
		"production floor is 1h": {mutate: func(r *CreateRequest) { r.MinInterval, r.MeanInterval = "5m", "5m" }, setup: func(f *clusterstest.Fake) {
			f.Pol.Spec.Environment = "staging"
		}, want: experiments.ErrInvalid},
		"approval without service": {setup: func(f *clusterstest.Fake) { f.Pol.Spec.Approval.Required = chaosv1.ApprovalAlways }, want: experiments.ErrApprovalRequired},
		"high risk needs step-up": {p: func() auth.Principal {
			p := owner()
			old := t0.Add(-time.Hour)
			p.AuthTime = &old
			return p
		}(), mutate: func(r *CreateRequest) { r.Template.Steps[0].Fault.PodKill.Count = 2 }, want: experiments.ErrStepUpRequired},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := setup(t)
			if c.setup != nil {
				c.setup(e.conn)
			}
			r := req()
			if c.mutate != nil {
				c.mutate(&r)
			}
			p := c.p
			if p.Subject == "" {
				p = owner()
			}
			if _, err := e.svc.Create(context.Background(), p, r, experiments.RequestMeta{}); kind(err) != c.want {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if l, _ := e.store.List(context.Background(), 10); len(l) != 0 {
				t.Fatal("nothing may be stored")
			}
		})
	}
}

func create(t *testing.T, e *env, mutate ...func(*CreateRequest)) *Schedule {
	t.Helper()
	r := req()
	for _, m := range mutate {
		m(&r)
	}
	s, err := e.svc.Create(context.Background(), owner(), r, experiments.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func get(t *testing.T, e *env, id string) *Schedule {
	s, err := e.store.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func finishLast(t *testing.T, e *env, id string) {
	s := get(t, e, id)
	_, _ = e.exps.ApplyClusterStatus(context.Background(), s.LastExperimentID, &chaosv1.ChaosExperimentStatus{Phase: chaosv1.PhaseCompleted}, nil)
}

func TestTickFiresDueSchedulesThroughTheExperimentPipeline(t *testing.T) {
	e := setup(t)
	s := create(t, e)
	e.svc.Tick(context.Background())
	if len(e.conn.Submitted) != 0 {
		t.Fatal("not due yet")
	}
	e.advance(time.Hour)
	e.svc.Tick(context.Background())
	if len(e.conn.Submitted) != 1 {
		t.Fatalf("due schedule did not fire: %d", len(e.conn.Submitted))
	}
	cr := e.conn.Submitted[0]
	if cr.Spec.RequestedBy.Subject != "alice" {
		t.Fatalf("runs are requested by the owner: %+v", cr.Spec.RequestedBy)
	}
	got := get(t, e, s.ID)
	if got.Runs != 1 || got.LastExperimentID == "" || got.NextRunAt == nil || !got.NextRunAt.Equal(t0.Add(2*time.Hour)) {
		t.Fatalf("after run: %+v next=%v", got, got.NextRunAt)
	}
	exp, _ := e.exps.Get(context.Background(), got.LastExperimentID)
	if exp.ScheduleID != s.ID {
		t.Fatal("experiment must link back to its schedule")
	}
	var scheduled bool
	for _, a := range e.exps.Audits {
		scheduled = scheduled || a.Action == "experiment.create.scheduled" && a.Decision == "allow"
	}
	if !scheduled {
		t.Fatal("scheduled run not audited")
	}
	// Ticking again at the same instant does nothing (already claimed).
	e.svc.Tick(context.Background())
	if len(e.conn.Submitted) != 1 {
		t.Fatal("fired twice")
	}
}

func TestSkipsWhilePreviousRunIsActiveOrLocked(t *testing.T) {
	e := setup(t)
	s := create(t, e)
	e.advance(time.Hour)
	e.svc.Tick(context.Background())
	e.advance(time.Hour)
	e.svc.Tick(context.Background()) // previous experiment has not finished
	runs, _ := e.store.Runs(context.Background(), s.ID, 10)
	if len(e.conn.Submitted) != 1 || runs[0].Outcome != OutcomeSkipped {
		t.Fatalf("expected skip, runs %+v", runs)
	}
	finishLast(t, e, s.ID)
	e.conn.LockList = []chaosv1.ChaosLock{{Spec: chaosv1.ChaosLockSpec{Reason: "incident", EngagedBy: "oncall"}}}
	e.advance(time.Hour)
	e.svc.Tick(context.Background())
	runs, _ = e.store.Runs(context.Background(), s.ID, 10)
	if len(e.conn.Submitted) != 1 || runs[0].Outcome != OutcomeSkipped || runs[0].Reason != "emergency stop engaged" {
		t.Fatalf("locked run must be skipped: %+v", runs[0])
	}
	if got := get(t, e, s.ID); got.State != StateActive || got.ConsecutiveDenials != 0 {
		t.Fatalf("skips do not pause: %+v", got)
	}
}

func TestPausesAfterConsecutiveDenials(t *testing.T) {
	e := setup(t)
	s := create(t, e)
	e.conn.Pol.Spec.AllowedNamespaces = []string{"other"} // the policy changed after creation
	for i := 0; i < MaxConsecutiveDenials; i++ {
		e.advance(time.Hour)
		e.svc.Tick(context.Background())
	}
	got := get(t, e, s.ID)
	if got.State != StatePaused || got.NextRunAt != nil || got.ConsecutiveDenials != MaxConsecutiveDenials {
		t.Fatalf("expected auto-pause: %+v", got)
	}
	e.advance(time.Hour)
	e.svc.Tick(context.Background())
	if runs, _ := e.store.Runs(context.Background(), s.ID, 10); len(runs) != MaxConsecutiveDenials {
		t.Fatalf("paused schedules must not run: %d runs", len(runs))
	}
}

func TestMaxRunsAndExpiryFinish(t *testing.T) {
	e := setup(t)
	s := create(t, e, func(r *CreateRequest) { r.MaxRuns = 1 })
	e.advance(time.Hour)
	e.svc.Tick(context.Background())
	if got := get(t, e, s.ID); got.State != StateFinished || got.Runs != 1 {
		t.Fatalf("maxRuns: %+v", got)
	}

	e2 := setup(t)
	s2 := create(t, e2, func(r *CreateRequest) { r.ExpiresAt = t0.Add(90 * time.Minute) })
	e2.advance(time.Hour)
	e2.svc.Tick(context.Background()) // runs at 12:00; the next slot (13:00) is after expiry
	if got := get(t, e2, s2.ID); got.State != StateFinished || got.Runs != 1 || got.NextRunAt != nil {
		t.Fatalf("expiry: %+v", got)
	}
}

func TestPauseResumeDeleteAuthorization(t *testing.T) {
	e := setup(t)
	s := create(t, e)
	ctx := context.Background()
	eve := auth.Principal{Issuer: "https://idp", Subject: "eve", Roles: []auth.Role{auth.RoleExperimenter}}
	if _, err := e.svc.Pause(ctx, eve, s.ID, experiments.RequestMeta{}); kind(err) != experiments.ErrForbidden {
		t.Fatalf("another experimenter must not pause: %v", err)
	}
	bob := auth.Principal{Issuer: "https://idp", Subject: "bob", Roles: []auth.Role{auth.RoleApprover}}
	if got, err := e.svc.Pause(ctx, bob, s.ID, experiments.RequestMeta{}); err != nil || got.State != StatePaused || got.NextRunAt != nil {
		t.Fatalf("approver pause: %v %+v", err, got)
	}
	if _, err := e.svc.Resume(ctx, bob, s.ID, experiments.RequestMeta{}); kind(err) != experiments.ErrForbidden {
		t.Fatalf("only the owner resumes: %v", err)
	}
	got, err := e.svc.Resume(ctx, owner(), s.ID, experiments.RequestMeta{})
	if err != nil || got.State != StateActive || got.NextRunAt == nil {
		t.Fatalf("owner resume: %v %+v", err, got)
	}
	if _, err := e.svc.Resume(ctx, owner(), s.ID, experiments.RequestMeta{}); kind(err) != experiments.ErrConflict {
		t.Fatalf("resume of an active schedule: %v", err)
	}
	carol := auth.Principal{Issuer: "https://idp", Subject: "carol", Roles: []auth.Role{auth.RoleAdmin}}
	if got, err := e.svc.Delete(ctx, carol, s.ID, experiments.RequestMeta{}); err != nil || got.State != StateDeleted {
		t.Fatalf("admin delete: %v", err)
	}
	if l, _ := e.store.List(ctx, 10); len(l) != 0 {
		t.Fatal("deleted schedules are not listed")
	}
	e.advance(2 * time.Hour)
	e.svc.Tick(ctx)
	if len(e.conn.Submitted) != 0 {
		t.Fatal("deleted schedules never run")
	}
}

func TestResumeRechecksPolicyWithCurrentRoles(t *testing.T) {
	e := setup(t)
	s := create(t, e)
	ctx := context.Background()
	_, _ = e.svc.Pause(ctx, owner(), s.ID, experiments.RequestMeta{})
	if _, err := e.svc.Resume(ctx, owner(auth.RoleViewer), s.ID, experiments.RequestMeta{}); kind(err) != experiments.ErrForbidden {
		t.Fatalf("an owner who lost the experimenter role cannot resume: %v", err)
	}
	e.conn.Pol.Spec.AllowedNamespaces = []string{"other"}
	if _, err := e.svc.Resume(ctx, owner(), s.ID, experiments.RequestMeta{}); kind(err) != experiments.ErrPolicy {
		t.Fatalf("resume must re-check policy: %v", err)
	}
}

func TestConcurrentTicksFireOnce(t *testing.T) {
	e := setup(t)
	create(t, e)
	e.advance(time.Hour)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); e.svc.Tick(context.Background()) }()
	}
	wg.Wait()
	if len(e.conn.Submitted) != 1 {
		t.Fatalf("fired %d times", len(e.conn.Submitted))
	}
}
