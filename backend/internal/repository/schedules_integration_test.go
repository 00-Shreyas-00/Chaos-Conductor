//go:build integration

package repository

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kubechaos/kubechaos/backend/internal/audit"
	"github.com/kubechaos/kubechaos/backend/internal/auth"
	"github.com/kubechaos/kubechaos/backend/internal/experiments"
	"github.com/kubechaos/kubechaos/backend/internal/schedules"
)

func newSchedule(t *testing.T, ctx context.Context, store *ScheduleStore, next time.Time) *schedules.Schedule {
	t.Helper()
	app := store.pool
	exps := NewExperimentStore(app, store.audit)
	if err := exps.EnsureCluster(ctx, "it-cluster", "Integration", "development"); err != nil {
		t.Fatal(err)
	}
	var identity string
	if err := app.QueryRow(ctx, `INSERT INTO app.identities (issuer, subject) VALUES ('https://idp.it', $1) RETURNING id::text`, randHashHex(t)).Scan(&identity); err != nil {
		t.Fatal(err)
	}
	sc := &schedules.Schedule{ID: "22222222-3333-4444-8555-" + randHashHex(t)[:12], Name: "it-" + randHashHex(t)[:8], ClusterID: "it-cluster",
		OwnerID: identity, OwnerRoles: []auth.Role{auth.RoleExperimenter}, Template: schedules.Template{MaxDuration: "1m"}, Risk: "Low",
		MinIntervalSeconds: 60, MeanIntervalSeconds: 120, Window: schedules.Window{Days: []string{"Mon"}, From: "09:00", To: "17:00", TimeZone: "UTC"},
		ExpiresAt: time.Now().Add(time.Hour), State: schedules.StateActive, NextRunAt: &next}
	if err := store.CreateWithAudit(ctx, sc, audit.Event{Action: "schedule.create", Decision: "allow"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	return sc
}

func TestScheduleStoreRoundTripAndClaim(t *testing.T) {
	ctx := context.Background()
	app := pool(t, "KUBECHAOS_TEST_APP_URL")
	store := NewScheduleStore(app, audit.NewWriter(app))
	due := time.Now().Add(-time.Minute).Truncate(time.Microsecond)
	sc := newSchedule(t, ctx, store, due)

	got, err := store.Get(ctx, sc.ID)
	if err != nil || got.OwnerIssuer != "https://idp.it" || got.Window.TimeZone != "UTC" || len(got.OwnerRoles) != 1 || !got.NextRunAt.Equal(due) {
		t.Fatalf("get: %v %+v", err, got)
	}
	list, err := store.Due(ctx, time.Now(), 200)
	found := false
	for _, x := range list {
		found = found || x.ID == sc.ID
	}
	if err != nil || !found {
		t.Fatalf("due: %v", err)
	}

	// Many concurrent claims of the same run: exactly one wins.
	next := time.Now().Add(time.Hour)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, err := store.Claim(ctx, sc.ID, due, &next); err == nil && ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("claims won: %d", wins.Load())
	}

	// Record a run; then a pause made concurrently is not overwritten by the scheduler.
	sc.Runs, sc.State, sc.NextRunAt = 1, schedules.StateActive, &next
	if err := store.RecordRun(ctx, sc, schedules.Run{OccurredAt: time.Now(), Outcome: schedules.OutcomeSkipped, Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.SetState(ctx, sc.ID, []string{schedules.StateActive}, schedules.StatePaused, "by test", nil, nil); err != nil || !ok {
		t.Fatalf("pause: %v %v", ok, err)
	}
	if err := store.RecordRun(ctx, sc, schedules.Run{OccurredAt: time.Now(), Outcome: schedules.OutcomeSkipped}); err != nil {
		t.Fatal(err)
	}
	got, _ = store.Get(ctx, sc.ID)
	if got.State != schedules.StatePaused || got.NextRunAt != nil || got.Runs != 1 {
		t.Fatalf("pause must win: %+v", got)
	}
	runs, err := store.Runs(ctx, sc.ID, 10)
	if err != nil || len(runs) != 2 {
		t.Fatalf("runs: %v %d", err, len(runs))
	}
	if ok, _ := store.SetState(ctx, sc.ID, []string{schedules.StateActive}, schedules.StateDeleted, "", nil, nil); ok {
		t.Fatal("state transition must respect 'from'")
	}
	// Resume stores the new role snapshot and resets denials.
	if ok, err := store.SetState(ctx, sc.ID, []string{schedules.StatePaused}, schedules.StateActive, "", &next,
		[]auth.Role{auth.RoleExperimenter, auth.RoleApprover}); err != nil || !ok {
		t.Fatalf("resume: %v", err)
	}
	if got, _ = store.Get(ctx, sc.ID); len(got.OwnerRoles) != 2 || got.State != schedules.StateActive {
		t.Fatalf("resume: %+v", got)
	}
	for _, sql := range []string{`DELETE FROM app.schedules`, `DELETE FROM app.schedule_runs`, `UPDATE app.schedule_runs SET reason = 'x'`} {
		if _, err := app.Exec(ctx, sql); err == nil {
			t.Errorf("app must be denied: %s", sql)
		}
	}
	if _, err := store.Get(ctx, "nope"); err != experiments.ErrNotFound {
		t.Fatalf("bad id: %v", err)
	}
}
