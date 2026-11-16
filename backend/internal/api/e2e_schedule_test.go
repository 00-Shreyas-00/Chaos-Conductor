//go:build e2e

package api

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kubechaos/kubechaos/backend/internal/audit"
	"github.com/kubechaos/kubechaos/backend/internal/auth"
	"github.com/kubechaos/kubechaos/backend/internal/clusters"
	"github.com/kubechaos/kubechaos/backend/internal/events"
	"github.com/kubechaos/kubechaos/backend/internal/experiments"
	"github.com/kubechaos/kubechaos/backend/internal/repository"
	"github.com/kubechaos/kubechaos/backend/internal/schedules"
)

// TestE2E_ScheduledChaos creates a schedule through the real API (Keycloak login, CSRF), lets
// the scheduler fire it against the real operator and kind cluster, and checks the run, the
// experiment it started, and the audit trail. Needs the default (no approval) dev policy.
func TestE2E_ScheduledChaos(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool, err := repository.Connect(ctx, mustEnv(t, "KUBECHAOS_DATABASE_URL"), repository.PoolOptions{ApplicationName: "e2e-schedule"})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	logger := discardLogger()
	writer := audit.NewWriter(pool)
	issuer := mustEnv(t, "KUBECHAOS_OIDC_ISSUER")
	public, _ := url.Parse(e2eBase)
	authSvc := auth.NewService(auth.Config{PublicURL: public, SessionIdle: 30 * time.Minute, SessionMax: 8 * time.Hour, LoginTTL: 10 * time.Minute},
		repository.NewSessionStore(pool), auth.NewOIDC(auth.OIDCConfig{Issuer: issuer, ClientID: mustEnv(t, "KUBECHAOS_OIDC_CLIENT_ID"),
			ClientSecret: mustEnv(t, "KUBECHAOS_OIDC_CLIENT_SECRET"), RedirectURL: e2eBase + "/auth/callback"}), logger)
	authSvc.Auditor = writer
	conn, err := clusters.NewCRDConnector(mustEnv(t, "KUBECHAOS_KUBECONFIG"), "dev-kind-01", logger)
	if err != nil {
		t.Fatal(err)
	}
	store := repository.NewExperimentStore(pool, writer)
	if err := store.EnsureCluster(ctx, "dev-kind-01", "kind", "development"); err != nil {
		t.Fatal(err)
	}
	broker := events.NewBroker(5)
	expSvc := &experiments.Service{Store: store, Conn: conn, Audit: writer, Broker: broker, Log: logger}
	schedSvc := &schedules.Service{Store: repository.NewScheduleStore(pool, writer), Exp: expSvc, Audit: writer, Log: logger}
	go expSvc.Run(ctx)
	go schedSvc.Run(ctx, 2*time.Second)

	ln, err := net.Listen("tcp", "0.0.0.0:8080")
	if err != nil {
		t.Fatalf("listen :8080 (is `make api` running?): %v", err)
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: NewRouter(Deps{Logger: logger, DB: pool, Auth: authSvc,
		Experiments: expSvc, Schedules: schedSvc, Broker: broker, Audit: PGAuditReader{Pool: pool}, MaxBodyBytes: 1 << 20, Version: "e2e"})}}
	srv.Start()
	defer srv.Close()

	e := &e2e{t: t, password: mustEnv(t, "KEYCLOAK_DEV_USER_PASSWORD"), issuer: issuer}
	alice, _ := e.loginAs("alice", "/")
	_, me := e.me(alice)
	call := func(method, path, body string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, e2eBase+path, strings.NewReader(body))
		req.AddCookie(alice)
		req.Header.Set("Content-Type", "application/json")
		if method != "GET" {
			req.Header.Set("Origin", e2eBase)
			req.Header.Set(auth.CSRFHeader, me.CSRFToken)
		}
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}

	name := "e2e-" + time.Now().UTC().Format("150405")
	body := `{"name":"` + name + `","description":"e2e scheduled chaos","minInterval":"1m","meanInterval":"1m","maxRuns":1,"confirm":true,
	  "window":{"days":["Mon","Tue","Wed","Thu","Fri","Sat","Sun"],"from":"00:00","to":"24:00","timeZone":"UTC"},
	  "expiresAt":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `",
	  "template":{"maxDuration":"3m","steps":[{"fault":{"type":"PodKill","target":{"namespace":"demo","selector":{"app":"web"}},"podKill":{"count":1,"gracePeriodSeconds":0}}}],
	    "successCriteria":[{"metric":"available_replicas","operator":"ge","value":"3","weight":1}]}}`
	code, raw := call("POST", "/api/v1/schedules", body)
	if code != http.StatusCreated {
		t.Fatalf("create schedule: %d %s", code, raw)
	}
	var sched schedules.Schedule
	_ = json.Unmarshal([]byte(raw), &sched)
	if sched.NextRunAt == nil || time.Until(*sched.NextRunAt) > 70*time.Second {
		t.Fatalf("first run should be ~1 minute away: %v", sched.NextRunAt)
	}
	t.Logf("schedule %s created, first run at %s", sched.Name, sched.NextRunAt.Format(time.RFC3339))

	var detail struct {
		Schedule schedules.Schedule `json:"schedule"`
		Runs     []schedules.Run    `json:"runs"`
	}
	for deadline := time.Now().Add(150 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Second) {
		_, raw = call("GET", "/api/v1/schedules/"+sched.ID, "")
		_ = json.Unmarshal([]byte(raw), &detail)
		if len(detail.Runs) > 0 {
			break
		}
	}
	if len(detail.Runs) != 1 || detail.Runs[0].Outcome != schedules.OutcomeStarted || detail.Runs[0].ExperimentID == "" {
		t.Fatalf("schedule did not start a run: %s", raw)
	}
	if detail.Schedule.State != schedules.StateFinished || detail.Schedule.Runs != 1 {
		t.Fatalf("maxRuns=1 must finish the schedule: %+v", detail.Schedule)
	}

	var got struct {
		Experiment experiments.Experiment `json:"experiment"`
	}
	for deadline := time.Now().Add(120 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		_, raw = call("GET", "/api/v1/experiments/"+detail.Runs[0].ExperimentID, "")
		_ = json.Unmarshal([]byte(raw), &got)
		if p := got.Experiment.Phase; p == "Completed" || p == "Failed" || p == "Aborted" || p == "Rejected" {
			break
		}
	}
	x := got.Experiment
	if x.ScheduleID != sched.ID || x.RequesterSubj != me.Subject || x.Phase != "Completed" || x.Result != "Passed" {
		t.Fatalf("scheduled experiment: schedule=%s requester=%s phase=%s result=%s", x.ScheduleID, x.RequesterSubj, x.Phase, x.Result)
	}

	var actions []string
	rows, err := pool.Query(ctx, `SELECT action FROM audit.events WHERE action IN ('schedule.create', 'experiment.create.scheduled')
		AND seq > (SELECT coalesce(max(seq), 0) - 500 FROM audit.events)`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		actions = append(actions, a)
	}
	rows.Close()
	if !strings.Contains(strings.Join(actions, ","), "schedule.create") || !strings.Contains(strings.Join(actions, ","), "experiment.create.scheduled") {
		t.Fatalf("audit trail missing schedule events: %v", actions)
	}
	if res, err := audit.Verify(ctx, pool); err != nil {
		t.Fatalf("audit chain: %v", err)
	} else {
		t.Logf("audit chain OK: %d events", res.Events)
	}
}
