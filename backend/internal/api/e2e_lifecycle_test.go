//go:build e2e

package api

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kubechaos/kubechaos/backend/internal/audit"
	"github.com/kubechaos/kubechaos/backend/internal/auth"
	"github.com/kubechaos/kubechaos/backend/internal/clusters"
	"github.com/kubechaos/kubechaos/backend/internal/events"
	"github.com/kubechaos/kubechaos/backend/internal/experiments"
	"github.com/kubechaos/kubechaos/backend/internal/repository"
)

// TestE2E_ExperimentLifecycle runs a complete PodKill experiment through the real API, the real
// operator and the real cluster: login -> create -> kill -> recovery -> score -> timeline (DB
// and SSE) -> audit chain. Needs `make operator-deploy cp-kubeconfig` and Keycloak.
func TestE2E_ExperimentLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool, err := repository.Connect(ctx, mustEnv(t, "KUBECHAOS_DATABASE_URL"), repository.PoolOptions{ApplicationName: "e2e-lifecycle"})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	logger := discardLogger()
	writer := audit.NewWriter(pool)

	issuer := mustEnv(t, "KUBECHAOS_OIDC_ISSUER")
	public, _ := url.Parse(e2eBase)
	authSvc := auth.NewService(auth.Config{PublicURL: public, SessionIdle: 30 * time.Minute, SessionMax: 8 * time.Hour, LoginTTL: 10 * time.Minute},
		repository.NewSessionStore(pool),
		auth.NewOIDC(auth.OIDCConfig{Issuer: issuer, ClientID: mustEnv(t, "KUBECHAOS_OIDC_CLIENT_ID"),
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
	go expSvc.Run(ctx)

	ln, err := net.Listen("tcp", "0.0.0.0:8080")
	if err != nil {
		t.Fatalf("listen :8080 (is `make api` running?): %v", err)
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: NewRouter(Deps{Logger: logger, DB: pool, Auth: authSvc,
		Experiments: expSvc, Broker: broker, Audit: PGAuditReader{Pool: pool}, MaxBodyBytes: 1 << 20, Version: "e2e"})}}
	srv.Start()
	defer srv.Close()

	e := &e2e{t: t, password: mustEnv(t, "KEYCLOAK_DEV_USER_PASSWORD"), issuer: issuer}
	alice, _ := e.loginAs("alice", "/")
	_, me := e.me(alice)

	call := func(c *http.Cookie, csrf, method, path, body string) (int, []byte) {
		t.Helper()
		req, _ := http.NewRequest(method, e2eBase+path, strings.NewReader(body))
		req.AddCookie(c)
		req.Header.Set("Content-Type", "application/json")
		if method != "GET" {
			req.Header.Set("Origin", e2eBase)
			req.Header.Set(auth.CSRFHeader, csrf)
		}
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var buf strings.Builder
		_, _ = bufioCopy(&buf, resp)
		return resp.StatusCode, []byte(buf.String())
	}

	t.Run("complete PodKill lifecycle via the API", func(t *testing.T) {
		e.t = t
		body := `{"description":"e2e lifecycle","maxDuration":"3m","confirm":true,
		  "steps":[{"fault":{"type":"PodKill","target":{"namespace":"demo","selector":{"app":"web"}},"podKill":{"count":1,"gracePeriodSeconds":0}}},
		           {"wait":{"duration":"5s"}}],
		  "successCriteria":[{"metric":"available_replicas","operator":"ge","value":"3","weight":2},
		                     {"metric":"recovery_time","operator":"lt","value":"60s","weight":1}]}`
		code, raw := call(alice, me.CSRFToken, "POST", "/api/v1/experiments", body)
		if code != http.StatusCreated {
			t.Fatalf("create: %d %s", code, raw)
		}
		var exp experiments.Experiment
		_ = json.Unmarshal(raw, &exp)

		// Live stream: the first SSE event is the current state.
		sctx, scancel := context.WithTimeout(ctx, 5*time.Second)
		req, _ := http.NewRequestWithContext(sctx, "GET", e2eBase+"/api/v1/experiments/"+exp.ID+"/events", nil)
		req.AddCookie(alice)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			sc := bufio.NewScanner(resp.Body)
			if !sc.Scan() || sc.Text() != "event: experiment" {
				t.Errorf("SSE first event %q", sc.Text())
			}
			resp.Body.Close()
		} else {
			t.Errorf("SSE: %v", err)
		}
		scancel()

		var got struct {
			Experiment experiments.Experiment      `json:"experiment"`
			Timeline   []experiments.TimelineEvent `json:"timeline"`
		}
		deadline := time.Now().Add(120 * time.Second)
		for time.Now().Before(deadline) {
			_, raw := call(alice, "", "GET", "/api/v1/experiments/"+exp.ID, "")
			_ = json.Unmarshal(raw, &got)
			if p := got.Experiment.Phase; p == "Completed" || p == "Failed" || p == "Aborted" || p == "Rejected" {
				break
			}
			time.Sleep(time.Second)
		}
		if got.Experiment.Phase != "Completed" || got.Experiment.Result != "Passed" || got.Experiment.Score == nil || *got.Experiment.Score != 100 {
			t.Fatalf("phase=%s result=%s score=%v status=%+v", got.Experiment.Phase, got.Experiment.Result, got.Experiment.Score, got.Experiment.Status)
		}
		var types []string
		for _, ev := range got.Timeline {
			types = append(types, ev.Type)
		}
		for _, want := range []string{"Started", "TargetSelected", "PodTerminated", "Recovered", "Completed", "Criterion"} {
			if !slices.Contains(types, want) {
				t.Errorf("timeline missing %s: %v", want, types)
			}
		}
		t.Logf("timeline: %v", types)
	})

	t.Run("step-up login forces re-authentication and is audited", func(t *testing.T) {
		e.t = t
		u := e.startLogin("/")
		_ = u
		resp, err := noRedirect.Get(e2eBase + "/auth/login?stepUp=1")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if loc.Query().Get("prompt") != "login" || loc.Query().Get("max_age") != "0" {
			t.Fatalf("step-up must force interactive login: %s", loc)
		}
		cb := e.submitIdPLogin(loc, "alice", e.password)
		if _, c := e.callback(cb); c == nil {
			t.Fatal("step-up login failed")
		}
	})

	t.Run("auditor verifies the chain; others cannot read it", func(t *testing.T) {
		e.t = t
		dave, _ := e.loginAs("dave", "/")
		code, raw := call(dave, "", "GET", "/api/v1/audit/verify", "")
		if code != 200 || !strings.Contains(string(raw), `"events"`) {
			t.Fatalf("verify: %d %s", code, raw)
		}
		_, raw = call(dave, "", "GET", "/api/v1/audit?limit=200", "")
		for _, action := range []string{"auth.login", "auth.step_up", "experiment.create", "experiment.finished"} {
			if !strings.Contains(string(raw), `"action":"`+action+`"`) {
				t.Errorf("audit log missing %s", action)
			}
		}
		if code, _ := call(alice, "", "GET", "/api/v1/audit", ""); code != http.StatusForbidden {
			t.Fatalf("experimenter must not read audit: %d", code)
		}
		if res, err := audit.Verify(ctx, pool); err != nil {
			t.Fatalf("chain broken: %v", err)
		} else {
			t.Logf("audit chain OK: %d events", res.Events)
		}
	})
}

func bufioCopy(dst *strings.Builder, resp *http.Response) (int64, error) {
	r := bufio.NewReader(resp.Body)
	var n int64
	for {
		line, err := r.ReadString('\n')
		dst.WriteString(line)
		n += int64(len(line))
		if err != nil {
			return n, nil
		}
	}
}
