//go:build e2e

package approvalapi

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kubechaos/kubechaos/backend/internal/api"
	"github.com/kubechaos/kubechaos/backend/internal/approval"
	"github.com/kubechaos/kubechaos/backend/internal/audit"
	"github.com/kubechaos/kubechaos/backend/internal/auth"
	"github.com/kubechaos/kubechaos/backend/internal/clusters"
	"github.com/kubechaos/kubechaos/backend/internal/config"
	"github.com/kubechaos/kubechaos/backend/internal/events"
	"github.com/kubechaos/kubechaos/backend/internal/experiments"
	"github.com/kubechaos/kubechaos/backend/internal/repository"
	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
)

const (
	approverBase = "http://localhost:8081"
	e2eBase      = "http://localhost:8080"
)

var (
	formAction = regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*>|<form[^>]*action="[^"]*login-actions/authenticate[^"]*"[^>]*>`)
	actionAttr = regexp.MustCompile(`action="([^"]+)"`)
	noRedirect = &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
)

func mustEnv(t *testing.T, k string) string {
	t.Helper()
	v := os.Getenv(k)
	if v == "" {
		t.Fatalf("%s not set", k)
	}
	return v
}

func discardLogger() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

// login performs a real Keycloak login against a BFF at base and returns its session cookie
// and CSRF token.
func login(t *testing.T, base, username, password string) (*http.Cookie, string) {
	t.Helper()
	resp, err := noRedirect.Get(base + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	authURL := resp.Header.Get("Location")
	host := strings.TrimPrefix(base, "http://")
	jar, _ := cookiejar.New(nil)
	kc := &http.Client{Jar: jar, Timeout: 20 * time.Second, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if req.URL.Host == host {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	resp, err = kc.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := actionAttr.FindSubmatch(formAction.Find(body))
	if m == nil {
		t.Fatalf("no Keycloak login form for %s at %s", username, base)
	}
	resp, err = kc.PostForm(html.UnescapeString(string(m[1])), url.Values{"username": {username}, "password": {password}, "credentialId": {""}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cb := resp.Header.Get("Location")
	if !strings.HasPrefix(cb, base+"/auth/callback") {
		t.Fatalf("login %s at %s: no callback redirect (status %d)", username, base, resp.StatusCode)
	}
	resp, err = noRedirect.Get(cb)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == auth.SessionCookie && c.MaxAge > 0 {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatalf("no session for %s at %s", username, base)
	}
	req, _ := http.NewRequest("GET", base+"/api/v1/me", nil)
	req.AddCookie(cookie)
	resp, err = noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var me struct {
		CSRFToken string `json:"csrfToken"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&me)
	return cookie, me.CSRFToken
}

func callAt(t *testing.T, base string, c *http.Cookie, csrf, method, path, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, base+path, strings.NewReader(body))
	req.AddCookie(c)
	req.Header.Set("Content-Type", "application/json")
	if method != "GET" {
		req.Header.Set("Origin", base)
		req.Header.Set(auth.CSRFHeader, csrf)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

type approvalClientAdapter struct{ c *approval.Client }

func (a approvalClientAdapter) Request(ctx context.Context, in experiments.ApprovalInput) (string, error) {
	return a.c.Request(ctx, approval.SubmitInput{ExperimentID: in.ExperimentID, ClusterID: in.ClusterID,
		Environment: in.Environment, Spec: in.Spec, RequesterName: in.RequesterName})
}

func (a approvalClientAdapter) Status(ctx context.Context, id string) (experiments.ApprovalStatus, error) {
	st, err := a.c.Status(ctx, id)
	return experiments.ApprovalStatus{ID: st.ID, State: st.State, Attestation: st.Attestation}, err
}

func serveOn(t *testing.T, addr string, h http.Handler) func() {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen %s (stop `make api` / `make approver` first): %v", addr, err)
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: h}}
	srv.Start()
	return srv.Close
}

// TestE2E_ApprovalFlow runs four-eyes approval end to end: the control plane (:8080) and the
// approval service (:8081) with real Keycloak, Postgres, operator and cluster. Needs
// `make approval-enable` (ChaosPolicy approval Always, trusting the dev key).
func TestE2E_ApprovalFlow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := discardLogger()
	password := mustEnv(t, "KEYCLOAK_DEV_USER_PASSWORD")
	issuer := mustEnv(t, "KUBECHAOS_OIDC_ISSUER")

	// --- approval service ---
	acfg, err := config.LoadApprover(func(k string) string {
		if k == "KUBECHAOS_APPROVER_PUBLIC_URL" {
			return approverBase
		}
		return os.Getenv(k)
	})
	if err != nil {
		t.Fatal(err)
	}
	apool, err := repository.Connect(ctx, acfg.DatabaseURL, repository.PoolOptions{ApplicationName: "e2e-approver"})
	if err != nil {
		t.Fatal(err)
	}
	defer apool.Close()
	if err := repository.VerifyServiceRole(ctx, apool, "app", "approval"); err != nil {
		t.Fatal(err)
	}
	apub, _ := url.Parse(approverBase)
	aauth := auth.NewService(auth.Config{PublicURL: apub, SessionIdle: 10 * time.Minute, SessionMax: time.Hour, LoginTTL: 10 * time.Minute},
		repository.NewSessionStore(apool), auth.NewOIDC(auth.OIDCConfig{Issuer: acfg.OIDCIssuer, ClientID: acfg.OIDCClientID,
			ClientSecret: acfg.OIDCClientSecret, RedirectURL: approverBase + "/auth/callback"}), logger)
	asvc := &approval.Service{Cfg: approval.Config{ClusterID: acfg.ClusterID, Environment: acfg.ClusterEnv, Routes: acfg.Routes,
		MinApprovals: acfg.MinApprovals, RequestTTL: time.Hour, AttestationTTL: time.Hour, StepUpMaxAge: 5 * time.Minute,
		KID: acfg.KID, Key: acfg.SigningKey}, Store: approval.PGStore{Pool: apool}, Log: logger}
	defer serveOn(t, "0.0.0.0:8081", NewRouter(Deps{Logger: logger, DB: apool, Auth: aauth,
		Service: asvc, ServiceToken: acfg.ServiceToken}))()

	// --- control plane ---
	pool, err := repository.Connect(ctx, mustEnv(t, "KUBECHAOS_DATABASE_URL"), repository.PoolOptions{ApplicationName: "e2e-approval"})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	writer := audit.NewWriter(pool)
	public, _ := url.Parse(e2eBase)
	authSvc := auth.NewService(auth.Config{PublicURL: public, SessionIdle: 30 * time.Minute, SessionMax: 8 * time.Hour, LoginTTL: 10 * time.Minute},
		repository.NewSessionStore(pool), auth.NewOIDC(auth.OIDCConfig{Issuer: issuer, ClientID: mustEnv(t, "KUBECHAOS_OIDC_CLIENT_ID"),
			ClientSecret: mustEnv(t, "KUBECHAOS_OIDC_CLIENT_SECRET"), RedirectURL: e2eBase + "/auth/callback"}), logger)
	authSvc.Auditor = writer
	conn, err := clusters.NewCRDConnector(mustEnv(t, "KUBECHAOS_KUBECONFIG"), "dev-kind-01", logger)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := conn.Policy(ctx)
	if err != nil || pol == nil || pol.Spec.Approval.Required != chaosv1.ApprovalAlways || len(pol.Spec.Approval.TrustedKeys) == 0 {
		t.Fatalf("ChaosPolicy must require approval with a trusted key: run `make approval-enable` (err=%v)", err)
	}
	store := repository.NewExperimentStore(pool, writer)
	broker := events.NewBroker(5)
	expSvc := &experiments.Service{Store: store, Conn: conn, Audit: writer, Broker: broker, Log: logger,
		Approvals: approvalClientAdapter{c: &approval.Client{BaseURL: approverBase, Token: acfg.ServiceToken}}}
	go expSvc.Run(ctx)
	go expSvc.RunApprovals(ctx, time.Second)
	defer serveOn(t, "0.0.0.0:8080", api.NewRouter(api.Deps{Logger: logger, DB: pool, Auth: authSvc, Experiments: expSvc, Broker: broker,
		Audit: api.PGAuditReader{Pool: pool}, MaxBodyBytes: 1 << 20, Version: "e2e"}))()

	alice, aliceCSRF := login(t, e2eBase, "alice", password)
	create := func(desc string) experiments.Experiment {
		t.Helper()
		code, raw := callAt(t, e2eBase, alice, aliceCSRF, "POST", "/api/v1/experiments", `{"description":"`+desc+`","maxDuration":"3m","confirm":true,
		  "steps":[{"fault":{"type":"PodKill","target":{"namespace":"demo","selector":{"app":"web"}},"podKill":{"count":1,"gracePeriodSeconds":0}}}],
		  "successCriteria":[{"metric":"available_replicas","operator":"ge","value":"3","weight":1}]}`)
		if code != http.StatusCreated {
			t.Fatalf("create: %d %s", code, raw)
		}
		var exp experiments.Experiment
		_ = json.Unmarshal([]byte(raw), &exp)
		if exp.State != experiments.StatePendingApproval || exp.ApprovalRequest == "" {
			t.Fatalf("expected PendingApproval, got %+v", exp)
		}
		return exp
	}
	waitFor := func(id string, done func(experiments.Experiment) bool) experiments.Experiment {
		t.Helper()
		var got struct {
			Experiment experiments.Experiment `json:"experiment"`
		}
		for deadline := time.Now().Add(120 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
			_, raw := callAt(t, e2eBase, alice, "", "GET", "/api/v1/experiments/"+id, "")
			_ = json.Unmarshal([]byte(raw), &got)
			if done(got.Experiment) {
				break
			}
		}
		return got.Experiment
	}

	t.Run("approved experiment runs with a verified attestation", func(t *testing.T) {
		exp := create("e2e approval: approve")
		time.Sleep(2 * time.Second) // several poller rounds
		if cur := waitFor(exp.ID, func(experiments.Experiment) bool { return true }); cur.Phase != "" || cur.State != experiments.StatePendingApproval {
			t.Fatalf("nothing may run before approval: %+v", cur)
		}

		// The requester is not an approver of demo: forbidden (and cannot see the request).
		aliceA, aliceACSRF := login(t, approverBase, "alice", password)
		if code, raw := callAt(t, approverBase, aliceA, aliceACSRF, "POST", "/api/v1/requests/"+exp.ApprovalRequest+"/approve", `{}`); code != http.StatusForbidden {
			t.Fatalf("non-member approve: %d %s", code, raw)
		}
		// bob is a head developer of demo and has just logged in (fresh auth_time).
		bob, bobCSRF := login(t, approverBase, "bob", password)
		code, raw := callAt(t, approverBase, bob, bobCSRF, "GET", "/api/v1/requests", "")
		if code != 200 || !strings.Contains(raw, exp.ApprovalRequest) || strings.Contains(raw, `"attestation"`) {
			t.Fatalf("bob's queue: %d %s", code, raw)
		}
		code, raw = callAt(t, approverBase, bob, bobCSRF, "POST", "/api/v1/requests/"+exp.ApprovalRequest+"/approve", `{"comment":"e2e"}`)
		if code != 200 || !strings.Contains(raw, `"state":"Approved"`) {
			t.Fatalf("approve: %d %s", code, raw)
		}

		final := waitFor(exp.ID, func(e experiments.Experiment) bool {
			return e.Phase == "Completed" || e.Phase == "Failed" || e.Phase == "Rejected"
		})
		if final.Phase != "Completed" || final.Result != "Passed" {
			t.Fatalf("approved experiment: phase=%s result=%s status=%+v", final.Phase, final.Result, final.Status)
		}
	})

	t.Run("rejected experiment never reaches the cluster", func(t *testing.T) {
		exp := create("e2e approval: reject")
		carol, carolCSRF := login(t, approverBase, "carol", password)
		if code, raw := callAt(t, approverBase, carol, carolCSRF, "POST", "/api/v1/requests/"+exp.ApprovalRequest+"/reject", `{"comment":"not today"}`); code != 200 {
			t.Fatalf("reject: %d %s", code, raw)
		}
		final := waitFor(exp.ID, func(e experiments.Experiment) bool { return e.State == experiments.StateApprovalRejected })
		if final.State != experiments.StateApprovalRejected {
			t.Fatalf("state %s", final.State)
		}
		if final.Phase != "" {
			t.Fatalf("rejected experiment reached the cluster: phase %s", final.Phase)
		}
	})

	t.Run("audit records the approval and the chain verifies", func(t *testing.T) {
		res, err := audit.Verify(ctx, pool)
		if err != nil {
			t.Fatalf("chain: %v", err)
		}
		var n int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit.events WHERE action IN ('experiment.approved', 'experiment.approval_rejected')`).Scan(&n)
		if n < 2 {
			t.Fatalf("approval audit events: %d", n)
		}
		t.Logf("audit chain OK: %d events", res.Events)
	})
}
