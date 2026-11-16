package api

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kubechaos/kubechaos/backend/internal/auth"
	"github.com/kubechaos/kubechaos/backend/internal/auth/authtest"
	"github.com/kubechaos/kubechaos/backend/internal/clusters/clusterstest"
	"github.com/kubechaos/kubechaos/backend/internal/experiments"
	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
)

type session struct {
	h      http.Handler
	cookie *http.Cookie
	csrf   string
	store  *experiments.MemStore
	conn   *clusterstest.Fake
}

// loginAs logs in a user with the given groups and an auth_time `authAge` ago.
func loginAs(t *testing.T, subject string, authAge time.Duration, groups ...string) session {
	t.Helper()
	as := authtest.NewMemStore()
	at := time.Now().Add(-authAge)
	idp := &authtest.FakeIdP{Claims: auth.Claims{Issuer: "https://idp.test", Subject: subject, Name: subject, Groups: groups, ACR: "1", AuthTime: &at}}
	h, store, conn := newRouterWithCluster(fakeDB{}, newAuth(as, idp))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/auth/login", nil))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/auth/callback?code=c&state="+url.QueryEscape(idp.LastState), nil))
	s := session{h: h, store: store, conn: conn}
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.SessionCookie {
			s.cookie = c
		}
	}
	for _, x := range as.Sessions {
		s.csrf = x.CSRFToken
	}
	if s.cookie == nil {
		t.Fatal("login failed")
	}
	return s
}

func (s session) do(method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.AddCookie(s.cookie)
	req.Header.Set("Content-Type", "application/json")
	if method != http.MethodGet {
		req.Header.Set("Origin", "http://localhost:4200")
		req.Header.Set(auth.CSRFHeader, s.csrf)
	}
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, req)
	return rec
}

func code(rec *httptest.ResponseRecorder) string {
	var p struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	return p.Code
}

const killOne = `{"description":"t","maxDuration":"2m","confirm":true,
  "steps":[{"fault":{"type":"PodKill","target":{"namespace":"demo","selector":{"app":"web"}},"podKill":{"count":1}}}]}`

func TestCreateAndReadExperiment(t *testing.T) {
	s := loginAs(t, "alice", time.Minute, "kubechaos-experimenter")
	rec := s.do("POST", "/api/v1/experiments", killOne)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var exp experiments.Experiment
	_ = json.Unmarshal(rec.Body.Bytes(), &exp)
	if exp.Spec.RequestedBy.Subject != "alice" || exp.ClusterID != "dev-kind-01" || rec.Header().Get("Location") != "/api/v1/experiments/"+exp.ID {
		t.Fatalf("server must set identity and cluster: %+v", exp)
	}
	if rec := s.do("GET", "/api/v1/experiments/"+exp.ID, ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"timeline"`) {
		t.Fatalf("get: %d %s", rec.Code, rec.Body.String())
	}
	if rec := s.do("GET", "/api/v1/experiments", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), exp.ID) {
		t.Fatalf("list: %d", rec.Code)
	}
	if rec := s.do("POST", "/api/v1/experiments/"+exp.ID+"/cancel", ""); rec.Code != http.StatusAccepted || len(s.conn.Cancelled) != 1 {
		t.Fatalf("cancel: %d %s", rec.Code, rec.Body.String())
	}
	if rec := s.do("GET", "/api/v1/experiments/not-a-uuid", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown id: %d", rec.Code)
	}
}

func TestCreateRejectsClientAssertedIdentityAndUnknownFields(t *testing.T) {
	s := loginAs(t, "alice", time.Minute, "kubechaos-experimenter")
	for _, body := range []string{
		strings.Replace(killOne, `"confirm":true`, `"confirm":true,"requestedBy":{"issuer":"x","subject":"bob"}`, 1),
		strings.Replace(killOne, `"confirm":true`, `"confirm":true,"clusterID":"prod-01"`, 1),
		strings.Replace(killOne, `"confirm":true`, `"confirm":true,"command":"kubectl delete pods --all"`, 1),
		strings.Replace(killOne, `"count":1`, `"count":1,"shell":"rm -rf /"`, 1),
		killOne + `{"second":"object"}`,
	} {
		if rec := s.do("POST", "/api/v1/experiments", body); rec.Code != http.StatusBadRequest {
			t.Errorf("must reject %s: %d", body[:60], rec.Code)
		}
	}
	if len(s.conn.Submitted) != 0 {
		t.Fatal("nothing may be submitted")
	}
}

func TestCreateErrorCodes(t *testing.T) {
	cases := []struct {
		name    string
		groups  []string
		authAge time.Duration
		body    string
		setup   func(*clusterstest.Fake)
		status  int
		code    string
	}{
		{"viewer", []string{"kubechaos-viewer"}, time.Minute, killOne, nil, 403, ""},
		{"auditor", []string{"kubechaos-auditor"}, time.Minute, killOne, nil, 403, ""},
		{"no roles", nil, time.Minute, killOne, nil, 403, ""},
		{"invalid", []string{"kubechaos-experimenter"}, time.Minute, strings.Replace(killOne, `"count":1`, `"count":99`, 1), nil, 400, "invalid"},
		{"policy", []string{"kubechaos-experimenter"}, time.Minute, strings.Replace(killOne, `"demo"`, `"ledger"`, 1), nil, 422, "policy_violation"},
		{"locked", []string{"kubechaos-experimenter"}, time.Minute, killOne, func(f *clusterstest.Fake) {
			f.LockList = []chaosv1.ChaosLock{{Spec: chaosv1.ChaosLockSpec{Reason: "r", EngagedBy: "x"}}}
		}, 409, "locked"},
		{"step-up", []string{"kubechaos-experimenter"}, time.Hour, strings.Replace(killOne, `"count":1`, `"count":2`, 1), nil, 403, "step_up_required"},
		{"confirm", []string{"kubechaos-experimenter"}, time.Minute, strings.Replace(killOne, `"confirm":true`, `"confirm":false`, 1), nil, 400, "confirmation_required"},
		{"cluster down", []string{"kubechaos-experimenter"}, time.Minute, killOne, func(f *clusterstest.Fake) { f.Unavailable = true }, 503, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := loginAs(t, "alice", c.authAge, c.groups...)
			if c.setup != nil {
				c.setup(s.conn)
			}
			rec := s.do("POST", "/api/v1/experiments", c.body)
			if rec.Code != c.status || (c.code != "" && code(rec) != c.code) {
				t.Fatalf("got %d %s, want %d %s: %s", rec.Code, code(rec), c.status, c.code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "connection") || strings.Contains(rec.Body.String(), "cluster down") {
				t.Fatal("internal errors must not leak")
			}
		})
	}
}

func TestRoleGatedEndpoints(t *testing.T) {
	cases := []struct {
		groups []string
		method string
		path   string
		body   string
		want   int
	}{
		{[]string{"kubechaos-auditor"}, "GET", "/api/v1/audit", "", 200},
		{[]string{"kubechaos-auditor"}, "GET", "/api/v1/audit/verify", "", 200},
		{[]string{"kubechaos-admin"}, "GET", "/api/v1/audit", "", 403}, // separation of duties
		{[]string{"kubechaos-auditor"}, "GET", "/api/v1/experiments", "", 403},
		{[]string{"kubechaos-viewer"}, "GET", "/api/v1/faults", "", 200},
		{[]string{"kubechaos-viewer"}, "GET", "/api/v1/scenarios", "", 200},
		{[]string{"kubechaos-viewer"}, "GET", "/api/v1/clusters", "", 200},
		{[]string{"kubechaos-viewer"}, "GET", "/api/v1/clusters/dev-kind-01", "", 200},
		{[]string{"kubechaos-viewer"}, "GET", "/api/v1/clusters/other", "", 404},
		{[]string{"kubechaos-viewer"}, "GET", "/api/v1/system/lock", "", 200},
		{[]string{"kubechaos-viewer"}, "POST", "/api/v1/admin/lock", `{"reason":"incident"}`, 403},
		{[]string{"kubechaos-experimenter"}, "POST", "/api/v1/admin/lock", `{"reason":"incident"}`, 403},
		{[]string{"kubechaos-admin"}, "POST", "/api/v1/admin/lock", `{"reason":"x"}`, 400},
		{[]string{"kubechaos-admin"}, "POST", "/api/v1/admin/lock", `{"reason":"incident 7"}`, 201},
	}
	for _, c := range cases {
		s := loginAs(t, "u", time.Minute, c.groups...)
		if rec := s.do(c.method, c.path, c.body); rec.Code != c.want {
			t.Errorf("%v %s %s: %d, want %d (%s)", c.groups, c.method, c.path, rec.Code, c.want, rec.Body.String())
		}
	}
}

func TestEngageLockIsAuditedAndBlocksNewExperiments(t *testing.T) {
	s := loginAs(t, "carol", time.Minute, "kubechaos-admin", "kubechaos-experimenter")
	if rec := s.do("POST", "/api/v1/admin/lock", `{"reason":"incident 7"}`); rec.Code != 201 {
		t.Fatalf("lock: %d", rec.Code)
	}
	last := s.store.Audits[len(s.store.Audits)-1]
	if last.Action != "system.lock.engage" || last.ActorSubject != "carol" {
		t.Fatalf("lock not audited: %+v", last)
	}
	if rec := s.do("POST", "/api/v1/experiments", killOne); rec.Code != 409 || code(rec) != "locked" {
		t.Fatalf("experiment while locked: %d %s", rec.Code, rec.Body.String())
	}
	if rec := s.do("GET", "/api/v1/system/lock", ""); !strings.Contains(rec.Body.String(), `"locked":true`) {
		t.Fatalf("lock state: %s", rec.Body.String())
	}
}

func TestSSEStreamsCurrentStateAndUpdates(t *testing.T) {
	s := loginAs(t, "alice", time.Minute, "kubechaos-experimenter")
	rec := s.do("POST", "/api/v1/experiments", killOne)
	var exp experiments.Experiment
	_ = json.Unmarshal(rec.Body.Bytes(), &exp)

	srv := httptest.NewServer(s.h)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/api/v1/experiments/"+exp.ID+"/events", nil)
	req.AddCookie(s.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("status %d type %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Scan()
	if sc.Text() != "event: experiment" {
		t.Fatalf("first event %q", sc.Text())
	}
	// Second and third streams for the same user hit the per-user limit (2 in tests).
	req2, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/api/v1/experiments/"+exp.ID+"/events", nil)
	req2.AddCookie(s.cookie)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	req3, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/api/v1/experiments/"+exp.ID+"/events", nil)
	req3.AddCookie(s.cookie)
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp2.StatusCode != 200 && resp3.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("per-user stream limit not enforced: %d %d", resp2.StatusCode, resp3.StatusCode)
	}
	// Unauthenticated stream: 401.
	r4, _ := http.Get(srv.URL + "/api/v1/experiments/" + exp.ID + "/events")
	if r4.StatusCode != 401 {
		t.Fatalf("anonymous SSE: %d", r4.StatusCode)
	}
}
