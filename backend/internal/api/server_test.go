package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kubechaos/kubechaos/backend/internal/audit"
	"github.com/kubechaos/kubechaos/backend/internal/auth"
	"github.com/kubechaos/kubechaos/backend/internal/auth/authtest"
	"github.com/kubechaos/kubechaos/backend/internal/clusters/clusterstest"
	"github.com/kubechaos/kubechaos/backend/internal/events"
	"github.com/kubechaos/kubechaos/backend/internal/experiments"
	"github.com/kubechaos/kubechaos/backend/internal/httpx"
	"github.com/kubechaos/kubechaos/backend/internal/schedules"
)

type fakeDB struct{ err error }

func (f fakeDB) Ping(context.Context) error { return f.err }

func discardLogger() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

func newAuth(store auth.Store, idp auth.IdP) *auth.Service {
	u, _ := url.Parse("http://localhost:4200")
	return auth.NewService(auth.Config{PublicURL: u, SessionIdle: time.Hour, SessionMax: time.Hour, LoginTTL: time.Minute},
		store, idp, discardLogger())
}

func newRouter(db Pinger, a *auth.Service) http.Handler {
	h, _, _ := newRouterWithCluster(db, a)
	return h
}

// newRouterWithCluster wires the experiment endpoints to an in-memory store and fake cluster.
func newRouterWithCluster(db Pinger, a *auth.Service) (http.Handler, *experiments.MemStore, *clusterstest.Fake) {
	store, conn := experiments.NewMemStore(), clusterstest.New()
	broker := events.NewBroker(2)
	svc := &experiments.Service{Store: store, Conn: conn, Audit: store, Broker: broker, Log: discardLogger()}
	sched := &schedules.Service{Store: schedules.NewMemStore(store), Exp: svc, Audit: store, Log: discardLogger()}
	return NewRouter(Deps{Logger: discardLogger(), DB: db, Auth: a, Experiments: svc, Schedules: sched, Broker: broker,
		Audit: fakeAudit{}, MaxBodyBytes: 64 << 10, Version: "test"}), store, conn
}

type fakeAudit struct{}

func (fakeAudit) List(*http.Request, int, int64) ([]audit.Record, error) {
	return []audit.Record{{Seq: 1, Event: audit.Event{Action: "auth.login"}}}, nil
}
func (fakeAudit) Verify(*http.Request) (audit.VerifyResult, error) {
	return audit.VerifyResult{Events: 1}, nil
}

func newTestServer(t *testing.T, db Pinger) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(newRouter(db, newAuth(authtest.NewMemStore(), &authtest.FakeIdP{})))
	t.Cleanup(srv.Close)
	return srv
}

// loggedIn returns a router plus a valid session cookie and CSRF token for an experimenter.
func loggedIn(t *testing.T) (http.Handler, *http.Cookie, string) {
	t.Helper()
	store := authtest.NewMemStore()
	idp := &authtest.FakeIdP{Claims: auth.Claims{Issuer: "https://idp.test", Subject: "alice", Name: "Alice",
		Groups: []string{"kubechaos-experimenter"}, ACR: "1"}}
	h := newRouter(fakeDB{}, newAuth(store, idp))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/auth/login", nil))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/auth/callback?code=c&state="+url.QueryEscape(idp.LastState), nil))
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.SessionCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatalf("login failed: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	var csrf string
	for _, s := range store.Sessions {
		csrf = s.CSRFToken
	}
	return h, cookie, csrf
}

func TestMeReturnsPrincipal(t *testing.T) {
	h, cookie, csrf := loggedIn(t)
	req := httptest.NewRequest("GET", "/api/v1/me", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	var me currentUser
	if err := json.NewDecoder(rec.Body).Decode(&me); err != nil {
		t.Fatal(err)
	}
	if me.Subject != "alice" || len(me.Roles) != 1 || me.Roles[0] != auth.RoleExperimenter || me.AuthLevel != "1" || me.CSRFToken != csrf {
		t.Fatalf("unexpected /me: %+v", me)
	}
}

func TestAuthenticatedUnsafeRequestsNeedCSRF(t *testing.T) {
	h, cookie, csrf := loggedIn(t)
	do := func(origin, token string) int {
		req := httptest.NewRequest("POST", "/api/v1/experiments", nil)
		req.AddCookie(cookie)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if token != "" {
			req.Header.Set(auth.CSRFHeader, token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := do("http://localhost:4200", ""); c != http.StatusForbidden {
		t.Errorf("no token: %d", c)
	}
	if c := do("https://evil.example", csrf); c != http.StatusForbidden {
		t.Errorf("foreign origin: %d", c)
	}
	// Valid CSRF reaches the handler, which rejects the empty body as invalid.
	if c := do("http://localhost:4200", csrf); c != http.StatusBadRequest {
		t.Errorf("valid csrf: %d", c)
	}
}

func get(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func decodeProblem(t *testing.T, resp *http.Response) httpx.Problem {
	t.Helper()
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content-type = %q, want application/problem+json", ct)
	}
	var p httpx.Problem
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHealthz(t *testing.T) {
	srv := newTestServer(t, fakeDB{err: errors.New("db down")}) // liveness ignores dependencies
	if resp := get(t, srv.URL+"/healthz"); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestReadyz(t *testing.T) {
	if resp := get(t, newTestServer(t, fakeDB{}).URL+"/readyz"); resp.StatusCode != http.StatusOK {
		t.Fatalf("ready: status = %d", resp.StatusCode)
	}
	resp := get(t, newTestServer(t, fakeDB{err: errors.New("dial tcp 10.0.0.5:5432: secret-host-detail")}).URL+"/readyz")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("not ready: status = %d", resp.StatusCode)
	}
	if p := decodeProblem(t, resp); strings.Contains(p.Detail, "secret-host-detail") {
		t.Fatal("internal error details leaked to client")
	}
}

// The API must be deny-by-default: every /api/v1 path, known or unknown, any method,
// returns 401 while no authentication mechanism exists.
func TestAPIv1DenyByDefault(t *testing.T) {
	srv := newTestServer(t, fakeDB{})
	cases := []struct{ method, path string }{
		{"GET", "/api/v1/me"},
		{"GET", "/api/v1/experiments"},
		{"POST", "/api/v1/experiments"},
		{"POST", "/api/v1/execute"},
		{"DELETE", "/api/v1/audit"},
		{"GET", "/api/v1/"},
	}
	for _, c := range cases {
		req, _ := http.NewRequest(c.method, srv.URL+c.path, strings.NewReader(`{"command":"kubectl delete pods --all"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer forged") // bearer tokens are not an accepted credential
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s: status = %d, want 401", c.method, c.path, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestSecurityHeadersAndRequestID(t *testing.T) {
	srv := newTestServer(t, fakeDB{})
	req, _ := http.NewRequest("GET", srv.URL+"/healthz", nil)
	req.Header.Set("X-Request-Id", "attacker-controlled-id")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	want := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
		"Referrer-Policy":         "no-referrer",
		"Cache-Control":           "no-store",
	}
	for k, v := range want {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	id := resp.Header.Get("X-Request-Id")
	if len(id) != 32 || strings.Contains(id, "attacker") {
		t.Errorf("request id must be server-generated 32 hex chars, got %q", id)
	}
}

func TestNotFoundAndMethodNotAllowedAreProblems(t *testing.T) {
	srv := newTestServer(t, fakeDB{})
	if p := decodeProblem(t, get(t, srv.URL+"/nope")); p.Status != http.StatusNotFound {
		t.Fatalf("status = %d", p.Status)
	}
	resp, err := http.Post(srv.URL+"/healthz", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if p := decodeProblem(t, resp); p.Status != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", p.Status)
	}
}

func TestPanicIsGeneric500(t *testing.T) {
	h := recoverer(slog.New(slog.NewJSONHandler(io.Discard, nil)))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom: secret internals")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "secret internals") {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMaxBody(t *testing.T) {
	var readErr error
	h := maxBody(10)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("x", 11))))
	var mbe *http.MaxBytesError
	if !errors.As(readErr, &mbe) {
		t.Fatalf("expected MaxBytesError, got %v", readErr)
	}
}
