package approvalapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kubechaos/kubechaos/backend/internal/approval"
	"github.com/kubechaos/kubechaos/backend/internal/auth"
	"github.com/kubechaos/kubechaos/backend/internal/auth/authtest"
)

const (
	token  = "0123456789abcdef0123456789abcdef-service"
	group  = "/teams/demo/head-developers"
	origin = "http://localhost:4201"
)

type okDB struct{}

func (okDB) Ping(context.Context) error { return nil }

type env struct {
	h     http.Handler
	svc   *approval.Service
	store *authtest.MemStore
	idp   *authtest.FakeIdP
}

func newEnv(t *testing.T) *env {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	u, _ := url.Parse(origin)
	as, idp := authtest.NewMemStore(), &authtest.FakeIdP{}
	a := auth.NewService(auth.Config{PublicURL: u, SessionIdle: 10 * time.Minute, SessionMax: time.Hour, LoginTTL: time.Minute}, as, idp, log)
	svc := &approval.Service{Cfg: approval.Config{ClusterID: "dev-kind-01", Environment: "development", Routes: map[string]string{"demo": group},
		MinApprovals: 1, RequestTTL: time.Hour, AttestationTTL: time.Hour, StepUpMaxAge: 5 * time.Minute, KID: "k1", Key: priv},
		Store: approval.NewMemStore(), Log: log}
	return &env{h: NewRouter(Deps{Logger: log, DB: okDB{}, Auth: a, Service: svc, ServiceToken: token}), svc: svc, store: as, idp: idp}
}

type browser struct {
	e      *env
	cookie *http.Cookie
	csrf   string
}

func (e *env) login(t *testing.T, subject string, groups ...string) browser {
	at := time.Now().Add(-time.Minute)
	e.idp.Claims = auth.Claims{Issuer: "https://idp.test", Subject: subject, Name: subject, Groups: groups, AuthTime: &at}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, httptest.NewRequest("GET", "/auth/login", nil))
	rec = httptest.NewRecorder()
	e.h.ServeHTTP(rec, httptest.NewRequest("GET", "/auth/callback?code=c&state="+url.QueryEscape(e.idp.LastState), nil))
	b := browser{e: e}
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.SessionCookie {
			b.cookie = c
		}
	}
	if b.cookie == nil {
		t.Fatal("login failed")
	}
	req := httptest.NewRequest("GET", "/api/v1/me", nil)
	req.AddCookie(b.cookie)
	rec = httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	var me struct {
		CSRFToken string   `json:"csrfToken"`
		Groups    []string `json:"groups"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &me)
	b.csrf = me.CSRFToken
	return b
}

func (b browser) do(method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.AddCookie(b.cookie)
	if method != http.MethodGet {
		req.Header.Set("Origin", origin)
		req.Header.Set(auth.CSRFHeader, b.csrf)
	}
	rec := httptest.NewRecorder()
	b.e.h.ServeHTTP(rec, req)
	return rec
}

func internal(e *env, method, path, body, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

const submitBody = `{"experimentId":"11111111-2222-4333-8444-555555555555","clusterId":"dev-kind-01","environment":"development",
 "requesterName":"Alice","spec":{"clusterID":"dev-kind-01","requestedBy":{"issuer":"https://idp.test","subject":"alice"},
 "maxDuration":"2m","steps":[{"fault":{"type":"PodKill","target":{"namespace":"demo","selector":{"app":"web"}},"podKill":{"count":1}}}]}}`

func submit(t *testing.T, e *env) string {
	rec := internal(e, "POST", "/internal/v1/requests", submitBody, token)
	if rec.Code != http.StatusCreated {
		t.Fatalf("submit: %d %s", rec.Code, rec.Body)
	}
	var out struct{ ID string }
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out.ID
}

func TestInternalAPIRequiresServiceToken(t *testing.T) {
	e := newEnv(t)
	for _, bearer := range []string{"", "wrong-token-wrong-token-wrong-token", token + "x"} {
		if rec := internal(e, "POST", "/internal/v1/requests", submitBody, bearer); rec.Code != http.StatusUnauthorized {
			t.Fatalf("bearer %q: %d", bearer, rec.Code)
		}
	}
	// A browser session is not a service token.
	b := e.login(t, "bob", group)
	if rec := b.do("GET", "/internal/v1/requests/x", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("session reached the internal API: %d", rec.Code)
	}
}

func TestApproveFlowOverHTTP(t *testing.T) {
	e := newEnv(t)
	id := submit(t, e)

	// The requester and outsiders cannot decide; outsiders cannot even see it.
	alice := e.login(t, "alice", "/teams/other")
	if rec := alice.do("POST", "/api/v1/requests/"+id+"/approve", `{}`); rec.Code != http.StatusForbidden {
		t.Fatalf("outsider approve: %d", rec.Code)
	}
	eve := e.login(t, "eve")
	if rec := eve.do("GET", "/api/v1/requests/"+id, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("outsider read: %d", rec.Code)
	}

	bob := e.login(t, "bob", group)
	rec := bob.do("GET", "/api/v1/requests", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), id) {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	// CSRF is enforced on decisions.
	req := httptest.NewRequest("POST", "/api/v1/requests/"+id+"/approve", strings.NewReader(`{}`))
	req.AddCookie(bob.cookie)
	req.Header.Set("Origin", origin)
	r := httptest.NewRecorder()
	e.h.ServeHTTP(r, req)
	if r.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF accepted: %d", r.Code)
	}

	rec = bob.do("POST", "/api/v1/requests/"+id+"/approve", `{"comment":"ok"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"state":"Approved"`) || strings.Contains(rec.Body.String(), "attestation") {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	// Only the control plane receives the attestation.
	rec = internal(e, "GET", "/internal/v1/requests/"+id, "", token)
	var st approval.Status
	_ = json.Unmarshal(rec.Body.Bytes(), &st)
	if st.State != approval.StateApproved || strings.Count(st.Attestation, ".") != 2 {
		t.Fatalf("status %+v", st)
	}
	if rec := bob.do("POST", "/api/v1/requests/"+id+"/reject", `{}`); rec.Code != http.StatusConflict {
		t.Fatalf("second decision: %d", rec.Code)
	}
}

func TestRejectsUnknownFieldsAndUnauthenticated(t *testing.T) {
	e := newEnv(t)
	if rec := internal(e, "POST", "/internal/v1/requests", `{"specSha256":"forged"}`, token); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", rec.Code)
	}
	if rec := internal(e, "GET", "/api/v1/requests", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", rec.Code)
	}
}

func TestClientAgainstRouter(t *testing.T) {
	e := newEnv(t)
	srv := httptest.NewServer(e.h)
	defer srv.Close()
	var in approval.SubmitInput
	_ = json.Unmarshal([]byte(submitBody), &in)
	c := &approval.Client{BaseURL: srv.URL, Token: token}
	id, err := c.Request(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.Status(context.Background(), id)
	if err != nil || st.State != approval.StatePending || st.Attestation != "" {
		t.Fatalf("%v %+v", err, st)
	}
	bad := &approval.Client{BaseURL: srv.URL, Token: "nope"}
	if _, err := bad.Status(context.Background(), id); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401, got %v", err)
	}
}
