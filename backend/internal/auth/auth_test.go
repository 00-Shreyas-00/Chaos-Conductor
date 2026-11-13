package auth_test

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kubechaos/kubechaos/backend/internal/auth"
	"github.com/kubechaos/kubechaos/backend/internal/auth/authtest"
)

const origin = "https://chaos.example.com"

func newService(t *testing.T) (*auth.Service, *authtest.MemStore, *authtest.FakeIdP) {
	t.Helper()
	u, _ := url.Parse(origin)
	store := authtest.NewMemStore()
	idp := &authtest.FakeIdP{Claims: auth.Claims{
		Issuer: "https://idp.test/realms/kubechaos", Subject: "sub-alice", Name: "Alice",
		Groups: []string{"kubechaos-experimenter", "unrelated-group"}, ACR: "1",
	}}
	svc := auth.NewService(auth.Config{
		PublicURL: u, SessionIdle: 30 * time.Minute, SessionMax: 8 * time.Hour, LoginTTL: 10 * time.Minute,
	}, store, idp, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	return svc, store, idp
}

// login runs Login + Callback and returns the callback response.
func login(t *testing.T, svc *auth.Service, idp *authtest.FakeIdP, returnTo string) *http.Response {
	t.Helper()
	rec := httptest.NewRecorder()
	svc.Login(rec, httptest.NewRequest("GET", "/auth/login?returnTo="+url.QueryEscape(returnTo), nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("login status = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	svc.Callback(rec, httptest.NewRequest("GET", "/auth/callback?code=c&state="+url.QueryEscape(idp.LastState), nil))
	return rec.Result()
}

func sessionCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == auth.SessionCookie {
			return c
		}
	}
	return nil
}

func TestRolesFromGroups(t *testing.T) {
	got := auth.RolesFromGroups([]string{
		"kubechaos-admin", "/kubechaos-viewer", "kubechaos-admin", // dup + full path
		"kubechaos-superuser", "admin", "KUBECHAOS-ADMIN", "/team/kubechaos-auditor", "", // ignored
	})
	want := []auth.Role{auth.RoleAdmin, auth.RoleViewer}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if r := auth.RolesFromGroups(nil); len(r) != 0 {
		t.Fatalf("no groups must yield no roles, got %v", r)
	}
}

func TestSafeReturnTo(t *testing.T) {
	ok := []string{"/", "/experiments", "/experiments/42?tab=events", "/a#b"}
	for _, s := range ok {
		if got := auth.SafeReturnTo(s); got != s {
			t.Errorf("SafeReturnTo(%q) = %q, want unchanged", s, got)
		}
	}
	bad := []string{
		"", "https://evil.example", "//evil.example", "/\\evil.example", "\\\\evil", "evil",
		"javascript:alert(1)", "/\t/evil", "/x\r\nSet-Cookie: a=b", "/auth/login", "/api/v1/me",
		"/healthz", "/" + strings.Repeat("a", 600),
	}
	for _, s := range bad {
		if got := auth.SafeReturnTo(s); got != "/" {
			t.Errorf("SafeReturnTo(%q) = %q, want /", s, got)
		}
	}
}

func TestLoginRedirectsAndStoresHashedState(t *testing.T) {
	svc, store, idp := newService(t)
	rec := httptest.NewRecorder()
	svc.Login(rec, httptest.NewRequest("GET", "/auth/login?returnTo=https://evil.example", nil))
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "https://idp.test/") {
		t.Fatalf("code=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
	if len(store.Logins) != 1 {
		t.Fatalf("expected 1 stored login request, got %d", len(store.Logins))
	}
	for key, lr := range store.Logins {
		if strings.Contains(key, idp.LastState) || lr.ReturnTo != "/" || lr.Nonce != idp.LastNonce {
			t.Fatalf("state must be stored hashed, returnTo sanitised: key=%s lr=%+v", key, lr)
		}
	}
}

func TestLoginFailsClosedWhenIdPUnavailable(t *testing.T) {
	svc, store, idp := newService(t)
	idp.AuthURLErr = errors.New("discovery failed")
	rec := httptest.NewRecorder()
	svc.Login(rec, httptest.NewRequest("GET", "/auth/login", nil))
	if rec.Code != http.StatusServiceUnavailable || len(store.Logins) != 0 {
		t.Fatalf("code=%d stored=%d", rec.Code, len(store.Logins))
	}
}

func TestCallbackCreatesHardenedSession(t *testing.T) {
	svc, store, idp := newService(t)
	resp := login(t, svc, idp, "/experiments")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/experiments" {
		t.Fatalf("status=%d location=%q", resp.StatusCode, resp.Header.Get("Location"))
	}
	c := sessionCookie(resp)
	if c == nil {
		t.Fatal("no session cookie")
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" || c.MaxAge <= 0 {
		t.Fatalf("cookie not hardened: %+v", c)
	}
	if len(store.Sessions) != 1 {
		t.Fatalf("sessions = %d", len(store.Sessions))
	}
	for key, s := range store.Sessions {
		if strings.Contains(key, c.Value) {
			t.Fatal("session token must be stored hashed")
		}
		if !slices.Equal(s.Roles, []auth.Role{auth.RoleExperimenter}) || s.ACR != "1" || len(s.CSRFToken) != 43 {
			t.Fatalf("unexpected session %+v", s)
		}
	}
	if len(store.Logins) != 0 {
		t.Fatal("login request must be consumed")
	}
}

func TestCallbackRejects(t *testing.T) {
	cases := map[string]func(svc *auth.Service, idp *authtest.FakeIdP) string{
		"unknown state": func(svc *auth.Service, idp *authtest.FakeIdP) string {
			return "/auth/callback?code=c&state=" + strings.Repeat("A", 43)
		},
		"malformed state": func(svc *auth.Service, idp *authtest.FakeIdP) string { return "/auth/callback?code=c&state=x" },
		"idp error": func(svc *auth.Service, idp *authtest.FakeIdP) string {
			return startLogin(svc, idp) + "&error=access_denied"
		},
		"missing code": func(svc *auth.Service, idp *authtest.FakeIdP) string {
			return strings.Replace(startLogin(svc, idp), "code=c&", "", 1)
		},
		"exchange fails": func(svc *auth.Service, idp *authtest.FakeIdP) string {
			idp.ExchangeErr = errors.New("invalid_grant")
			return startLogin(svc, idp)
		},
		"nonce mismatch": func(svc *auth.Service, idp *authtest.FakeIdP) string {
			idp.Claims.Nonce = "attacker-nonce"
			return startLogin(svc, idp)
		},
		"missing subject": func(svc *auth.Service, idp *authtest.FakeIdP) string {
			idp.Claims.Subject = ""
			return startLogin(svc, idp)
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			svc, store, idp := newService(t)
			target := setup(svc, idp)
			rec := httptest.NewRecorder()
			svc.Callback(rec, httptest.NewRequest("GET", target, nil))
			resp := rec.Result()
			if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/?loginError=1" {
				t.Fatalf("status=%d location=%q", resp.StatusCode, resp.Header.Get("Location"))
			}
			if sessionCookie(resp) != nil || len(store.Sessions) != 0 {
				t.Fatal("no session may be created")
			}
			if len(store.Logins) != 0 {
				t.Fatal("state must be consumed even on failure")
			}
		})
	}
}

func startLogin(svc *auth.Service, idp *authtest.FakeIdP) string {
	rec := httptest.NewRecorder()
	svc.Login(rec, httptest.NewRequest("GET", "/auth/login", nil))
	return "/auth/callback?code=c&state=" + url.QueryEscape(idp.LastState)
}

func TestCallbackReplayRejected(t *testing.T) {
	svc, store, idp := newService(t)
	target := startLogin(svc, idp)
	for i, want := range []string{"/", "/?loginError=1"} {
		rec := httptest.NewRecorder()
		svc.Callback(rec, httptest.NewRequest("GET", target, nil))
		if got := rec.Header().Get("Location"); got != want {
			t.Fatalf("attempt %d: location=%q want %q", i+1, got, want)
		}
	}
	if len(store.Sessions) != 1 {
		t.Fatalf("replay must not create a second session; sessions=%d", len(store.Sessions))
	}
}

func TestCallbackReplacesExistingSession(t *testing.T) {
	svc, store, idp := newService(t)
	first := sessionCookie(login(t, svc, idp, "/"))
	target := startLogin(svc, idp)
	req := httptest.NewRequest("GET", target, nil)
	req.AddCookie(first)
	rec := httptest.NewRecorder()
	svc.Callback(rec, req)
	second := sessionCookie(rec.Result())
	if second == nil || second.Value == first.Value || len(store.Sessions) != 1 {
		t.Fatalf("session fixation: new token must replace old; sessions=%d", len(store.Sessions))
	}
}

func protected(svc *auth.Service) http.Handler {
	return svc.RequireSession(svc.RequireCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := auth.PrincipalFrom(r.Context())
		_, _ = io.WriteString(w, p.Subject)
	})))
}

func TestRequireSession(t *testing.T) {
	svc, store, idp := newService(t)
	cookie := sessionCookie(login(t, svc, idp, "/"))
	h := protected(svc)

	do := func(c *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/api/v1/me", nil)
		if c != nil {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := do(cookie); rec.Code != http.StatusOK || rec.Body.String() != "sub-alice" {
		t.Fatalf("valid session: code=%d body=%q", rec.Code, rec.Body.String())
	}
	for name, c := range map[string]*http.Cookie{
		"no cookie":     nil,
		"short cookie":  {Name: auth.SessionCookie, Value: "abc"},
		"unknown token": {Name: auth.SessionCookie, Value: strings.Repeat("A", 43)},
	} {
		if rec := do(c); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: code=%d want 401", name, rec.Code)
		}
	}
	store.Err = errors.New("db down")
	if rec := do(cookie); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("store failure must fail closed with 503, got %d", rec.Code)
	}
}

func TestRequireCSRF(t *testing.T) {
	svc, store, idp := newService(t)
	cookie := sessionCookie(login(t, svc, idp, "/"))
	var csrf string
	for _, s := range store.Sessions {
		csrf = s.CSRFToken
	}
	h := protected(svc)
	cases := []struct {
		name, method, origin, token string
		want                        int
	}{
		{"GET needs no token", "GET", "", "", http.StatusOK},
		{"POST ok", "POST", origin, csrf, http.StatusOK},
		{"DELETE ok", "DELETE", origin, csrf, http.StatusOK},
		{"POST no token", "POST", origin, "", http.StatusForbidden},
		{"POST wrong token", "POST", origin, strings.Repeat("A", 43), http.StatusForbidden},
		{"POST no origin", "POST", "", csrf, http.StatusForbidden},
		{"POST foreign origin", "POST", "https://evil.example", csrf, http.StatusForbidden},
		{"POST null origin", "POST", "null", csrf, http.StatusForbidden},
		{"PUT foreign origin", "PUT", "https://chaos.example.com.evil.example", csrf, http.StatusForbidden},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, "/api/v1/x", nil)
		req.AddCookie(cookie)
		if c.origin != "" {
			req.Header.Set("Origin", c.origin)
		}
		if c.token != "" {
			req.Header.Set(auth.CSRFHeader, c.token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s: code=%d want %d", c.name, rec.Code, c.want)
		}
	}
}

func TestLogout(t *testing.T) {
	svc, store, idp := newService(t)
	cookie := sessionCookie(login(t, svc, idp, "/"))
	var csrf string
	for _, s := range store.Sessions {
		csrf = s.CSRFToken
	}
	h := svc.RequireSession(svc.RequireCSRF(http.HandlerFunc(svc.Logout)))
	req := httptest.NewRequest("POST", "/auth/logout", nil)
	req.AddCookie(cookie)
	req.Header.Set("Origin", origin)
	req.Header.Set(auth.CSRFHeader, csrf)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "idp.test/logout") {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	if c := sessionCookie(rec.Result()); c == nil || c.MaxAge >= 0 {
		t.Fatal("logout must clear the cookie")
	}
	if len(store.Sessions) != 0 {
		t.Fatal("logout must delete the server-side session")
	}
}
