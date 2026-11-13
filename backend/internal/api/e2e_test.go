//go:build e2e

// End-to-end OIDC tests against the real dev Keycloak and PostgreSQL.
// Run with `make test-e2e` inside the devcontainer (after `make dev migrate`).
// The test server listens on 127.0.0.1:8080, so `make api` must not be running.
package api

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kubechaos/kubechaos/backend/internal/auth"
	"github.com/kubechaos/kubechaos/backend/internal/logging"
	"github.com/kubechaos/kubechaos/backend/internal/repository"
)

const e2eBase = "http://localhost:8080"

func mustEnv(t *testing.T, k string) string {
	t.Helper()
	v := os.Getenv(k)
	if v == "" {
		t.Fatalf("%s not set", k)
	}
	return v
}

var noRedirect = &http.Client{
	Timeout:       20 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

type e2e struct {
	t        *testing.T
	password string
	issuer   string
	seen     []string // real codes, states, cookies and CSRF tokens; must never appear in logs
}

// startLogin calls /auth/login and returns the IdP authorization URL.
func (e *e2e) startLogin(returnTo string) *url.URL {
	e.t.Helper()
	resp, err := noRedirect.Get(e2eBase + "/auth/login?returnTo=" + url.QueryEscape(returnTo))
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		e.t.Fatalf("/auth/login status %d", resp.StatusCode)
	}
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

var formAction = regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*>|<form[^>]*action="[^"]*login-actions/authenticate[^"]*"[^>]*>`)
var actionAttr = regexp.MustCompile(`action="([^"]+)"`)

// submitIdPLogin fills in Keycloak's login form. It returns our callback URL, or "" if
// Keycloak did not redirect (e.g. wrong password).
func (e *e2e) submitIdPLogin(authURL *url.URL, username, password string) string {
	e.t.Helper()
	jar, _ := cookiejar.New(nil)
	kc := &http.Client{Jar: jar, Timeout: 20 * time.Second,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if req.URL.Host == "localhost:8080" {
				return http.ErrUseLastResponse
			}
			return nil
		}}
	resp, err := kc.Get(authURL.String())
	if err != nil {
		e.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	form := formAction.Find(body)
	m := actionAttr.FindSubmatch(form)
	if m == nil {
		e.t.Fatalf("no login form in Keycloak page (status %d)", resp.StatusCode)
	}
	action := html.UnescapeString(string(m[1]))
	resp, err = kc.PostForm(action, url.Values{"username": {username}, "password": {password}, "credentialId": {""}})
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, e2eBase+"/auth/callback") {
		return ""
	}
	return loc
}

// callback calls our callback and returns the redirect target and the session cookie.
func (e *e2e) callback(cbURL string) (string, *http.Cookie) {
	e.t.Helper()
	if u, err := url.Parse(cbURL); err == nil {
		e.seen = append(e.seen, u.Query().Get("code"), u.Query().Get("state"))
	}
	resp, err := noRedirect.Get(cbURL)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == auth.SessionCookie && c.MaxAge > 0 {
			e.seen = append(e.seen, c.Value)
			return resp.Header.Get("Location"), c
		}
	}
	return resp.Header.Get("Location"), nil
}

func (e *e2e) loginAs(username, returnTo string) (*http.Cookie, string) {
	e.t.Helper()
	cb := e.submitIdPLogin(e.startLogin(returnTo), username, e.password)
	if cb == "" {
		e.t.Fatalf("Keycloak login for %s did not redirect to callback", username)
	}
	loc, c := e.callback(cb)
	if c == nil {
		e.t.Fatalf("no session cookie for %s (redirect %q)", username, loc)
	}
	return c, cb
}

func (e *e2e) me(c *http.Cookie) (int, currentUser) {
	e.t.Helper()
	req, _ := http.NewRequest("GET", e2eBase+"/api/v1/me", nil)
	if c != nil {
		req.AddCookie(c)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var u currentUser
	if resp.StatusCode == http.StatusOK {
		_ = json.NewDecoder(resp.Body).Decode(&u)
		e.seen = append(e.seen, u.CSRFToken)
	}
	return resp.StatusCode, u
}

func TestE2E_OIDC(t *testing.T) {
	ctx := context.Background()
	pool, err := repository.Connect(ctx, mustEnv(t, "KUBECHAOS_DATABASE_URL"), repository.PoolOptions{ApplicationName: "e2e"})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	issuer := mustEnv(t, "KUBECHAOS_OIDC_ISSUER")
	public, _ := url.Parse(e2eBase)
	clientSecret := mustEnv(t, "KUBECHAOS_OIDC_CLIENT_SECRET")
	// Real redacting logger into a buffer: scanned for leaked OIDC material at the end.
	var logBuf syncBuffer
	logger := logging.New(&logBuf, slog.LevelDebug)
	store := repository.NewSessionStore(pool)
	svc := auth.NewService(auth.Config{
		PublicURL: public, SessionIdle: 30 * time.Minute, SessionMax: 8 * time.Hour, LoginTTL: 10 * time.Minute,
		HighPrivilegeRoles: auth.DefaultHighPrivilegeRoles, HighPrivSessionIdle: 10 * time.Minute, HighPrivSessionMax: time.Hour,
	},
		store,
		auth.NewOIDC(auth.OIDCConfig{
			Issuer: issuer, ClientID: mustEnv(t, "KUBECHAOS_OIDC_CLIENT_ID"),
			ClientSecret: clientSecret, RedirectURL: e2eBase + "/auth/callback",
		}), logger)

	// All interfaces: Keycloak must reach /auth/backchannel-logout via kubechaos-api.internal.
	ln, err := net.Listen("tcp", "0.0.0.0:8080")
	if err != nil {
		t.Fatalf("listen :8080 (is `make api` running?): %v", err)
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: NewRouter(Deps{
		Logger: logger, DB: pool, Auth: svc, MaxBodyBytes: 1 << 20, Version: "e2e"})}}
	srv.Start()
	defer srv.Close()

	e := &e2e{t: t, password: mustEnv(t, "KEYCLOAK_DEV_USER_PASSWORD"), issuer: issuer}
	defer func() {
		// Nothing secret may appear in the logs: not the client secret, the user password,
		// any authorization code, state, session cookie or CSRF token we saw, nor any JWT.
		logs := logBuf.String()
		secrets := append([]string{clientSecret, e.password}, e.seen...)
		for _, s := range secrets {
			if len(s) >= 20 && strings.Contains(logs, s) { // short dummy values (e.g. forged "x") are not secrets
				t.Errorf("sensitive value leaked into logs (len %d)", len(s))
			}
		}
		if strings.Contains(logs, "eyJ") {
			t.Error("JWT-shaped data leaked into logs")
		}
		if !strings.Contains(logs, `"msg":"login succeeded"`) || !strings.Contains(logs, `"msg":"back-channel logout"`) {
			t.Error("expected auth events missing from logs (scan would be meaningless)")
		}
		t.Logf("log scan: %d lines, %d sensitive values checked", strings.Count(logs, "\n"), len(secrets))
		if t.Failed() {
			for _, line := range strings.Split(logs, "\n") {
				if strings.Contains(line, "back-channel") || strings.Contains(line, "login succeeded") {
					t.Log(line) // already redacted
				}
			}
		}
	}()

	t.Run("authorization request uses PKCE S256, state and nonce, and no secret", func(t *testing.T) {
		e.t = t
		u := e.startLogin("/")
		q := u.Query()
		if !strings.HasPrefix(u.String(), issuer+"/protocol/openid-connect/auth") ||
			q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" ||
			len(q.Get("code_challenge")) != 43 || len(q.Get("state")) != 43 || len(q.Get("nonce")) != 43 ||
			!strings.Contains(q.Get("scope"), "openid") || q.Get("redirect_uri") != e2eBase+"/auth/callback" ||
			strings.Contains(u.RawQuery, "secret") {
			t.Fatalf("unexpected authorization URL: %s", u)
		}
	})

	t.Run("experimenter logs in; session hashed; me; replay; logout", func(t *testing.T) {
		e.t = t
		cookie, cb := e.loginAs("alice", "/experiments?tab=mine")
		if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" {
			t.Fatalf("cookie not hardened: %+v", cookie)
		}

		code, me := e.me(cookie)
		if code != http.StatusOK || me.Subject == "" || me.Issuer != issuer || me.DisplayName != "Alice Experimenter" ||
			!slices.Equal(me.Roles, []auth.Role{auth.RoleExperimenter}) || me.AuthLevel != "1" || len(me.CSRFToken) != 43 {
			t.Fatalf("me: code=%d %+v", code, me)
		}

		var hashed, raw int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM app.sessions WHERE token_hash = sha256(convert_to($1, 'UTF8'))`, cookie.Value).Scan(&hashed)
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM app.sessions WHERE token_hash = convert_to($1, 'UTF8')`, cookie.Value).Scan(&raw)
		if hashed != 1 || raw != 0 {
			t.Fatalf("session must be stored as SHA-256 only (hashed=%d raw=%d)", hashed, raw)
		}

		if loc, c := e.callback(cb); loc != "/?loginError=1" || c != nil {
			t.Fatalf("replayed callback must fail: loc=%q cookie=%v", loc, c)
		}

		logout := func(origin, token string) *http.Response {
			req, _ := http.NewRequest("POST", e2eBase+"/auth/logout", nil)
			req.AddCookie(cookie)
			if origin != "" {
				req.Header.Set("Origin", origin)
			}
			if token != "" {
				req.Header.Set(auth.CSRFHeader, token)
			}
			resp, err := noRedirect.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			return resp
		}
		if r := logout(e2eBase, ""); r.StatusCode != http.StatusForbidden {
			t.Fatalf("logout without CSRF token: %d", r.StatusCode)
		}
		if r := logout("https://evil.example", me.CSRFToken); r.StatusCode != http.StatusForbidden {
			t.Fatalf("logout from foreign origin: %d", r.StatusCode)
		}
		r := logout(e2eBase, me.CSRFToken)
		var body struct {
			LogoutURL string `json:"logoutUrl"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		r.Body.Close()
		if r.StatusCode != http.StatusOK || !strings.HasPrefix(body.LogoutURL, issuer+"/protocol/openid-connect/logout?") ||
			!strings.Contains(body.LogoutURL, "client_id=kubechaos-api") {
			t.Fatalf("logout: %d %q", r.StatusCode, body.LogoutURL)
		}
		if code, _ := e.me(cookie); code != http.StatusUnauthorized {
			t.Fatalf("session must be dead after logout, got %d", code)
		}
	})

	t.Run("roles come only from allow-listed groups", func(t *testing.T) {
		e.t = t
		for user, want := range map[string][]auth.Role{
			"carol":   {auth.RoleAdmin},
			"dave":    {auth.RoleAuditor},
			"mallory": {},
		} {
			c, _ := e.loginAs(user, "/")
			if code, me := e.me(c); code != http.StatusOK || !slices.Equal(me.Roles, want) {
				t.Errorf("%s: code=%d roles=%v want %v", user, code, me.Roles, want)
			}
		}
	})

	t.Run("wrong password never reaches the callback", func(t *testing.T) {
		e.t = t
		if cb := e.submitIdPLogin(e.startLogin("/"), "eve", "definitely-wrong-password"); cb != "" {
			t.Fatalf("wrong password produced a callback: %s", cb)
		}
		e.loginAs("eve", "/") // successful login resets Keycloak's brute-force counter
	})

	t.Run("open redirect via returnTo is neutralised", func(t *testing.T) {
		e.t = t
		cb := e.submitIdPLogin(e.startLogin("https://evil.example/phish"), "eve", e.password)
		if loc, c := e.callback(cb); loc != "/" || c == nil {
			t.Fatalf("loc=%q cookie=%v", loc, c)
		}
	})

	t.Run("forged state and forged code are rejected", func(t *testing.T) {
		e.t = t
		if loc, c := e.callback(e2eBase + "/auth/callback?code=x&state=" + strings.Repeat("A", 43)); loc != "/?loginError=1" || c != nil {
			t.Fatalf("forged state: loc=%q", loc)
		}
		state := e.startLogin("/").Query().Get("state")
		if loc, c := e.callback(e2eBase + "/auth/callback?code=forged-code&state=" + state); loc != "/?loginError=1" || c != nil {
			t.Fatalf("forged code: loc=%q", loc)
		}
	})

	t.Run("admin sessions are short-lived", func(t *testing.T) {
		e.t = t
		c, _ := e.loginAs("carol", "/")
		var idle int
		var maxLeft time.Duration
		err := pool.QueryRow(ctx, `SELECT idle_timeout_seconds, (expires_at - now()) FROM app.sessions
			WHERE token_hash = sha256(convert_to($1, 'UTF8'))`, c.Value).Scan(&idle, &maxLeft)
		if err != nil || idle != 600 || maxLeft > time.Hour || c.MaxAge != 3600 {
			t.Fatalf("admin session: idle=%ds expiresIn=%v cookieMaxAge=%d err=%v", idle, maxLeft, c.MaxAge, err)
		}
	})

	t.Run("Keycloak admin sign-out revokes the session via back-channel logout", func(t *testing.T) {
		e.t = t
		c, _ := e.loginAs("alice", "/")
		if code, _ := e.me(c); code != http.StatusOK {
			t.Fatalf("precondition: %d", code)
		}
		keycloakAdminLogout(t, issuer, "alice")
		deadline := time.Now().Add(10 * time.Second)
		for {
			code, _ := e.me(c)
			if code == http.StatusUnauthorized {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("session still valid 10s after Keycloak sign-out (last status %d)", code)
			}
			time.Sleep(200 * time.Millisecond)
		}
	})

	t.Run("break-glass revocation by e-mail and by role", func(t *testing.T) {
		e.t = t
		dave, _ := e.loginAs("dave", "/")
		carol, _ := e.loginAs("carol", "/")
		alice, _ := e.loginAs("alice", "/")
		if n, err := store.RevokeSessions(ctx, repository.RevokeSelector{Email: "DAVE@kubechaos.test"}); err != nil || n < 1 {
			t.Fatalf("revoke by email: n=%d err=%v", n, err)
		}
		if n, err := store.RevokeSessions(ctx, repository.RevokeSelector{Role: "admin"}); err != nil || n < 1 {
			t.Fatalf("revoke by role: n=%d err=%v", n, err)
		}
		for name, want := range map[*http.Cookie]int{dave: 401, carol: 401, alice: 200} {
			if code, _ := e.me(name); code != want {
				t.Errorf("after revocation: status %d, want %d", code, want)
			}
		}
	})

	t.Run("forged back-channel logout tokens are rejected", func(t *testing.T) {
		e.t = t
		c, _ := e.loginAs("eve", "/")
		for _, tok := range []string{"not-a-jwt", forgeUnsignedLogoutToken(issuer)} {
			resp, err := http.PostForm(e2eBase+"/auth/backchannel-logout", url.Values{"logout_token": {tok}})
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("forged token: status %d, want 400", resp.StatusCode)
			}
		}
		if code, _ := e.me(c); code != http.StatusOK {
			t.Fatalf("forged logout must not revoke sessions: %d", code)
		}
	})
}

// keycloakAdminLogout signs a user out of all Keycloak sessions via the Admin REST API,
// which makes Keycloak send back-channel logout tokens to the API.
func keycloakAdminLogout(t *testing.T, issuer, username string) {
	t.Helper()
	base := strings.TrimSuffix(issuer, "/realms/kubechaos")
	resp, err := http.PostForm(base+"/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"}, "client_id": {"admin-cli"},
		"username": {mustEnv(t, "KEYCLOAK_ADMIN_USER")}, "password": {mustEnv(t, "KEYCLOAK_ADMIN_PASSWORD")},
	})
	if err != nil {
		t.Fatal(err)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tok)
	resp.Body.Close()
	if tok.AccessToken == "" {
		t.Fatalf("keycloak admin token: status %d", resp.StatusCode)
	}
	do := func(method, path string) *http.Response {
		req, _ := http.NewRequest(method, base+"/admin/realms/kubechaos"+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := do("GET", "/users?exact=true&username="+url.QueryEscape(username))
	var users []struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&users)
	r.Body.Close()
	if len(users) != 1 {
		t.Fatalf("keycloak user %q not found", username)
	}
	if r := do("POST", "/users/"+users[0].ID+"/logout"); r.StatusCode != http.StatusNoContent {
		t.Fatalf("keycloak admin logout: status %d", r.StatusCode)
	}
}

// forgeUnsignedLogoutToken builds an alg=none logout token with valid-looking claims.
func forgeUnsignedLogoutToken(issuer string) string {
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	return enc(map[string]string{"alg": "none", "typ": "logout+jwt"}) + "." + enc(map[string]any{
		"iss": issuer, "aud": "kubechaos-api", "iat": time.Now().Unix(), "jti": "forged",
		"sub": "anyone", "events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	}) + "."
}

// syncBuffer is a goroutine-safe bytes.Buffer for capturing server logs.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
func (b *syncBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.buf.String() }
