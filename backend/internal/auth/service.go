// Package auth implements authentication: the OIDC authorization-code flow (BFF, D1),
// server-side sessions, and CSRF protection. It answers "who is this user?" only;
// "what may they do?" belongs to the authorization package.
package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/kubechaos/kubechaos/backend/internal/audit"
	"github.com/kubechaos/kubechaos/backend/internal/httpx"
)

const (
	// SessionCookie uses the __Host- prefix: Secure, Path=/, no Domain — the browser
	// refuses to let any other origin or subdomain set or shadow it.
	SessionCookie = "__Host-kc_session"
	// CSRFHeader must carry the session's CSRF token on every state-changing request.
	CSRFHeader = "X-KubeChaos-CSRF"
)

// Config configures the Service.
type Config struct {
	PublicURL   *url.URL // origin the browser uses, e.g. https://chaos.example.com
	SessionIdle time.Duration
	SessionMax  time.Duration
	LoginTTL    time.Duration

	// Sessions holding any of HighPrivilegeRoles get the shorter limits below, so a stale
	// or stolen high-privilege session is useful for much less time.
	HighPrivilegeRoles  []Role
	HighPrivSessionIdle time.Duration
	HighPrivSessionMax  time.Duration
}

// DefaultHighPrivilegeRoles are roles whose sessions get the shorter lifetime: admin
// (bindings, clusters, lock) and approver (signs off production experiments).
var DefaultHighPrivilegeRoles = []Role{RoleAdmin, RoleApprover}

// sessionLimits returns the idle and absolute lifetime for a session with roles.
func (c Config) sessionLimits(roles []Role) (idle, max time.Duration) {
	for _, r := range roles {
		if slices.Contains(c.HighPrivilegeRoles, r) {
			return c.HighPrivSessionIdle, c.HighPrivSessionMax
		}
	}
	return c.SessionIdle, c.SessionMax
}

// Service provides the login/logout handlers and the session/CSRF middleware.
type Service struct {
	cfg    Config
	origin string
	store  Store
	idp    IdP
	log    *slog.Logger
	now    func() time.Time
	// Auditor receives authentication events. Nil means no audit sink (tests only).
	Auditor Auditor
}

// Auditor records security events (the audit package's Writer satisfies it).
type Auditor interface {
	Append(ctx context.Context, e audit.Event) error
}

func (s *Service) audit(ctx context.Context, e audit.Event) error {
	if s.Auditor == nil {
		return nil
	}
	return s.Auditor.Append(ctx, e)
}

// clientIP is the TCP peer address. Proxy headers are not trusted until a trusted-proxy list
// is configured (they are client-controlled).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || net.ParseIP(host) == nil {
		return ""
	}
	return host
}

func rolesJSON(roles []Role) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"roles": roles})
	return b
}

// NewService builds a Service.
func NewService(cfg Config, store Store, idp IdP, logger *slog.Logger) *Service {
	// High-privilege limits may only ever be stricter than the ordinary ones.
	if cfg.HighPrivSessionIdle <= 0 || cfg.HighPrivSessionIdle > cfg.SessionIdle {
		cfg.HighPrivSessionIdle = cfg.SessionIdle
	}
	if cfg.HighPrivSessionMax <= 0 || cfg.HighPrivSessionMax > cfg.SessionMax {
		cfg.HighPrivSessionMax = cfg.SessionMax
	}
	return &Service{
		cfg:    cfg,
		origin: cfg.PublicURL.Scheme + "://" + cfg.PublicURL.Host,
		store:  store,
		idp:    idp,
		log:    logger,
		now:    time.Now,
	}
}

// Login starts the authorization-code flow with PKCE (S256), state and nonce.
func (s *Service) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	state, nonce, verifier := newToken(), newToken(), oauth2.GenerateVerifier()
	stepUp := r.URL.Query().Get("stepUp") == "1"

	authURL, err := s.idp.AuthCodeURL(ctx, state, nonce, verifier, stepUp)
	if err != nil {
		s.log.ErrorContext(ctx, "login: identity provider unavailable", reqID(r), slog.Any("error", err))
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "Service Unavailable", "identity provider unavailable")
		return
	}
	err = s.store.CreateLoginRequest(ctx, LoginRequest{
		StateHash:    hashToken(state),
		Nonce:        nonce,
		PKCEVerifier: verifier,
		ReturnTo:     SafeReturnTo(r.URL.Query().Get("returnTo")),
		StepUp:       stepUp,
		ExpiresAt:    s.now().Add(s.cfg.LoginTTL),
	})
	if err != nil {
		s.log.ErrorContext(ctx, "login: store login request", reqID(r), slog.Any("error", err))
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "Service Unavailable", "")
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// Callback completes the flow. Every failure redirects to "/?loginError=1" without detail;
// the reason is logged server-side.
func (s *Service) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fail := func(reason string, err error) {
		s.log.WarnContext(ctx, "login failed", reqID(r), slog.String("reason", reason), slog.Any("error", err))
		http.Redirect(w, r, "/?loginError=1", http.StatusFound)
	}

	q := r.URL.Query()
	state := q.Get("state")
	if len(state) != tokenLen {
		fail("missing or malformed state", nil)
		return
	}
	// Consume first: a state value is single-use even if the IdP reports an error.
	lr, err := s.store.ConsumeLoginRequest(ctx, hashToken(state))
	if err != nil {
		fail("unknown, expired or replayed state", err)
		return
	}
	if e := q.Get("error"); e != "" {
		fail("idp returned error", errors.New(truncate(e, 64)))
		return
	}
	code := q.Get("code")
	if code == "" {
		fail("missing code", nil)
		return
	}
	claims, err := s.idp.Exchange(ctx, code, lr.PKCEVerifier)
	if err != nil {
		fail("code exchange or id_token verification failed", err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(lr.Nonce)) != 1 {
		fail("nonce mismatch", nil)
		return
	}
	if claims.Subject == "" || claims.Issuer == "" {
		fail("id_token without sub/iss", nil)
		return
	}
	// Step-up: the IdP must prove a fresh interactive authentication (auth_time), not reuse SSO.
	if lr.StepUp && (claims.AuthTime == nil || s.now().Sub(*claims.AuthTime) > 2*time.Minute || claims.AuthTime.After(s.now().Add(time.Minute))) {
		fail("step-up requested but the identity provider did not re-authenticate the user", nil)
		return
	}

	display := claims.Name
	if display == "" {
		display = claims.PreferredUsername
	}
	identityID, err := s.store.UpsertIdentity(ctx, Identity{
		Issuer: claims.Issuer, Subject: claims.Subject,
		DisplayName: truncate(display, 255), Email: truncate(claims.Email, 320),
	})
	if err != nil {
		fail("store identity", err)
		return
	}

	// Session fixation defence: always mint a new session and drop any previous one.
	if c, err := r.Cookie(SessionCookie); err == nil && len(c.Value) == tokenLen {
		_ = s.store.DeleteSession(ctx, hashToken(c.Value))
	}
	token := newToken()
	roles := RolesFromGroups(claims.Groups)
	idle, maxAge := s.cfg.sessionLimits(roles)
	err = s.store.CreateSession(ctx, Session{
		TokenHash:   hashToken(token),
		IdentityID:  identityID,
		Roles:       roles,
		ACR:         truncate(claims.ACR, 64),
		AuthTime:    claims.AuthTime,
		CSRFToken:   newToken(),
		IdPSID:      truncate(claims.SID, 255),
		IdleTimeout: idle,
		ExpiresAt:   s.now().Add(maxAge),
	})
	if err != nil {
		fail("store session", err)
		return
	}
	action := "auth.login"
	if lr.StepUp {
		action = "auth.step_up"
	}
	// Fail closed: a login that cannot be audited does not happen.
	if err := s.audit(ctx, audit.Event{Action: action, ActorIssuer: claims.Issuer, ActorSubject: claims.Subject,
		ActorName: truncate(display, 255), AuthLevel: claims.ACR, SourceIP: clientIP(r), Result: "success",
		Parameters: rolesJSON(roles)}); err != nil {
		_ = s.store.DeleteSession(ctx, hashToken(token))
		fail("audit write failed", err)
		return
	}

	http.SetCookie(w, s.sessionCookie(token, int(maxAge.Seconds())))
	s.log.InfoContext(ctx, "login succeeded", reqID(r),
		slog.String("issuer", claims.Issuer), slog.String("subject", claims.Subject),
		slog.Any("roles", roles), slog.String("acr", claims.ACR), slog.Bool("step_up", lr.StepUp),
		slog.Duration("session_idle_timeout", idle), slog.Duration("session_max_age", maxAge))
	http.Redirect(w, r, lr.ReturnTo, http.StatusFound)
}

// Logout ends the local session and returns the IdP end-session URL for the SPA to visit.
// Must be mounted behind RequireSession and RequireCSRF.
func (s *Service) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if c, err := r.Cookie(SessionCookie); err == nil {
		if err := s.store.DeleteSession(ctx, hashToken(c.Value)); err != nil {
			s.log.ErrorContext(ctx, "logout: delete session", reqID(r), slog.Any("error", err))
			httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "Service Unavailable", "")
			return
		}
	}
	http.SetCookie(w, s.sessionCookie("", -1))
	logoutURL, err := s.idp.EndSessionURL(ctx, s.origin+"/")
	if err != nil {
		// Local session is gone either way; the IdP SSO session will simply expire.
		s.log.WarnContext(ctx, "logout: no idp end-session url", reqID(r), slog.Any("error", err))
		logoutURL = "/"
	}
	if p, ok := PrincipalFrom(ctx); ok {
		s.log.InfoContext(ctx, "logout", reqID(r), slog.String("subject", p.Subject))
		if err := s.audit(ctx, audit.Event{Action: "auth.logout", ActorIssuer: p.Issuer, ActorSubject: p.Subject,
			ActorName: p.DisplayName, SourceIP: clientIP(r), Result: "success"}); err != nil {
			s.log.ErrorContext(ctx, "audit write failed for logout", reqID(r), slog.Any("error", err))
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"logoutUrl": logoutURL})
}

// BackchannelLogout implements OIDC Back-Channel Logout 1.0. The IdP POSTs a signed logout
// token when a user's IdP session ends (user logout elsewhere, admin "sign out", session
// revocation); matching application sessions are deleted immediately. No cookie or CSRF
// token is involved: the request is authenticated solely by the token's signature.
func (s *Service) BackchannelLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")
	// Never let the IdP keep this connection for reuse. Keycloak does not retry back-channel
	// logouts, and a pooled keep-alive connection that went stale (API restart, redeploy,
	// proxy idle timeout) made it drop revocations silently (NoHttpResponseException).
	w.Header().Set("Connection", "close")
	reject := func(reason string, err error) {
		s.log.WarnContext(ctx, "back-channel logout rejected", reqID(r), slog.String("reason", reason), slog.Any("error", err))
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		reject("unexpected content type", nil)
		return
	}
	if err := r.ParseForm(); err != nil {
		reject("unparseable body", err)
		return
	}
	raw := r.PostForm.Get("logout_token")
	if raw == "" || len(raw) > 16<<10 {
		reject("missing or oversized logout_token", nil)
		return
	}
	lt, err := s.idp.VerifyLogoutToken(ctx, raw)
	if err != nil {
		reject("invalid logout token", err)
		return
	}
	// Revocation errs toward revoking more: a token naming a subject ends EVERY session of
	// that subject here, not only the one matching sid. IdPs do not reliably send one token
	// per IdP session (Keycloak's admin sign-out was observed sending a single token), and a
	// surviving session after an explicit IdP sign-out is the failure that matters. A
	// sid-only token revokes just the sessions created from that IdP session.
	var (
		n     int64
		scope string
	)
	switch {
	case lt.Subject != "":
		scope = "subject"
		n, err = s.store.DeleteSessionsBySubject(ctx, lt.Issuer, lt.Subject)
	default:
		scope = "sid"
		n, err = s.store.DeleteSessionsBySID(ctx, lt.Issuer, lt.SID)
	}
	if err != nil {
		s.log.ErrorContext(ctx, "back-channel logout: revoke sessions", reqID(r), slog.Any("error", err))
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", "")
		return
	}
	s.log.InfoContext(ctx, "back-channel logout", reqID(r),
		slog.String("issuer", lt.Issuer), slog.String("subject", lt.Subject),
		slog.String("scope", scope), slog.Int64("sessions_revoked", n))
	if err := s.audit(ctx, audit.Event{Action: "auth.session.revoked", ActorIssuer: lt.Issuer, ActorSubject: lt.Subject,
		ActorName: "identity-provider", Result: fmt.Sprintf("back-channel logout (%s): %d session(s) revoked", scope, n)}); err != nil {
		s.log.ErrorContext(ctx, "audit write failed for back-channel logout", reqID(r), slog.Any("error", err))
	}
	w.WriteHeader(http.StatusOK)
}

// RequireSession authenticates the request from the session cookie or rejects it with 401.
// Store failures yield 503, never a pass-through (fail closed).
func (s *Service) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(SessionCookie)
		if err != nil || len(c.Value) != tokenLen {
			httpx.WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "authentication required")
			return
		}
		th := hashToken(c.Value)
		sess, ident, err := s.store.LookupSession(r.Context(), th)
		if errors.Is(err, ErrNotFound) {
			httpx.WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "authentication required")
			return
		}
		if err != nil {
			s.log.ErrorContext(r.Context(), "session lookup failed", reqID(r), slog.Any("error", err))
			httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "Service Unavailable", "")
			return
		}
		if err := s.store.TouchSession(r.Context(), th); err != nil {
			s.log.WarnContext(r.Context(), "session touch failed", reqID(r), slog.Any("error", err))
		}
		p := Principal{
			IdentityID: sess.IdentityID, Issuer: ident.Issuer, Subject: ident.Subject,
			DisplayName: ident.DisplayName, Roles: sess.Roles, ACR: sess.ACR,
			AuthTime: sess.AuthTime, CSRFToken: sess.CSRFToken,
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

// RequireCSRF protects state-changing requests: the Origin header must equal the public
// origin and the CSRF header must equal the session's token. Safe methods pass through.
// Must run after RequireSession.
func (s *Service) RequireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		p, ok := PrincipalFrom(r.Context())
		if !ok {
			httpx.WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "authentication required")
			return
		}
		if r.Header.Get("Origin") != s.origin {
			httpx.WriteProblem(w, r, http.StatusForbidden, "Forbidden", "cross-origin request rejected")
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get(CSRFHeader)), []byte(p.CSRFToken)) != 1 {
			httpx.WriteProblem(w, r, http.StatusForbidden, "Forbidden", "missing or invalid CSRF token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Service) sessionCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   true, // browsers treat http://localhost as a secure context in development
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

func reqID(r *http.Request) slog.Attr {
	return slog.String("request_id", httpx.RequestIDFrom(r.Context()))
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
