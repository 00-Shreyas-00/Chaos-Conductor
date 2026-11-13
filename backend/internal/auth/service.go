// Package auth implements authentication: the OIDC authorization-code flow (BFF, D1),
// server-side sessions, and CSRF protection. It answers "who is this user?" only;
// "what may they do?" belongs to the authorization package.
package auth

import (
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"

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
}

// Service provides the login/logout handlers and the session/CSRF middleware.
type Service struct {
	cfg    Config
	origin string
	store  Store
	idp    IdP
	log    *slog.Logger
	now    func() time.Time
}

// NewService builds a Service.
func NewService(cfg Config, store Store, idp IdP, logger *slog.Logger) *Service {
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

	authURL, err := s.idp.AuthCodeURL(ctx, state, nonce, verifier)
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
	err = s.store.CreateSession(ctx, Session{
		TokenHash:  hashToken(token),
		IdentityID: identityID,
		Roles:      roles,
		ACR:        truncate(claims.ACR, 64),
		AuthTime:   claims.AuthTime,
		CSRFToken:  newToken(),
		ExpiresAt:  s.now().Add(s.cfg.SessionMax),
	})
	if err != nil {
		fail("store session", err)
		return
	}

	http.SetCookie(w, s.sessionCookie(token, int(s.cfg.SessionMax.Seconds())))
	s.log.InfoContext(ctx, "login succeeded", reqID(r),
		slog.String("issuer", claims.Issuer), slog.String("subject", claims.Subject),
		slog.Any("roles", roles), slog.String("acr", claims.ACR))
	// TODO(step 14): emit audit event auth.login.
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
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"logoutUrl": logoutURL})
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
		sess, ident, err := s.store.LookupSession(r.Context(), th, s.cfg.SessionIdle)
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
