// Package api wires the public HTTP API. Handlers stay thin; security decisions live in
// dedicated packages (auth, authorization, policy) so they are explicit and testable.
package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/kubechaos/kubechaos/backend/internal/auth"
	"github.com/kubechaos/kubechaos/backend/internal/httpx"
)

// Pinger reports database reachability for readiness checks.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Deps are the router's collaborators.
type Deps struct {
	Logger       *slog.Logger
	DB           Pinger
	Auth         *auth.Service
	MaxBodyBytes int64
	Version      string
}

// NewRouter builds the HTTP handler. Every route added here must also be documented in
// api/openapi/openapi.yaml; TestRoutesMatchOpenAPI enforces this.
func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(httpx.RequestID, accessLog(d.Logger), recoverer(d.Logger), securityHeaders, maxBody(d.MaxBodyBytes))

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteProblem(w, r, http.StatusNotFound, "Not Found", "")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteProblem(w, r, http.StatusMethodNotAllowed, "Method Not Allowed", "")
	})

	// Liveness: process is up. Never touches dependencies.
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Readiness: dependencies reachable. Errors are logged, not returned.
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := d.DB.Ping(ctx); err != nil {
			d.Logger.WarnContext(r.Context(), "readiness check failed",
				slog.String("request_id", httpx.RequestIDFrom(r.Context())), slog.String("dependency", "postgres"), slog.Any("error", err))
			httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "Service Unavailable", "dependency unavailable")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ready", "version": d.Version})
	})

	// Authentication (OIDC authorization-code flow; the browser only ever holds a cookie).
	r.Get("/auth/login", d.Auth.Login)
	r.Get("/auth/callback", d.Auth.Callback)
	r.With(d.Auth.RequireSession, d.Auth.RequireCSRF).Post("/auth/logout", d.Auth.Logout)

	// Application API: deny by default. Every route requires a session; state-changing
	// methods additionally require a same-origin request carrying the CSRF token. Unknown
	// paths under /api/v1 return 401 so unauthenticated callers cannot enumerate routes.
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(d.Auth.RequireSession, d.Auth.RequireCSRF)
		r.Get("/me", getMe)
	})

	return r
}

type currentUser struct {
	Subject     string      `json:"subject"`
	Issuer      string      `json:"issuer"`
	DisplayName string      `json:"displayName,omitempty"`
	Roles       []auth.Role `json:"roles"`
	AuthLevel   string      `json:"authLevel"`
	CSRFToken   string      `json:"csrfToken"`
}

func getMe(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok { // unreachable behind RequireSession; fail closed anyway
		httpx.WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "authentication required")
		return
	}
	roles := p.Roles
	if roles == nil {
		roles = []auth.Role{}
	}
	httpx.WriteJSON(w, http.StatusOK, currentUser{
		Subject: p.Subject, Issuer: p.Issuer, DisplayName: p.DisplayName,
		Roles: roles, AuthLevel: p.ACR, CSRFToken: p.CSRFToken,
	})
}
