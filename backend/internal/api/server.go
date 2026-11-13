// Package api wires the public HTTP API. Handlers stay thin; security decisions live in
// dedicated packages (auth, authorization, policy) so they are explicit and testable.
package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// Pinger reports database reachability for readiness checks.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Deps are the router's collaborators.
type Deps struct {
	Logger       *slog.Logger
	DB           Pinger
	MaxBodyBytes int64
	Version      string
}

// NewRouter builds the HTTP handler. Every route added here must also be documented in
// api/openapi/openapi.yaml; TestRoutesMatchOpenAPI enforces this.
func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(requestID, accessLog(d.Logger), recoverer(d.Logger), securityHeaders, maxBody(d.MaxBodyBytes))

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		writeProblem(w, r, http.StatusNotFound, "Not Found", "")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeProblem(w, r, http.StatusMethodNotAllowed, "Method Not Allowed", "")
	})

	// Liveness: process is up. Never touches dependencies.
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Readiness: dependencies reachable. Errors are logged, not returned.
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := d.DB.Ping(ctx); err != nil {
			d.Logger.WarnContext(r.Context(), "readiness check failed",
				slog.String("request_id", requestIDFrom(r.Context())), slog.String("dependency", "postgres"), slog.Any("error", err))
			writeProblem(w, r, http.StatusServiceUnavailable, "Service Unavailable", "dependency unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready", "version": d.Version})
	})

	// Application API: everything below is authenticated (deny by default). Unknown paths
	// under /api/v1 also return 401 so unauthenticated callers cannot enumerate routes.
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(requireAuthenticated)
		r.Get("/me", func(w http.ResponseWriter, r *http.Request) {
			// Unreachable until authentication exists (step 9).
			writeProblem(w, r, http.StatusNotImplemented, "Not Implemented", "")
		})
	})

	return r
}
