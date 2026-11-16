// Package approvalapi is the Approval Service's HTTP surface: an approver UI API (session +
// CSRF, OIDC via its own Keycloak client) and an internal API for the control plane
// (bearer service token). It is served on its own origin, separate from the main SPA.
package approvalapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/kubechaos/kubechaos/backend/internal/api"
	"github.com/kubechaos/kubechaos/backend/internal/approval"
	"github.com/kubechaos/kubechaos/backend/internal/auth"
	"github.com/kubechaos/kubechaos/backend/internal/httpx"
)

// Deps are the router's collaborators.
type Deps struct {
	Logger       *slog.Logger
	DB           interface{ Ping(context.Context) error }
	Auth         *auth.Service
	Service      *approval.Service
	ServiceToken string // shared with the control plane; >= 32 chars
}

// NewRouter builds the approval service handler.
func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(api.Middleware(d.Logger, 256<<10)...)
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteProblem(w, r, http.StatusNotFound, "Not Found", "")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteProblem(w, r, http.StatusMethodNotAllowed, "Method Not Allowed", "")
	})
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, 200, map[string]string{"status": "ok"})
	})
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := d.DB.Ping(ctx); err != nil {
			httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "Service Unavailable", "dependency unavailable")
			return
		}
		httpx.WriteJSON(w, 200, map[string]string{"status": "ready"})
	})

	h := &handlers{svc: d.Service, log: d.Logger}

	r.Get("/auth/login", d.Auth.Login)
	r.Get("/auth/callback", d.Auth.Callback)
	r.With(d.Auth.RequireSession, d.Auth.RequireCSRF).Post("/auth/logout", d.Auth.Logout)
	r.Post("/auth/backchannel-logout", d.Auth.BackchannelLogout)

	// Approver API (browser): session + CSRF.
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(d.Auth.RequireSession, d.Auth.RequireCSRF)
		r.Get("/me", h.me)
		r.Get("/requests", h.list)
		r.Get("/requests/{id}", h.get)
		r.Post("/requests/{id}/approve", h.decide(true))
		r.Post("/requests/{id}/reject", h.decide(false))
	})

	// Internal API (control plane only): bearer service token, never a browser.
	r.Route("/internal/v1", func(r chi.Router) {
		r.Use(serviceToken(d.ServiceToken))
		r.Post("/requests", h.submit)
		r.Get("/requests/{id}", h.status)
	})
	return r
}

func serviceToken(want string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got := r.Header.Get("Authorization")
			if len(want) < 32 || subtle.ConstantTimeCompare([]byte(got), []byte("Bearer "+want)) != 1 {
				httpx.WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

type handlers struct {
	svc *approval.Service
	log *slog.Logger
}

func principal(r *http.Request) auth.Principal {
	p, _ := auth.PrincipalFrom(r.Context())
	return p
}

func (h *handlers) mapError(w http.ResponseWriter, r *http.Request, err error) {
	write := func(status int, title, code string) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "about:blank", "title": title, "status": status, "code": code,
			"reasons": []string{err.Error()}, "requestId": httpx.RequestIDFrom(r.Context())})
	}
	switch {
	case errors.Is(err, approval.ErrNotFound):
		httpx.WriteProblem(w, r, http.StatusNotFound, "Not Found", "")
	case errors.Is(err, approval.ErrStepUpRequired):
		write(http.StatusForbidden, "Step-up authentication required", "step_up_required")
	case errors.Is(err, approval.ErrForbidden):
		write(http.StatusForbidden, "Forbidden", "forbidden")
	case errors.Is(err, approval.ErrConflict):
		write(http.StatusConflict, "Conflict", "conflict")
	case errors.Is(err, approval.ErrInvalid):
		write(http.StatusBadRequest, "Invalid request", "invalid")
	default:
		h.log.ErrorContext(r.Context(), "approval request failed", slog.Any("error", err))
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", "")
	}
}

func (h *handlers) me(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	groups := p.Groups
	if groups == nil {
		groups = []string{}
	}
	httpx.WriteJSON(w, 200, map[string]any{"subject": p.Subject, "issuer": p.Issuer, "displayName": p.DisplayName,
		"groups": groups, "authTime": p.AuthTime, "csrfToken": p.CSRFToken})
}

func (h *handlers) list(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	reqs, err := h.svc.Store.ListForGroups(r.Context(), p.Groups, 100)
	if err != nil {
		h.mapError(w, r, err)
		return
	}
	if reqs == nil {
		reqs = []*approval.Request{}
	}
	for _, x := range reqs {
		x.Attestation = "" // the signed token goes only to the control plane
	}
	httpx.WriteJSON(w, 200, map[string]any{"items": reqs})
}

func (h *handlers) get(w http.ResponseWriter, r *http.Request) {
	req, err := h.svc.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		h.mapError(w, r, err)
		return
	}
	if !approval.CanView(principal(r), req) {
		httpx.WriteProblem(w, r, http.StatusNotFound, "Not Found", "") // do not reveal existence
		return
	}
	req.Attestation = ""
	httpx.WriteJSON(w, 200, req)
}

func (h *handlers) decide(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Comment string `json:"comment"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			h.mapError(w, r, approval.ErrInvalid)
			return
		}
		req, err := h.svc.Decide(r.Context(), principal(r), chi.URLParam(r, "id"), approve, body.Comment)
		if err != nil {
			h.mapError(w, r, err)
			return
		}
		req.Attestation = ""
		httpx.WriteJSON(w, 200, req)
	}
}

func (h *handlers) submit(w http.ResponseWriter, r *http.Request) {
	var in approval.SubmitInput
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		h.mapError(w, r, approval.ErrInvalid)
		return
	}
	req, err := h.svc.Submit(r.Context(), in)
	if err != nil {
		h.mapError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]string{"id": req.ID, "state": req.State})
}

func (h *handlers) status(w http.ResponseWriter, r *http.Request) {
	req, err := h.svc.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		h.mapError(w, r, err)
		return
	}
	httpx.WriteJSON(w, 200, map[string]string{"id": req.ID, "state": req.State, "attestation": req.Attestation})
}
