package api

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/kubechaos/kubechaos/backend/internal/experiments"
	"github.com/kubechaos/kubechaos/backend/internal/httpx"
	"github.com/kubechaos/kubechaos/backend/internal/schedules"
)

type scheduleHandlers struct {
	*handlers
	svc *schedules.Service
}

func (h *scheduleHandlers) create(w http.ResponseWriter, r *http.Request) {
	var req schedules.CreateRequest
	if err := decodeStrict(r, &req); err != nil {
		writeProblemReasons(w, r, http.StatusBadRequest, "Invalid request body", "invalid", []string{truncate(err.Error(), 300)})
		return
	}
	s, err := h.svc.Create(r.Context(), principal(r), req, experiments.RequestMeta{SourceIP: sourceIP(r)})
	if err != nil {
		h.mapError(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/schedules/"+s.ID)
	httpx.WriteJSON(w, http.StatusCreated, s)
}

func (h *scheduleHandlers) list(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 200 {
		limit = 50
	}
	items, err := h.svc.Store.List(r.Context(), limit)
	if err != nil {
		h.mapError(w, r, err)
		return
	}
	if items == nil {
		items = []*schedules.Schedule{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *scheduleHandlers) get(w http.ResponseWriter, r *http.Request) {
	s, err := h.svc.Store.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		h.mapError(w, r, err)
		return
	}
	runs, err := h.svc.Store.Runs(r.Context(), s.ID, 100)
	if err != nil {
		h.mapError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"schedule": s, "runs": runs})
}

func (h *scheduleHandlers) action(fn func(*schedules.Service) func(r *http.Request) (*schedules.Schedule, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := fn(h.svc)(r)
		if err != nil {
			h.mapError(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, s)
	}
}

func meta(r *http.Request) experiments.RequestMeta {
	return experiments.RequestMeta{SourceIP: sourceIP(r)}
}

func pause(s *schedules.Service) func(*http.Request) (*schedules.Schedule, error) {
	return func(r *http.Request) (*schedules.Schedule, error) {
		return s.Pause(r.Context(), principal(r), chi.URLParam(r, "id"), meta(r))
	}
}

func resume(s *schedules.Service) func(*http.Request) (*schedules.Schedule, error) {
	return func(r *http.Request) (*schedules.Schedule, error) {
		return s.Resume(r.Context(), principal(r), chi.URLParam(r, "id"), meta(r))
	}
}

func remove(s *schedules.Service) func(*http.Request) (*schedules.Schedule, error) {
	return func(r *http.Request) (*schedules.Schedule, error) {
		return s.Delete(r.Context(), principal(r), chi.URLParam(r, "id"), meta(r))
	}
}
