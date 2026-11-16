package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/kubechaos/kubechaos/backend/internal/audit"
	"github.com/kubechaos/kubechaos/backend/internal/auth"
	"github.com/kubechaos/kubechaos/backend/internal/authorization"
	"github.com/kubechaos/kubechaos/backend/internal/events"
	"github.com/kubechaos/kubechaos/backend/internal/experiments"
	"github.com/kubechaos/kubechaos/backend/internal/httpx"
	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
)

// problemWithReasons is an RFC 9457 problem plus machine-readable fields.
type problemWithReasons struct {
	httpx.Problem
	Code    string   `json:"code,omitempty"`
	Reasons []string `json:"reasons,omitempty"`
}

func writeProblemReasons(w http.ResponseWriter, r *http.Request, status int, title, code string, reasons []string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problemWithReasons{
		Problem: httpx.Problem{Type: "about:blank", Title: title, Status: status, RequestID: httpx.RequestIDFrom(r.Context())},
		Code:    code, Reasons: reasons,
	})
}

// mapError turns service errors into precise HTTP responses (never leaking internals).
func (h *handlers) mapError(w http.ResponseWriter, r *http.Request, err error) {
	var d *experiments.DetailedError
	reasons := []string(nil)
	if errors.As(err, &d) {
		reasons = d.Reasons
	}
	switch {
	case errors.Is(err, experiments.ErrForbidden):
		writeProblemReasons(w, r, http.StatusForbidden, "Forbidden", "forbidden", reasons)
	case errors.Is(err, experiments.ErrStepUpRequired):
		writeProblemReasons(w, r, http.StatusForbidden, "Step-up authentication required", "step_up_required", reasons)
	case errors.Is(err, experiments.ErrInvalid):
		writeProblemReasons(w, r, http.StatusBadRequest, "Invalid experiment", "invalid", reasons)
	case errors.Is(err, experiments.ErrConfirmationRequired):
		writeProblemReasons(w, r, http.StatusBadRequest, "Confirmation required", "confirmation_required", reasons)
	case errors.Is(err, experiments.ErrPolicy):
		writeProblemReasons(w, r, http.StatusUnprocessableEntity, "Not permitted by cluster policy", "policy_violation", reasons)
	case errors.Is(err, experiments.ErrApprovalRequired):
		writeProblemReasons(w, r, http.StatusConflict, "Approval required", "approval_required", reasons)
	case errors.Is(err, experiments.ErrLocked):
		writeProblemReasons(w, r, http.StatusConflict, "Emergency stop engaged", "locked", reasons)
	case errors.Is(err, experiments.ErrConflict):
		writeProblemReasons(w, r, http.StatusConflict, "Conflict", "conflict", reasons)
	case errors.Is(err, experiments.ErrNotFound):
		httpx.WriteProblem(w, r, http.StatusNotFound, "Not Found", "")
	case errors.Is(err, experiments.ErrUnavailable):
		h.log.WarnContext(r.Context(), "cluster unavailable", slog.String("request_id", httpx.RequestIDFrom(r.Context())), slog.Any("error", err))
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "Service Unavailable", "cluster unavailable")
	default:
		h.log.ErrorContext(r.Context(), "request failed", slog.String("request_id", httpx.RequestIDFrom(r.Context())), slog.Any("error", err))
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", "")
	}
}

type handlers struct {
	exp    *experiments.Service
	broker *events.Broker
	audit  AuditReader
	log    *slog.Logger
}

// AuditReader lists and verifies the audit log.
type AuditReader interface {
	List(r *http.Request, limit int, before int64) ([]audit.Record, error)
	Verify(r *http.Request) (audit.VerifyResult, error)
}

func principal(r *http.Request) auth.Principal {
	p, _ := auth.PrincipalFrom(r.Context())
	return p
}

func sourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || net.ParseIP(host) == nil {
		return ""
	}
	return host
}

func (h *handlers) require(a authorization.Action) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !authorization.Allowed(principal(r), a) {
				httpx.WriteProblem(w, r, http.StatusForbidden, "Forbidden", "your role does not permit this action")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// decodeStrict decodes exactly one JSON object, rejecting unknown fields.
func decodeStrict(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after JSON object")
	}
	return nil
}

func (h *handlers) createExperiment(w http.ResponseWriter, r *http.Request) {
	var req experiments.CreateRequest
	if err := decodeStrict(r, &req); err != nil {
		writeProblemReasons(w, r, http.StatusBadRequest, "Invalid request body", "invalid", []string{truncate(err.Error(), 300)})
		return
	}
	exp, err := h.exp.Create(r.Context(), principal(r), req, experiments.RequestMeta{SourceIP: sourceIP(r)})
	if err != nil {
		h.mapError(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/experiments/"+exp.ID)
	httpx.WriteJSON(w, http.StatusCreated, exp)
}

func (h *handlers) listExperiments(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 200 {
		limit = 50
	}
	list, err := h.exp.Store.List(r.Context(), limit)
	if err != nil {
		h.mapError(w, r, err)
		return
	}
	if list == nil {
		list = []*experiments.Experiment{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": list})
}

func (h *handlers) getExperiment(w http.ResponseWriter, r *http.Request) {
	exp, err := h.exp.Store.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		h.mapError(w, r, err)
		return
	}
	evs, err := h.exp.Store.Events(r.Context(), exp.ID)
	if err != nil {
		h.mapError(w, r, err)
		return
	}
	if evs == nil {
		evs = []experiments.TimelineEvent{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"experiment": exp, "timeline": evs})
}

func (h *handlers) cancelExperiment(w http.ResponseWriter, r *http.Request) {
	exp, err := h.exp.Cancel(r.Context(), principal(r), chi.URLParam(r, "id"), experiments.RequestMeta{SourceIP: sourceIP(r)})
	if err != nil {
		h.mapError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, exp)
}

// streamExperiment is the SSE endpoint: the current state, then live updates. EventSource
// sends the session cookie, so the normal session check applies.
func (h *handlers) streamExperiment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	exp, err := h.exp.Store.Get(ctx, chi.URLParam(r, "id"))
	if err != nil {
		h.mapError(w, r, err)
		return
	}
	p := principal(r)
	ch, cancel, ok := h.broker.Subscribe(exp.ID, p.Issuer+"|"+p.Subject)
	if !ok {
		httpx.WriteProblem(w, r, http.StatusTooManyRequests, "Too Many Requests", "too many open live streams")
		return
	}
	defer cancel()

	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{}) // long-lived: the server's WriteTimeout does not apply
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	send := func(typ string, data any) error {
		b, err := json.Marshal(data)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", typ, b); err != nil {
			return err
		}
		return rc.Flush()
	}
	evs, _ := h.exp.Store.Events(ctx, exp.ID)
	if send("experiment", exp) != nil {
		return
	}
	for _, e := range evs {
		if send("timeline", e) != nil {
			return
		}
	}
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	maxLife := time.NewTimer(30 * time.Minute) // bounded; the browser reconnects
	defer maxLife.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-maxLife.C:
			return
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": keep-alive\n\n"); err != nil || rc.Flush() != nil {
				return
			}
		case m, open := <-ch:
			if !open {
				return
			}
			if m.Type == "resync" {
				if send("resync", map[string]string{"reason": "client too slow; reload"}) != nil {
					return
				}
				continue
			}
			if send(m.Type, m.Data) != nil {
				return
			}
		}
	}
}

func (h *handlers) listFaults(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": chaosv1.FaultCatalog})
}

func (h *handlers) listScenarios(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": scenarios})
}

func (h *handlers) clusterSummary(r *http.Request) (map[string]any, error) {
	conn := h.exp.Conn
	pol, err := conn.Policy(r.Context())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", experiments.ErrUnavailable, err)
	}
	locks, err := conn.Locks(r.Context())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", experiments.ErrUnavailable, err)
	}
	out := map[string]any{"id": conn.ClusterID(), "locked": len(locks) > 0, "policy": nil}
	if pol != nil {
		out["environment"] = pol.Spec.Environment
		out["policy"] = map[string]any{
			"allowedFaults": pol.Spec.AllowedFaults, "allowedNamespaces": pol.Spec.AllowedNamespaces,
			"limits": pol.Spec.Limits, "approvalRequired": pol.Spec.Approval.Required,
			"prometheus": pol.Spec.Observability != nil && pol.Spec.Observability.Prometheus != nil,
		}
	}
	return out, nil
}

func (h *handlers) listClusters(w http.ResponseWriter, r *http.Request) {
	c, err := h.clusterSummary(r)
	if err != nil {
		h.mapError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": []any{c}})
}

func (h *handlers) getCluster(w http.ResponseWriter, r *http.Request) {
	if chi.URLParam(r, "id") != h.exp.Conn.ClusterID() {
		httpx.WriteProblem(w, r, http.StatusNotFound, "Not Found", "")
		return
	}
	c, err := h.clusterSummary(r)
	if err != nil {
		h.mapError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, c)
}

func (h *handlers) getLock(w http.ResponseWriter, r *http.Request) {
	locks, err := h.exp.Conn.Locks(r.Context())
	if err != nil {
		h.mapError(w, r, fmt.Errorf("%w: %v", experiments.ErrUnavailable, err))
		return
	}
	type lock struct {
		Name      string    `json:"name"`
		Reason    string    `json:"reason"`
		EngagedBy string    `json:"engagedBy"`
		Since     time.Time `json:"since"`
	}
	out := []lock{}
	for _, l := range locks {
		out = append(out, lock{l.Name, l.Spec.Reason, l.Spec.EngagedBy, l.CreationTimestamp.Time})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"locked": len(out) > 0, "locks": out})
}

// engageLock: admins may stop the system from the UI (cheap to allow, D8). Unlocking is only
// possible with kubechaosctl on the control node.
func (h *handlers) engageLock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	if err := decodeStrict(r, &req); err != nil || len(req.Reason) < 3 || len(req.Reason) > 512 {
		writeProblemReasons(w, r, http.StatusBadRequest, "Invalid request body", "invalid", []string{"reason: 3-512 characters required"})
		return
	}
	p := principal(r)
	ev := audit.Event{Action: "system.lock.engage", ActorIssuer: p.Issuer, ActorSubject: p.Subject, ActorName: p.DisplayName,
		AuthLevel: p.ACR, SourceIP: sourceIP(r), ClusterID: h.exp.Conn.ClusterID(), Decision: "allow", Result: req.Reason}
	if err := h.exp.Audit.Append(r.Context(), ev); err != nil {
		h.mapError(w, r, err)
		return
	}
	name, err := h.exp.Conn.EngageLock(r.Context(), req.Reason, "web:"+p.Subject)
	if err != nil {
		h.mapError(w, r, fmt.Errorf("%w: %v", experiments.ErrUnavailable, err))
		return
	}
	h.log.WarnContext(r.Context(), "emergency stop engaged from the web UI", slog.String("lock", name), slog.String("subject", p.Subject))
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"locked": true, "lock": name})
}

func (h *handlers) listAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	recs, err := h.audit.List(r, limit, before)
	if err != nil {
		h.mapError(w, r, err)
		return
	}
	if recs == nil {
		recs = []audit.Record{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": recs})
}

func (h *handlers) verifyAudit(w http.ResponseWriter, r *http.Request) {
	res, err := h.audit.Verify(r)
	if err != nil {
		writeProblemReasons(w, r, http.StatusConflict, "Audit chain verification failed", "audit_chain_broken", []string{err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
