package api

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kubechaos/kubechaos/backend/internal/audit"
)

// PGAuditReader reads the audit log with the app role (SELECT only on audit.events).
type PGAuditReader struct{ Pool *pgxpool.Pool }

func (a PGAuditReader) List(r *http.Request, limit int, before int64) ([]audit.Record, error) {
	return audit.List(r.Context(), a.Pool, limit, before)
}

func (a PGAuditReader) Verify(r *http.Request) (audit.VerifyResult, error) {
	return audit.Verify(r.Context(), a.Pool)
}
