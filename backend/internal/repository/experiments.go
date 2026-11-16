package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kubechaos/kubechaos/backend/internal/audit"
	"github.com/kubechaos/kubechaos/backend/internal/experiments"
	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
)

// ExperimentStore implements experiments.Store on PostgreSQL.
type ExperimentStore struct {
	pool  *pgxpool.Pool
	audit *audit.Writer
}

// NewExperimentStore returns an ExperimentStore.
func NewExperimentStore(pool *pgxpool.Pool, w *audit.Writer) *ExperimentStore {
	return &ExperimentStore{pool: pool, audit: w}
}

var _ experiments.Store = (*ExperimentStore)(nil)

// EnsureCluster records the connected cluster (experiments reference it).
func (s *ExperimentStore) EnsureCluster(ctx context.Context, id, displayName, environment string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO app.clusters (id, display_name, environment) VALUES ($1, $2, $3)
		ON CONFLICT (id) DO UPDATE SET display_name = EXCLUDED.display_name, environment = EXCLUDED.environment, updated_at = now()`,
		id, displayName, environment)
	return err
}

func (s *ExperimentStore) CreateWithAudit(ctx context.Context, e *experiments.Experiment, ev audit.Event) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	spec, err := json.Marshal(e.Spec)
	if err != nil {
		return err
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO app.experiments (id, name, cluster_id, requested_by, description, spec, spec_sha256, risk, state, schedule_id)
		VALUES ($1, $2, $3, $4::uuid, $5, $6, $7, $8, $9, NULLIF($10, '')::uuid)
		RETURNING created_at, updated_at`,
		e.ID, e.Name, e.ClusterID, e.RequesterID, e.Description, spec, e.SpecSHA256, string(e.Risk), e.State, e.ScheduleID).
		Scan(&e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		return fmt.Errorf("insert experiment: %w", err)
	}
	if err := s.audit.AppendTx(ctx, tx, ev); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *ExperimentStore) SetState(ctx context.Context, id, state string) error {
	_, err := s.pool.Exec(ctx, `UPDATE app.experiments SET state = $2, updated_at = now() WHERE id = $1`, id, state)
	return err
}

func (s *ExperimentStore) SetApprovalRequest(ctx context.Context, id, requestID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE app.experiments SET approval_request_id = $2::uuid, updated_at = now() WHERE id = $1`, id, requestID)
	return err
}

func (s *ExperimentStore) ListPendingApproval(ctx context.Context) ([]*experiments.Experiment, error) {
	rows, err := s.pool.Query(ctx, selectExperiment+`WHERE e.state = 'PendingApproval' ORDER BY e.created_at LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*experiments.Experiment
	for rows.Next() {
		e, err := scanExperiment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *ExperimentStore) SetCancelRequested(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE app.experiments SET cancel_requested = true, updated_at = now() WHERE id = $1`, id)
	return err
}

const selectExperiment = `
	SELECT e.id::text, e.name, e.cluster_id, e.requested_by::text, i.issuer, i.subject, coalesce(i.display_name, ''),
	       e.description, e.spec, e.spec_sha256, e.risk, e.state, e.phase, e.result, e.score, e.status,
	       e.cancel_requested, e.created_at, e.updated_at, coalesce(e.approval_request_id::text, ''), coalesce(e.schedule_id::text, '')
	FROM app.experiments e JOIN app.identities i ON i.id = e.requested_by `

func scanExperiment(row pgx.Row) (*experiments.Experiment, error) {
	var (
		e            experiments.Experiment
		spec, status []byte
		risk         string
	)
	err := row.Scan(&e.ID, &e.Name, &e.ClusterID, &e.RequesterID, &e.RequesterIssuer, &e.RequesterSubj, &e.RequesterName,
		&e.Description, &spec, &e.SpecSHA256, &risk, &e.State, &e.Phase, &e.Result, &e.Score, &status,
		&e.CancelRequested, &e.CreatedAt, &e.UpdatedAt, &e.ApprovalRequest, &e.ScheduleID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, experiments.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	e.Risk = chaosv1.RiskLevel(risk)
	if err := json.Unmarshal(spec, &e.Spec); err != nil {
		return nil, fmt.Errorf("decode spec: %w", err)
	}
	if len(status) > 0 {
		e.Status = &chaosv1.ChaosExperimentStatus{}
		if err := json.Unmarshal(status, e.Status); err != nil {
			return nil, fmt.Errorf("decode status: %w", err)
		}
	}
	return &e, nil
}

func (s *ExperimentStore) Get(ctx context.Context, id string) (*experiments.Experiment, error) {
	if !isUUID(id) {
		return nil, experiments.ErrNotFound
	}
	return scanExperiment(s.pool.QueryRow(ctx, selectExperiment+`WHERE e.id = $1::uuid`, id))
}

func (s *ExperimentStore) GetByName(ctx context.Context, name string) (*experiments.Experiment, error) {
	return scanExperiment(s.pool.QueryRow(ctx, selectExperiment+`WHERE e.name = $1`, name))
}

func (s *ExperimentStore) List(ctx context.Context, limit int) ([]*experiments.Experiment, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, selectExperiment+`ORDER BY e.created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*experiments.Experiment
	for rows.Next() {
		e, err := scanExperiment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *ExperimentStore) ApplyClusterStatus(ctx context.Context, id string, st *chaosv1.ChaosExperimentStatus, evs []experiments.TimelineEvent) ([]experiments.TimelineEvent, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	raw, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE app.experiments SET phase = $2, result = $3, score = $4, status = $5, updated_at = now() WHERE id = $1::uuid`,
		id, string(st.Phase), st.Result, st.Score, raw); err != nil {
		return nil, err
	}
	stored := make([]experiments.TimelineEvent, 0, len(evs))
	for _, e := range evs {
		if err := tx.QueryRow(ctx, `
			INSERT INTO app.experiment_events (experiment_id, occurred_at, type, message) VALUES ($1::uuid, $2, $3, $4)
			RETURNING id`, id, e.OccurredAt, e.Type, e.Message).Scan(&e.ID); err != nil {
			return nil, err
		}
		stored = append(stored, e)
	}
	return stored, tx.Commit(ctx)
}

func (s *ExperimentStore) Events(ctx context.Context, id string) ([]experiments.TimelineEvent, error) {
	if !isUUID(id) {
		return nil, experiments.ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT id, occurred_at, type, message FROM app.experiment_events
		WHERE experiment_id = $1::uuid ORDER BY occurred_at, id LIMIT 1000`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []experiments.TimelineEvent
	for rows.Next() {
		var e experiments.TimelineEvent
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.Type, &e.Message); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
	}
	return true
}
