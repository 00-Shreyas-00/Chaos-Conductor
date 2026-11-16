package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kubechaos/kubechaos/backend/internal/audit"
	"github.com/kubechaos/kubechaos/backend/internal/auth"
	"github.com/kubechaos/kubechaos/backend/internal/experiments"
	"github.com/kubechaos/kubechaos/backend/internal/schedules"
)

// ScheduleStore implements schedules.Store on PostgreSQL.
type ScheduleStore struct {
	pool  *pgxpool.Pool
	audit *audit.Writer
}

// NewScheduleStore returns a ScheduleStore.
func NewScheduleStore(pool *pgxpool.Pool, w *audit.Writer) *ScheduleStore {
	return &ScheduleStore{pool: pool, audit: w}
}

func rolesText(rs []auth.Role) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = string(r)
	}
	return out
}

func (s *ScheduleStore) CreateWithAudit(ctx context.Context, sc *schedules.Schedule, ev audit.Event) error {
	tmpl, err := json.Marshal(sc.Template)
	if err != nil {
		return err
	}
	win, err := json.Marshal(sc.Window)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	err = tx.QueryRow(ctx, `
		INSERT INTO app.schedules (id, name, cluster_id, owner_id, owner_roles, description, template, risk,
		    min_interval_seconds, mean_interval_seconds, window_spec, expires_at, max_runs, state, next_run_at)
		VALUES ($1, $2, $3, $4::uuid, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		RETURNING created_at, updated_at`,
		sc.ID, sc.Name, sc.ClusterID, sc.OwnerID, rolesText(sc.OwnerRoles), sc.Description, tmpl, sc.Risk,
		sc.MinIntervalSeconds, sc.MeanIntervalSeconds, win, sc.ExpiresAt, sc.MaxRuns, sc.State, sc.NextRunAt).
		Scan(&sc.CreatedAt, &sc.UpdatedAt)
	if err != nil {
		return fmt.Errorf("insert schedule: %w", err)
	}
	if err := s.audit.AppendTx(ctx, tx, ev); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

const selectSchedule = `
	SELECT s.id::text, s.name, s.cluster_id, s.owner_id::text, i.issuer, i.subject, coalesce(i.display_name, ''), s.owner_roles,
	       s.description, s.template, s.risk, s.min_interval_seconds, s.mean_interval_seconds, s.window_spec, s.expires_at,
	       s.max_runs, s.runs, s.consecutive_denials, s.state, s.state_reason, s.next_run_at, s.last_run_at,
	       coalesce(s.last_experiment_id::text, ''), s.created_at, s.updated_at
	FROM app.schedules s JOIN app.identities i ON i.id = s.owner_id `

func scanSchedule(row pgx.Row) (*schedules.Schedule, error) {
	var (
		sc        schedules.Schedule
		roles     []string
		tmpl, win []byte
	)
	err := row.Scan(&sc.ID, &sc.Name, &sc.ClusterID, &sc.OwnerID, &sc.OwnerIssuer, &sc.OwnerSubject, &sc.OwnerName, &roles,
		&sc.Description, &tmpl, &sc.Risk, &sc.MinIntervalSeconds, &sc.MeanIntervalSeconds, &win, &sc.ExpiresAt,
		&sc.MaxRuns, &sc.Runs, &sc.ConsecutiveDenials, &sc.State, &sc.StateReason, &sc.NextRunAt, &sc.LastRunAt,
		&sc.LastExperimentID, &sc.CreatedAt, &sc.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, experiments.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	for _, r := range roles {
		sc.OwnerRoles = append(sc.OwnerRoles, auth.Role(r))
	}
	if err := json.Unmarshal(tmpl, &sc.Template); err != nil {
		return nil, fmt.Errorf("decode template: %w", err)
	}
	if err := json.Unmarshal(win, &sc.Window); err != nil {
		return nil, fmt.Errorf("decode window: %w", err)
	}
	return &sc, nil
}

func (s *ScheduleStore) list(ctx context.Context, where string, args ...any) ([]*schedules.Schedule, error) {
	rows, err := s.pool.Query(ctx, selectSchedule+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*schedules.Schedule
	for rows.Next() {
		sc, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

func (s *ScheduleStore) Get(ctx context.Context, id string) (*schedules.Schedule, error) {
	if !isUUID(id) {
		return nil, experiments.ErrNotFound
	}
	return scanSchedule(s.pool.QueryRow(ctx, selectSchedule+`WHERE s.id = $1::uuid`, id))
}

func (s *ScheduleStore) List(ctx context.Context, limit int) ([]*schedules.Schedule, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	return s.list(ctx, `WHERE s.state <> 'Deleted' ORDER BY s.created_at DESC LIMIT $1`, limit)
}

func (s *ScheduleStore) Due(ctx context.Context, now time.Time, limit int) ([]*schedules.Schedule, error) {
	return s.list(ctx, `WHERE s.state = 'Active' AND s.next_run_at <= $1 ORDER BY s.next_run_at LIMIT $2`, now, limit)
}

// Claim is a compare-and-set on next_run_at: exactly one replica wins each run.
func (s *ScheduleStore) Claim(ctx context.Context, id string, expected time.Time, next *time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE app.schedules SET next_run_at = $3, updated_at = now()
		WHERE id = $1::uuid AND state = 'Active' AND next_run_at = $2`, id, expected, next)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *ScheduleStore) RecordRun(ctx context.Context, sc *schedules.Schedule, r schedules.Run) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `INSERT INTO app.schedule_runs (schedule_id, occurred_at, outcome, experiment_id, reason)
		VALUES ($1::uuid, $2, $3, NULLIF($4, '')::uuid, $5)`, sc.ID, r.OccurredAt, r.Outcome, r.ExperimentID, r.Reason); err != nil {
		return fmt.Errorf("insert run: %w", err)
	}
	// Counters always; state only while still Active (a concurrent pause or delete wins).
	if _, err := tx.Exec(ctx, `UPDATE app.schedules SET runs = $2, consecutive_denials = $3, last_run_at = $4,
		    last_experiment_id = NULLIF($5, '')::uuid, updated_at = now(),
		    state = CASE WHEN state = 'Active' THEN $6 ELSE state END,
		    state_reason = CASE WHEN state = 'Active' THEN $7 ELSE state_reason END,
		    next_run_at = CASE WHEN state = 'Active' THEN $8 ELSE next_run_at END
		WHERE id = $1::uuid`,
		sc.ID, sc.Runs, sc.ConsecutiveDenials, sc.LastRunAt, sc.LastExperimentID, sc.State, sc.StateReason, sc.NextRunAt); err != nil {
		return fmt.Errorf("update schedule: %w", err)
	}
	return tx.Commit(ctx)
}

func (s *ScheduleStore) SetState(ctx context.Context, id string, from []string, state, reason string, next *time.Time, roles []auth.Role) (bool, error) {
	if !isUUID(id) {
		return false, experiments.ErrNotFound
	}
	var rolesArg any
	if roles != nil {
		rolesArg = rolesText(roles)
	}
	tag, err := s.pool.Exec(ctx, `UPDATE app.schedules SET state = $3, state_reason = $4, next_run_at = $5,
		    owner_roles = coalesce($6, owner_roles),
		    consecutive_denials = CASE WHEN $6::text[] IS NULL THEN consecutive_denials ELSE 0 END, updated_at = now()
		WHERE id = $1::uuid AND state = ANY($2)`, id, from, state, reason, next, rolesArg)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *ScheduleStore) Runs(ctx context.Context, id string, limit int) ([]schedules.Run, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, schedule_id::text, occurred_at, outcome, coalesce(experiment_id::text, ''), reason
		FROM app.schedule_runs WHERE schedule_id = $1::uuid ORDER BY id DESC LIMIT $2`, id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []schedules.Run{}
	for rows.Next() {
		var r schedules.Run
		if err := rows.Scan(&r.ID, &r.ScheduleID, &r.OccurredAt, &r.Outcome, &r.ExperimentID, &r.Reason); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
