package approval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PGStore implements Store on the approval database.
type PGStore struct{ Pool *pgxpool.Pool }

func (s PGStore) Create(ctx context.Context, r *Request) (*Request, error) {
	spec, err := json.Marshal(r.Spec)
	if err != nil {
		return nil, err
	}
	tag, err := s.Pool.Exec(ctx, `
		INSERT INTO approval.requests (id, experiment_id, cluster_id, environment, namespaces, approver_group, spec,
		    spec_sha256, risk, requester_issuer, requester_subject, requester_name, min_approvals, state, created_at, expires_at)
		VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		ON CONFLICT (experiment_id) DO NOTHING`,
		r.ID, r.ExperimentID, r.ClusterID, r.Environment, r.Namespaces, r.ApproverGroup, spec, r.SpecSHA256, r.Risk,
		r.RequesterIssuer, r.RequesterSubject, r.RequesterName, r.MinApprovals, r.State, r.CreatedAt, r.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 { // idempotent: return the existing request for this experiment
		var id string
		if err := s.Pool.QueryRow(ctx, `SELECT id::text FROM approval.requests WHERE experiment_id = $1::uuid`, r.ExperimentID).Scan(&id); err != nil {
			return nil, err
		}
		return s.Get(ctx, id)
	}
	return r, nil
}

const selectRequest = `SELECT id::text, experiment_id::text, cluster_id, environment, namespaces, approver_group, spec,
	spec_sha256, risk, requester_issuer, requester_subject, requester_name, min_approvals, state, coalesce(attestation, ''),
	created_at, expires_at, decided_at FROM approval.requests `

func scanRequest(row pgx.Row) (*Request, error) {
	var (
		r    Request
		spec []byte
	)
	err := row.Scan(&r.ID, &r.ExperimentID, &r.ClusterID, &r.Environment, &r.Namespaces, &r.ApproverGroup, &spec,
		&r.SpecSHA256, &r.Risk, &r.RequesterIssuer, &r.RequesterSubject, &r.RequesterName, &r.MinApprovals, &r.State,
		&r.Attestation, &r.CreatedAt, &r.ExpiresAt, &r.DecidedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(spec, &r.Spec); err != nil {
		return nil, fmt.Errorf("decode spec: %w", err)
	}
	return &r, nil
}

func (s PGStore) decisions(ctx context.Context, r *Request) error {
	rows, err := s.Pool.Query(ctx, `SELECT approver_issuer, approver_subject, approver_name, decision, comment, auth_time, decided_at
		FROM approval.decisions WHERE request_id = $1::uuid ORDER BY id`, r.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	r.Decisions = []Decision{}
	for rows.Next() {
		var d Decision
		if err := rows.Scan(&d.ApproverIssuer, &d.ApproverSubject, &d.ApproverName, &d.Decision, &d.Comment, &d.AuthTime, &d.DecidedAt); err != nil {
			return err
		}
		r.Decisions = append(r.Decisions, d)
	}
	return rows.Err()
}

func (s PGStore) Get(ctx context.Context, id string) (*Request, error) {
	if !isUUID(id) {
		return nil, ErrNotFound
	}
	r, err := scanRequest(s.Pool.QueryRow(ctx, selectRequest+`WHERE id = $1::uuid`, id))
	if err != nil {
		return nil, err
	}
	return r, s.decisions(ctx, r)
}

func (s PGStore) ListForGroups(ctx context.Context, groups []string, limit int) ([]*Request, error) {
	rows, err := s.Pool.Query(ctx, selectRequest+`WHERE approver_group = ANY($1) ORDER BY created_at DESC LIMIT $2`, groups, limit)
	if err != nil {
		return nil, err
	}
	var out []*Request
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, r := range out {
		if err := s.decisions(ctx, r); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s PGStore) AddDecision(ctx context.Context, id string, d Decision) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO approval.decisions (request_id, approver_issuer, approver_subject, approver_name, decision, comment, auth_time, decided_at)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8)`, id, d.ApproverIssuer, d.ApproverSubject, d.ApproverName, d.Decision, d.Comment, d.AuthTime, d.DecidedAt)
	return err
}

func (s PGStore) Finish(ctx context.Context, id, state, att string) error {
	// Only a Pending request can move; concurrent decisions cannot overwrite each other.
	tag, err := s.Pool.Exec(ctx, `UPDATE approval.requests SET state = $2, attestation = NULLIF($3, ''), decided_at = now()
		WHERE id = $1::uuid AND state = 'Pending'`, id, state, att)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return nil
}

// MemStore is an in-memory Store for tests.
type MemStore struct {
	mu   sync.Mutex
	reqs map[string]*Request
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore { return &MemStore{reqs: map[string]*Request{}} }

func (m *MemStore) Create(_ context.Context, r *Request) (*Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.reqs {
		if x.ExperimentID == r.ExperimentID {
			c := *x
			return &c, nil
		}
	}
	c := *r
	c.Decisions = []Decision{}
	m.reqs[r.ID] = &c
	out := c
	return &out, nil
}

func (m *MemStore) Get(_ context.Context, id string) (*Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reqs[id]
	if !ok {
		return nil, ErrNotFound
	}
	c := *r
	c.Decisions = append([]Decision(nil), r.Decisions...)
	return &c, nil
}

func (m *MemStore) ListForGroups(_ context.Context, groups []string, _ int) ([]*Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Request
	for _, r := range m.reqs {
		for _, g := range groups {
			if r.ApproverGroup == g {
				c := *r
				out = append(out, &c)
			}
		}
	}
	return out, nil
}

func (m *MemStore) AddDecision(_ context.Context, id string, d Decision) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reqs[id]
	if !ok {
		return ErrNotFound
	}
	for _, x := range r.Decisions {
		if x.ApproverIssuer == d.ApproverIssuer && x.ApproverSubject == d.ApproverSubject {
			return ErrConflict
		}
	}
	r.Decisions = append(r.Decisions, d)
	return nil
}

func (m *MemStore) Finish(_ context.Context, id, state, att string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reqs[id]
	if !ok {
		return ErrNotFound
	}
	if r.State != StatePending {
		return ErrConflict
	}
	r.State, r.Attestation = state, att
	return nil
}
