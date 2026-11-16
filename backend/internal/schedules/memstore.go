package schedules

import (
	"context"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/kubechaos/kubechaos/backend/internal/audit"
	"github.com/kubechaos/kubechaos/backend/internal/auth"
	"github.com/kubechaos/kubechaos/backend/internal/experiments"
)

// MemStore is an in-memory Store for tests.
type MemStore struct {
	mu    sync.Mutex
	byID  map[string]*Schedule
	runs  map[string][]Run
	next  int64
	Audit experiments.Auditor // receives CreateWithAudit events
}

// NewMemStore returns an empty MemStore that records audit events in a.
func NewMemStore(a experiments.Auditor) *MemStore {
	return &MemStore{byID: map[string]*Schedule{}, runs: map[string][]Run{}, Audit: a}
}

func clone(s *Schedule) *Schedule {
	c := *s
	c.OwnerRoles = slices.Clone(s.OwnerRoles)
	return &c
}

func (m *MemStore) CreateWithAudit(ctx context.Context, s *Schedule, ev audit.Event) error {
	if err := m.Audit.Append(ctx, ev); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s.CreatedAt, s.UpdatedAt = time.Now(), time.Now()
	m.byID[s.ID] = clone(s)
	return nil
}

func (m *MemStore) Get(_ context.Context, id string) (*Schedule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[id]
	if !ok {
		return nil, experiments.ErrNotFound
	}
	return clone(s), nil
}

func (m *MemStore) List(_ context.Context, limit int) ([]*Schedule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Schedule
	for _, s := range m.byID {
		if s.State != StateDeleted {
			out = append(out, clone(s))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MemStore) Due(_ context.Context, now time.Time, limit int) ([]*Schedule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Schedule
	for _, s := range m.byID {
		if s.State == StateActive && s.NextRunAt != nil && !s.NextRunAt.After(now) && len(out) < limit {
			out = append(out, clone(s))
		}
	}
	return out, nil
}

func (m *MemStore) Claim(_ context.Context, id string, expected time.Time, next *time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[id]
	if !ok || s.State != StateActive || s.NextRunAt == nil || !s.NextRunAt.Equal(expected) {
		return false, nil
	}
	s.NextRunAt = next
	return true, nil
}

func (m *MemStore) RecordRun(_ context.Context, s *Schedule, r Run) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.byID[s.ID]
	if !ok {
		return experiments.ErrNotFound
	}
	m.next++
	r.ID = m.next
	m.runs[s.ID] = append(m.runs[s.ID], r)
	cur.Runs, cur.ConsecutiveDenials, cur.LastRunAt, cur.LastExperimentID = s.Runs, s.ConsecutiveDenials, s.LastRunAt, s.LastExperimentID
	if cur.State == StateActive { // a concurrent pause/delete wins
		cur.State, cur.StateReason, cur.NextRunAt = s.State, s.StateReason, s.NextRunAt
	}
	return nil
}

func (m *MemStore) SetState(_ context.Context, id string, from []string, state, reason string, next *time.Time, roles []auth.Role) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[id]
	if !ok {
		return false, experiments.ErrNotFound
	}
	if !slices.Contains(from, s.State) {
		return false, nil
	}
	s.State, s.StateReason, s.NextRunAt = state, reason, next
	if roles != nil {
		s.OwnerRoles, s.ConsecutiveDenials = slices.Clone(roles), 0
	}
	return true, nil
}

func (m *MemStore) Runs(_ context.Context, id string, limit int) ([]Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rs := m.runs[id]
	out := make([]Run, 0, len(rs))
	for i := len(rs) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, rs[i])
	}
	return out, nil
}
