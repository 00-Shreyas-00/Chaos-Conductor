package experiments

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/kubechaos/kubechaos/backend/internal/audit"
	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
)

// MemStore is an in-memory Store and Auditor for tests.
type MemStore struct {
	mu       sync.Mutex
	byID     map[string]*Experiment
	events   map[string][]TimelineEvent
	nextID   int64
	Audits   []audit.Event
	AuditErr error
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{byID: map[string]*Experiment{}, events: map[string][]TimelineEvent{}}
}

func (m *MemStore) Append(_ context.Context, e audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.AuditErr != nil {
		return m.AuditErr
	}
	m.Audits = append(m.Audits, e)
	return nil
}

func (m *MemStore) CreateWithAudit(_ context.Context, e *Experiment, ev audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.AuditErr != nil {
		return m.AuditErr // atomic: nothing stored either
	}
	e.CreatedAt, e.UpdatedAt = time.Now(), time.Now()
	c := *e
	m.byID[e.ID] = &c
	m.Audits = append(m.Audits, ev)
	return nil
}

func (m *MemStore) SetState(_ context.Context, id, state string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.byID[id]; ok {
		e.State = state
	}
	return nil
}

func (m *MemStore) SetCancelRequested(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.byID[id]; ok {
		e.CancelRequested = true
	}
	return nil
}

func (m *MemStore) Get(_ context.Context, id string) (*Experiment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	c := *e
	return &c, nil
}

func (m *MemStore) GetByName(_ context.Context, name string) (*Experiment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.byID {
		if e.Name == name {
			c := *e
			return &c, nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemStore) List(_ context.Context, limit int) ([]*Experiment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Experiment
	for _, e := range m.byID {
		c := *e
		out = append(out, &c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MemStore) ApplyClusterStatus(_ context.Context, id string, st *chaosv1.ChaosExperimentStatus, evs []TimelineEvent) ([]TimelineEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	e.Phase, e.Result, e.Score, e.Status = string(st.Phase), st.Result, st.Score, st.DeepCopy()
	var stored []TimelineEvent
	for _, ev := range evs {
		m.nextID++
		ev.ID = m.nextID
		m.events[id] = append(m.events[id], ev)
		stored = append(stored, ev)
	}
	return stored, nil
}

func (m *MemStore) SetApprovalRequest(_ context.Context, id, requestID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.byID[id]; ok {
		e.ApprovalRequest = requestID
	}
	return nil
}

func (m *MemStore) ListPendingApproval(_ context.Context) ([]*Experiment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Experiment
	for _, e := range m.byID {
		if e.State == StatePendingApproval {
			c := *e
			out = append(out, &c)
		}
	}
	return out, nil
}

func (m *MemStore) Events(_ context.Context, id string) ([]TimelineEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]TimelineEvent(nil), m.events[id]...), nil
}
