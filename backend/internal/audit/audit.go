// Package audit writes the append-only, hash-chained audit log (architecture §9, threat model
// T12) and verifies it. Every security-relevant action produces one event; if an event cannot
// be written, the action it describes must not happen (callers fail closed).
package audit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Event is one audit record. Field names are the canonical JSON keys.
type Event struct {
	Action               string          `json:"action"`
	ActorIssuer          string          `json:"actorIssuer,omitempty"`
	ActorSubject         string          `json:"actorSubject,omitempty"`
	ActorName            string          `json:"actorName,omitempty"`
	AuthLevel            string          `json:"authLevel,omitempty"`
	SourceIP             string          `json:"sourceIp,omitempty"`
	ClusterID            string          `json:"clusterId,omitempty"`
	Namespace            string          `json:"namespace,omitempty"`
	Resource             string          `json:"resource,omitempty"`
	FaultType            string          `json:"faultType,omitempty"`
	ExperimentID         string          `json:"experimentId,omitempty"`
	Parameters           json.RawMessage `json:"parameters,omitempty"`
	RequestedBlastRadius json.RawMessage `json:"requestedBlastRadius,omitempty"`
	Decision             string          `json:"decision,omitempty"` // allow | deny
	DecisionReasons      []string        `json:"decisionReasons,omitempty"`
	PolicyVersion        string          `json:"policyVersion,omitempty"`
	Result               string          `json:"result,omitempty"`
	AffectedResources    json.RawMessage `json:"affectedResources,omitempty"`
}

// Record is an event as stored.
type Record struct {
	Seq        int64     `json:"seq"`
	ID         string    `json:"id"`
	OccurredAt time.Time `json:"occurredAt"`
	Event
	Hash string `json:"hash"`
}

type canonicalRecord struct {
	ID         string `json:"id"`
	OccurredAt string `json:"occurredAt"`
	Event
}

// lockKey serialises chain appends (pg_advisory_xact_lock).
const lockKey = 7243561

var zeroHash = make([]byte, 32)

// Writer appends to and verifies audit.events.
type Writer struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// NewWriter returns a Writer.
func NewWriter(pool *pgxpool.Pool) *Writer { return &Writer{pool: pool, now: time.Now} }

// Append writes e in its own transaction.
func (w *Writer) Append(ctx context.Context, e Event) error {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("audit: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if err := w.AppendTx(ctx, tx, e); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AppendTx writes e inside tx, so it commits or rolls back together with the action it records.
func (w *Writer) AppendTx(ctx context.Context, tx pgx.Tx, e Event) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockKey); err != nil {
		return fmt.Errorf("audit: lock: %w", err)
	}
	prev := zeroHash
	err := tx.QueryRow(ctx, `SELECT hash FROM audit.events ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("audit: read chain head: %w", err)
	}
	id := newUUID()
	at := w.now().UTC().Truncate(time.Microsecond) // Postgres precision
	canonical, err := json.Marshal(canonicalRecord{ID: id, OccurredAt: at.Format(time.RFC3339Nano), Event: e})
	if err != nil {
		return fmt.Errorf("audit: encode: %w", err)
	}
	h := chainHash(prev, canonical)
	reasons, _ := json.Marshal(e.DecisionReasons)
	if e.DecisionReasons == nil {
		reasons = nil
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO audit.events (id, occurred_at, actor_issuer, actor_subject, actor_display_name, auth_level,
		    source_ip, action, cluster_id, namespace, resource, fault_type, experiment_id, parameters,
		    requested_blast_radius, decision, decision_reasons, policy_version, result, affected_resources,
		    prev_hash, hash, canonical)
		VALUES ($1, $2, NULLIF($3,''), NULLIF($4,''), NULLIF($5,''), NULLIF($6,''), NULLIF($7,'')::inet, $8,
		    NULLIF($9,''), NULLIF($10,''), NULLIF($11,''), NULLIF($12,''), NULLIF($13,'')::uuid, $14, $15,
		    NULLIF($16,''), $17, NULLIF($18,''), NULLIF($19,''), $20, $21, $22, $23)`,
		id, at, e.ActorIssuer, e.ActorSubject, e.ActorName, e.AuthLevel, e.SourceIP, e.Action, e.ClusterID,
		e.Namespace, e.Resource, e.FaultType, e.ExperimentID, nullJSON(e.Parameters), nullJSON(e.RequestedBlastRadius),
		e.Decision, nullJSON(reasons), e.PolicyVersion, e.Result, nullJSON(e.AffectedResources), prev, h, string(canonical))
	if err != nil {
		return fmt.Errorf("audit: insert: %w", err)
	}
	return nil
}

// VerifyResult summarises a chain verification.
type VerifyResult struct {
	Events int    `json:"events"`
	Head   string `json:"head"`
}

// Verify walks the whole chain: every prev_hash must equal the previous hash, every hash must
// equal SHA-256(prev_hash || canonical), and the queryable columns must match the canonical
// record. Any deletion, reordering or edit is detected.
func Verify(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}) (VerifyResult, error) {
	rows, err := q.Query(ctx, `SELECT seq, prev_hash, hash, canonical, action, coalesce(actor_subject,''),
		coalesce(experiment_id::text,''), coalesce(decision,'') FROM audit.events ORDER BY seq`)
	if err != nil {
		return VerifyResult{}, err
	}
	defer rows.Close()
	prev := zeroHash
	n := 0
	for rows.Next() {
		var (
			seq                              int64
			prevHash, hash                   []byte
			canonical                        *string
			action, subject, expID, decision string
		)
		if err := rows.Scan(&seq, &prevHash, &hash, &canonical, &action, &subject, &expID, &decision); err != nil {
			return VerifyResult{}, err
		}
		switch {
		case canonical == nil:
			return VerifyResult{}, fmt.Errorf("audit chain broken at seq %d: no canonical record", seq)
		case hex.EncodeToString(prevHash) != hex.EncodeToString(prev):
			return VerifyResult{}, fmt.Errorf("audit chain broken at seq %d: prev_hash does not match the previous event (deletion or reordering)", seq)
		case hex.EncodeToString(hash) != hex.EncodeToString(chainHash(prevHash, []byte(*canonical))):
			return VerifyResult{}, fmt.Errorf("audit chain broken at seq %d: hash mismatch (record modified)", seq)
		}
		var c canonicalRecord
		if err := json.Unmarshal([]byte(*canonical), &c); err != nil ||
			c.Action != action || c.ActorSubject != subject || c.ExperimentID != expID || c.Decision != decision {
			return VerifyResult{}, fmt.Errorf("audit chain broken at seq %d: columns differ from the hashed record", seq)
		}
		prev = hash
		n++
	}
	if err := rows.Err(); err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{Events: n, Head: hex.EncodeToString(prev)}, nil
}

// List returns up to limit records with seq < before (0 = newest), newest first.
func List(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, limit int, before int64) ([]Record, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	if before <= 0 {
		before = 1<<63 - 1
	}
	rows, err := q.Query(ctx, `SELECT seq, hash, canonical FROM audit.events
		WHERE seq < $1 AND canonical IS NOT NULL ORDER BY seq DESC LIMIT $2`, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var (
			seq       int64
			hash      []byte
			canonical string
		)
		if err := rows.Scan(&seq, &hash, &canonical); err != nil {
			return nil, err
		}
		var c canonicalRecord
		if err := json.Unmarshal([]byte(canonical), &c); err != nil {
			return nil, err
		}
		at, _ := time.Parse(time.RFC3339Nano, c.OccurredAt)
		out = append(out, Record{Seq: seq, ID: c.ID, OccurredAt: at, Event: c.Event, Hash: hex.EncodeToString(hash)})
	}
	return out, rows.Err()
}

func chainHash(prev, canonical []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(canonical)
	return h.Sum(nil)
}

func nullJSON(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
