package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kubechaos/kubechaos/backend/internal/auth"
)

// SessionStore implements auth.Store on PostgreSQL.
type SessionStore struct{ pool *pgxpool.Pool }

// NewSessionStore returns a SessionStore.
func NewSessionStore(pool *pgxpool.Pool) *SessionStore { return &SessionStore{pool: pool} }

var _ auth.Store = (*SessionStore)(nil)

func (s *SessionStore) CreateLoginRequest(ctx context.Context, lr auth.LoginRequest) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO app.login_requests (state_hash, nonce, pkce_verifier, return_to, step_up, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		lr.StateHash, lr.Nonce, lr.PKCEVerifier, lr.ReturnTo, lr.StepUp, lr.ExpiresAt)
	return err
}

func (s *SessionStore) ConsumeLoginRequest(ctx context.Context, stateHash []byte) (auth.LoginRequest, error) {
	lr := auth.LoginRequest{StateHash: stateHash}
	// DELETE … RETURNING makes consumption atomic: concurrent replays cannot both succeed.
	err := s.pool.QueryRow(ctx, `
		DELETE FROM app.login_requests
		WHERE state_hash = $1
		RETURNING nonce, pkce_verifier, return_to, step_up, expires_at`, stateHash).
		Scan(&lr.Nonce, &lr.PKCEVerifier, &lr.ReturnTo, &lr.StepUp, &lr.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return lr, auth.ErrNotFound
	}
	if err != nil {
		return lr, err
	}
	if !lr.ExpiresAt.After(time.Now()) {
		return lr, auth.ErrNotFound
	}
	return lr, nil
}

func (s *SessionStore) UpsertIdentity(ctx context.Context, id auth.Identity) (string, error) {
	var out string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO app.identities (issuer, subject, display_name, email, last_login_at)
		VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), now())
		ON CONFLICT (issuer, subject) DO UPDATE
		   SET display_name = EXCLUDED.display_name,
		       email        = EXCLUDED.email,
		       last_login_at = now()
		RETURNING id::text`, id.Issuer, id.Subject, id.DisplayName, id.Email).Scan(&out)
	return out, err
}

func (s *SessionStore) CreateSession(ctx context.Context, sess auth.Session) error {
	roles := make([]string, len(sess.Roles))
	for i, r := range sess.Roles {
		roles[i] = string(r)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO app.sessions (token_hash, identity_id, roles, acr, auth_time, csrf_token, idp_sid, idle_timeout_seconds, expires_at, groups)
		VALUES ($1, $2::uuid, $3, NULLIF($4, ''), $5, $6, NULLIF($7, ''), $8, $9, $10)`,
		sess.TokenHash, sess.IdentityID, roles, sess.ACR, sess.AuthTime, sess.CSRFToken,
		sess.IdPSID, int(sess.IdleTimeout.Seconds()), sess.ExpiresAt, nonNil(sess.Groups))
	return err
}

func (s *SessionStore) LookupSession(ctx context.Context, tokenHash []byte) (auth.Session, auth.Identity, error) {
	var (
		sess    = auth.Session{TokenHash: tokenHash}
		ident   auth.Identity
		roles   []string
		sid     string
		idleSec int
	)
	err := s.pool.QueryRow(ctx, `
		SELECT s.identity_id::text, s.roles, coalesce(s.acr, ''), s.auth_time, s.csrf_token, s.expires_at,
		       coalesce(s.idp_sid, ''), s.idle_timeout_seconds, s.groups,
		       i.issuer, i.subject, coalesce(i.display_name, ''), coalesce(i.email, '')
		FROM app.sessions s
		JOIN app.identities i ON i.id = s.identity_id
		WHERE s.token_hash = $1
		  AND s.expires_at > now()
		  AND s.last_seen_at > now() - make_interval(secs => s.idle_timeout_seconds)`,
		tokenHash).
		Scan(&sess.IdentityID, &roles, &sess.ACR, &sess.AuthTime, &sess.CSRFToken, &sess.ExpiresAt,
			&sid, &idleSec, &sess.Groups, &ident.Issuer, &ident.Subject, &ident.DisplayName, &ident.Email)
	if errors.Is(err, pgx.ErrNoRows) {
		return sess, ident, auth.ErrNotFound
	}
	if err != nil {
		return sess, ident, fmt.Errorf("lookup session: %w", err)
	}
	ident.ID = sess.IdentityID
	sess.IdPSID = sid
	sess.IdleTimeout = time.Duration(idleSec) * time.Second
	sess.Roles = make([]auth.Role, len(roles))
	for i, r := range roles {
		sess.Roles[i] = auth.Role(r)
	}
	return sess, ident, nil
}

func (s *SessionStore) TouchSession(ctx context.Context, tokenHash []byte) error {
	// Throttled: at most one write per session per minute.
	_, err := s.pool.Exec(ctx, `
		UPDATE app.sessions SET last_seen_at = now()
		WHERE token_hash = $1 AND last_seen_at < now() - interval '1 minute'`, tokenHash)
	return err
}

func (s *SessionStore) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM app.sessions WHERE token_hash = $1`, tokenHash)
	return err
}

func (s *SessionStore) DeleteSessionsBySID(ctx context.Context, issuer, sid string) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM app.sessions s USING app.identities i
		WHERE s.identity_id = i.id AND i.issuer = $1 AND s.idp_sid = $2`, issuer, sid)
	return tag.RowsAffected(), err
}

func (s *SessionStore) DeleteSessionsBySubject(ctx context.Context, issuer, subject string) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM app.sessions s USING app.identities i
		WHERE s.identity_id = i.id AND i.issuer = $1 AND i.subject = $2`, issuer, subject)
	return tag.RowsAffected(), err
}

// RevokeSelector chooses which sessions the break-glass CLI revokes. Exactly one field is set.
type RevokeSelector struct {
	Subject string // IdP subject (any issuer)
	Email   string // identity e-mail (case-insensitive)
	Role    string // every session holding this role
	All     bool
}

// RevokeSessions deletes sessions for the break-glass CLI path (`kubechaos-api sessions
// revoke`), which works without the web UI or the IdP.
func (s *SessionStore) RevokeSessions(ctx context.Context, sel RevokeSelector) (int64, error) {
	var (
		sql  string
		args []any
	)
	switch {
	case sel.All:
		sql = `DELETE FROM app.sessions`
	case sel.Subject != "":
		sql, args = `DELETE FROM app.sessions s USING app.identities i WHERE s.identity_id = i.id AND i.subject = $1`, []any{sel.Subject}
	case sel.Email != "":
		sql, args = `DELETE FROM app.sessions s USING app.identities i WHERE s.identity_id = i.id AND lower(i.email) = lower($1)`, []any{sel.Email}
	case sel.Role != "":
		sql, args = `DELETE FROM app.sessions WHERE $1 = ANY(roles)`, []any{sel.Role}
	default:
		return 0, errors.New("revoke: no selector")
	}
	tag, err := s.pool.Exec(ctx, sql, args...)
	return tag.RowsAffected(), err
}

func (s *SessionStore) DeleteExpired(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM app.sessions WHERE expires_at <= now()`); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM app.login_requests WHERE expires_at <= now()`)
	return err
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
