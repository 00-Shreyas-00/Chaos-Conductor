package auth

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by Store lookups that find nothing (missing, expired or consumed).
var ErrNotFound = errors.New("not found")

// LoginRequest is the server-side state of one in-flight authorization-code flow.
type LoginRequest struct {
	StateHash    []byte // SHA-256 of the OAuth state parameter
	Nonce        string
	PKCEVerifier string
	ReturnTo     string
	// StepUp requires the callback's ID token to prove a fresh interactive authentication.
	StepUp    bool
	ExpiresAt time.Time
}

// Identity is an IdP subject as recorded by the application.
type Identity struct {
	ID          string
	Issuer      string
	Subject     string
	DisplayName string
	Email       string
}

// Session is a server-side session. The browser holds only the random token; the store
// holds only its hash.
type Session struct {
	TokenHash   []byte
	IdentityID  string
	Roles       []Role
	ACR         string
	AuthTime    *time.Time
	CSRFToken   string
	IdPSID      string        // IdP session ID ("sid" claim), for back-channel logout
	IdleTimeout time.Duration // per-session; shorter for high-privilege roles
	ExpiresAt   time.Time
}

// Store persists login requests, identities and sessions.
type Store interface {
	CreateLoginRequest(ctx context.Context, lr LoginRequest) error
	// ConsumeLoginRequest atomically deletes and returns an unexpired request (single use).
	ConsumeLoginRequest(ctx context.Context, stateHash []byte) (LoginRequest, error)
	UpsertIdentity(ctx context.Context, id Identity) (string, error)
	CreateSession(ctx context.Context, s Session) error
	// LookupSession returns a session that is neither expired nor idle beyond its own timeout.
	LookupSession(ctx context.Context, tokenHash []byte) (Session, Identity, error)
	TouchSession(ctx context.Context, tokenHash []byte) error
	DeleteSession(ctx context.Context, tokenHash []byte) error
	// DeleteSessionsBySID revokes sessions created from IdP session sid (back-channel logout).
	DeleteSessionsBySID(ctx context.Context, issuer, sid string) (int64, error)
	// DeleteSessionsBySubject revokes every session of an identity.
	DeleteSessionsBySubject(ctx context.Context, issuer, subject string) (int64, error)
	DeleteExpired(ctx context.Context) error
}
