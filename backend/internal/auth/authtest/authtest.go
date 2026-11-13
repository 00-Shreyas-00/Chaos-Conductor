// Package authtest provides in-memory fakes of auth.Store and auth.IdP for tests.
package authtest

import (
	"context"
	"encoding/hex"
	"errors"
	"net/url"
	"sync"
	"time"

	"github.com/kubechaos/kubechaos/backend/internal/auth"
)

// MemStore is an in-memory auth.Store. Set Err to make every call fail.
type MemStore struct {
	mu         sync.Mutex
	Err        error
	Logins     map[string]auth.LoginRequest
	Identities map[string]auth.Identity // key: issuer|subject
	Sessions   map[string]auth.Session
	LastSeen   map[string]time.Time
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{
		Logins: map[string]auth.LoginRequest{}, Identities: map[string]auth.Identity{},
		Sessions: map[string]auth.Session{}, LastSeen: map[string]time.Time{},
	}
}

func k(b []byte) string { return hex.EncodeToString(b) }

func (m *MemStore) CreateLoginRequest(_ context.Context, lr auth.LoginRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return m.Err
	}
	m.Logins[k(lr.StateHash)] = lr
	return nil
}

func (m *MemStore) ConsumeLoginRequest(_ context.Context, h []byte) (auth.LoginRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return auth.LoginRequest{}, m.Err
	}
	lr, ok := m.Logins[k(h)]
	delete(m.Logins, k(h))
	if !ok || !lr.ExpiresAt.After(time.Now()) {
		return auth.LoginRequest{}, auth.ErrNotFound
	}
	return lr, nil
}

func (m *MemStore) UpsertIdentity(_ context.Context, id auth.Identity) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return "", m.Err
	}
	key := id.Issuer + "|" + id.Subject
	if existing, ok := m.Identities[key]; ok {
		id.ID = existing.ID
	} else {
		id.ID = "00000000-0000-0000-0000-" + hex.EncodeToString([]byte(id.Subject + "      "))[:12]
	}
	m.Identities[key] = id
	return id.ID, nil
}

func (m *MemStore) CreateSession(_ context.Context, s auth.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return m.Err
	}
	m.Sessions[k(s.TokenHash)] = s
	m.LastSeen[k(s.TokenHash)] = time.Now()
	return nil
}

func (m *MemStore) LookupSession(_ context.Context, h []byte) (auth.Session, auth.Identity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return auth.Session{}, auth.Identity{}, m.Err
	}
	s, ok := m.Sessions[k(h)]
	if !ok || !s.ExpiresAt.After(time.Now()) || time.Since(m.LastSeen[k(h)]) > s.IdleTimeout {
		return auth.Session{}, auth.Identity{}, auth.ErrNotFound
	}
	for _, id := range m.Identities {
		if id.ID == s.IdentityID {
			return s, id, nil
		}
	}
	return auth.Session{}, auth.Identity{}, auth.ErrNotFound
}

func (m *MemStore) TouchSession(_ context.Context, h []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.LastSeen[k(h)] = time.Now()
	return m.Err
}

func (m *MemStore) DeleteSession(_ context.Context, h []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return m.Err
	}
	delete(m.Sessions, k(h))
	return nil
}

func (m *MemStore) deleteWhere(match func(auth.Session, auth.Identity) bool) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return 0, m.Err
	}
	var n int64
	for key, s := range m.Sessions {
		for _, id := range m.Identities {
			if id.ID == s.IdentityID && match(s, id) {
				delete(m.Sessions, key)
				n++
			}
		}
	}
	return n, nil
}

func (m *MemStore) DeleteSessionsBySID(_ context.Context, issuer, sid string) (int64, error) {
	return m.deleteWhere(func(s auth.Session, id auth.Identity) bool { return id.Issuer == issuer && s.IdPSID == sid })
}

func (m *MemStore) DeleteSessionsBySubject(_ context.Context, issuer, subject string) (int64, error) {
	return m.deleteWhere(func(_ auth.Session, id auth.Identity) bool { return id.Issuer == issuer && id.Subject == subject })
}

func (m *MemStore) DeleteExpired(context.Context) error { return m.Err }

// FakeIdP is a programmable auth.IdP.
type FakeIdP struct {
	mu          sync.Mutex
	AuthURLErr  error
	ExchangeErr error
	// Claims returned by Exchange. If Claims.Nonce is empty, the nonce from the most recent
	// AuthCodeURL call is echoed back (the honest-IdP behaviour).
	Claims       auth.Claims
	LastState    string
	LastNonce    string
	LastVerifier string
	LastCode     string
	LogoutTokens map[string]auth.LogoutToken
}

func (f *FakeIdP) AuthCodeURL(_ context.Context, state, nonce, verifier string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.AuthURLErr != nil {
		return "", f.AuthURLErr
	}
	f.LastState, f.LastNonce, f.LastVerifier = state, nonce, verifier
	return "https://idp.test/authorize?state=" + url.QueryEscape(state), nil
}

func (f *FakeIdP) Exchange(_ context.Context, code, verifier string) (auth.Claims, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.LastCode = code
	if f.ExchangeErr != nil {
		return auth.Claims{}, f.ExchangeErr
	}
	c := f.Claims
	if c.Nonce == "" {
		c.Nonce = f.LastNonce
	}
	if verifier != f.LastVerifier {
		c.Nonce = "pkce-verifier-mismatch" // makes the flow fail like a real IdP would
	}
	return c, nil
}

// LogoutTokens maps raw logout-token strings to the verified result; anything else is invalid.
func (f *FakeIdP) VerifyLogoutToken(_ context.Context, raw string) (auth.LogoutToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if lt, ok := f.LogoutTokens[raw]; ok {
		return lt, nil
	}
	return auth.LogoutToken{}, errors.New("invalid logout token")
}

func (f *FakeIdP) EndSessionURL(_ context.Context, redirect string) (string, error) {
	return "https://idp.test/logout?post_logout_redirect_uri=" + url.QueryEscape(redirect), nil
}
