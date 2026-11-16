package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Claims are the ID-token claims the application uses.
type Claims struct {
	Issuer            string
	Subject           string
	Nonce             string
	Name              string
	PreferredUsername string
	Email             string
	Groups            []string
	ACR               string
	AuthTime          *time.Time
	SID               string
}

// LogoutToken is a verified OIDC Back-Channel Logout token.
type LogoutToken struct {
	Issuer  string
	Subject string
	SID     string
}

// IdP is the identity provider as seen by the login flow. The production implementation is
// OIDC (Keycloak); tests use a fake.
type IdP interface {
	// AuthCodeURL builds the authorization URL. stepUp forces a fresh interactive login
	// (prompt=login, max_age=0) so the resulting auth_time proves the user just authenticated.
	AuthCodeURL(ctx context.Context, state, nonce, pkceVerifier string, stepUp bool) (string, error)
	// Exchange redeems an authorization code and returns *verified* ID-token claims.
	Exchange(ctx context.Context, code, pkceVerifier string) (Claims, error)
	EndSessionURL(ctx context.Context, postLogoutRedirect string) (string, error)
	// VerifyLogoutToken validates a back-channel logout token (signature, iss, aud, iat,
	// events claim, no nonce).
	VerifyLogoutToken(ctx context.Context, raw string) (LogoutToken, error)
}

// OIDCConfig configures the OIDC identity provider.
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	HTTPClient   *http.Client
}

type oidcIdP struct {
	cfg OIDCConfig

	mu         sync.Mutex
	provider   *oidc.Provider
	endSession string
}

// NewOIDC returns an IdP backed by OIDC discovery. Discovery happens lazily and is retried on
// the next request if it fails, so the API can start before Keycloak is ready; while the IdP
// is unreachable, logins fail (closed).
func NewOIDC(cfg OIDCConfig) IdP {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &oidcIdP{cfg: cfg}
}

func (o *oidcIdP) ctx(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, o.cfg.HTTPClient)
}

func (o *oidcIdP) get(ctx context.Context) (*oidc.Provider, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.provider != nil {
		return o.provider, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(o.ctx(ctx), o.cfg.Issuer) // verifies discovery issuer == configured issuer
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	var extra struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := p.Claims(&extra); err != nil {
		return nil, fmt.Errorf("oidc discovery metadata: %w", err)
	}
	o.provider, o.endSession = p, extra.EndSession
	return p, nil
}

func (o *oidcIdP) oauth2Config(p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     o.cfg.ClientID,
		ClientSecret: o.cfg.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  o.cfg.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
}

func (o *oidcIdP) AuthCodeURL(ctx context.Context, state, nonce, verifier string, stepUp bool) (string, error) {
	p, err := o.get(ctx)
	if err != nil {
		return "", err
	}
	opts := []oauth2.AuthCodeOption{oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)}
	if stepUp {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0"))
	}
	return o.oauth2Config(p).AuthCodeURL(state, opts...), nil
}

func (o *oidcIdP) Exchange(ctx context.Context, code, verifier string) (Claims, error) {
	p, err := o.get(ctx)
	if err != nil {
		return Claims{}, err
	}
	tok, err := o.oauth2Config(p).Exchange(o.ctx(ctx), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Claims{}, sanitizeExchangeError(err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return Claims{}, errors.New("token response has no id_token")
	}
	// Verifies signature (JWKS), issuer, audience (client ID) and expiry.
	idt, err := p.Verifier(&oidc.Config{ClientID: o.cfg.ClientID}).Verify(o.ctx(ctx), raw)
	if err != nil {
		return Claims{}, fmt.Errorf("verify id_token: %w", err)
	}
	var c struct {
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		Email             string   `json:"email"`
		Groups            []string `json:"groups"`
		ACR               string   `json:"acr"`
		AuthTime          int64    `json:"auth_time"`
		SID               string   `json:"sid"`
	}
	if err := idt.Claims(&c); err != nil {
		return Claims{}, fmt.Errorf("decode id_token claims: %w", err)
	}
	out := Claims{
		Issuer: idt.Issuer, Subject: idt.Subject, Nonce: idt.Nonce,
		Name: c.Name, PreferredUsername: c.PreferredUsername, Email: c.Email,
		Groups: c.Groups, ACR: c.ACR, SID: c.SID,
	}
	if c.AuthTime > 0 {
		t := time.Unix(c.AuthTime, 0).UTC()
		out.AuthTime = &t
	}
	return out, nil
}

const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// logoutTokenMaxAge bounds how old (by iat) an acceptable logout token may be.
const logoutTokenMaxAge = 5 * time.Minute

func (o *oidcIdP) VerifyLogoutToken(ctx context.Context, raw string) (LogoutToken, error) {
	p, err := o.get(ctx)
	if err != nil {
		return LogoutToken{}, err
	}
	// Signature (JWKS), issuer and audience are verified here. Expiry is checked below
	// because "exp" is optional in logout tokens; "iat" freshness is enforced instead.
	t, err := p.Verifier(&oidc.Config{ClientID: o.cfg.ClientID, SkipExpiryCheck: true}).Verify(o.ctx(ctx), raw)
	if err != nil {
		return LogoutToken{}, fmt.Errorf("verify logout token: %w", err)
	}
	var c struct {
		Events map[string]json.RawMessage `json:"events"`
		SID    string                     `json:"sid"`
		Nonce  *string                    `json:"nonce"`
		IAT    int64                      `json:"iat"`
	}
	if err := t.Claims(&c); err != nil {
		return LogoutToken{}, fmt.Errorf("decode logout token: %w", err)
	}
	now := time.Now()
	switch {
	case c.Events == nil || c.Events[backchannelLogoutEvent] == nil:
		return LogoutToken{}, errors.New("logout token: missing back-channel logout event")
	case c.Nonce != nil:
		return LogoutToken{}, errors.New("logout token: must not contain nonce") // rejects ID tokens
	case t.Subject == "" && c.SID == "":
		return LogoutToken{}, errors.New("logout token: neither sub nor sid")
	case c.IAT == 0:
		return LogoutToken{}, errors.New("logout token: missing iat")
	}
	iat := time.Unix(c.IAT, 0)
	if now.Sub(iat) > logoutTokenMaxAge || iat.After(now.Add(time.Minute)) {
		return LogoutToken{}, errors.New("logout token: iat outside the accepted window")
	}
	if !t.Expiry.IsZero() && now.After(t.Expiry) {
		return LogoutToken{}, errors.New("logout token: expired")
	}
	return LogoutToken{Issuer: t.Issuer, Subject: t.Subject, SID: truncate(c.SID, 255)}, nil
}

// sanitizeExchangeError keeps only the HTTP status and OAuth error code of a token-endpoint
// failure. oauth2.RetrieveError.Error() embeds the raw response body, which must never
// reach the logs.
func sanitizeExchangeError(err error) error {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		status := 0
		if re.Response != nil {
			status = re.Response.StatusCode
		}
		code := re.ErrorCode
		if code == "" {
			code = "unknown"
		}
		return fmt.Errorf("code exchange: token endpoint returned HTTP %d (%s)", status, truncate(code, 64))
	}
	// Transport errors (e.g. connection refused) carry the endpoint URL but no request body;
	// keep them for diagnosis — the logging layer still scrubs anything token-shaped.
	return fmt.Errorf("code exchange: %w", err)
}

func (o *oidcIdP) EndSessionURL(ctx context.Context, postLogoutRedirect string) (string, error) {
	if _, err := o.get(ctx); err != nil {
		return "", err
	}
	if o.endSession == "" {
		return "", errors.New("idp has no end_session_endpoint")
	}
	u, err := url.Parse(o.endSession)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", o.cfg.ClientID)
	q.Set("post_logout_redirect_uri", postLogoutRedirect)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
