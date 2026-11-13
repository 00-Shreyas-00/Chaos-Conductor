package auth

import (
	"context"
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
}

// IdP is the identity provider as seen by the login flow. The production implementation is
// OIDC (Keycloak); tests use a fake.
type IdP interface {
	AuthCodeURL(ctx context.Context, state, nonce, pkceVerifier string) (string, error)
	// Exchange redeems an authorization code and returns *verified* ID-token claims.
	Exchange(ctx context.Context, code, pkceVerifier string) (Claims, error)
	EndSessionURL(ctx context.Context, postLogoutRedirect string) (string, error)
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

func (o *oidcIdP) AuthCodeURL(ctx context.Context, state, nonce, verifier string) (string, error) {
	p, err := o.get(ctx)
	if err != nil {
		return "", err
	}
	return o.oauth2Config(p).AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), nil
}

func (o *oidcIdP) Exchange(ctx context.Context, code, verifier string) (Claims, error) {
	p, err := o.get(ctx)
	if err != nil {
		return Claims{}, err
	}
	tok, err := o.oauth2Config(p).Exchange(o.ctx(ctx), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Claims{}, fmt.Errorf("code exchange: %w", err)
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
	}
	if err := idt.Claims(&c); err != nil {
		return Claims{}, fmt.Errorf("decode id_token claims: %w", err)
	}
	out := Claims{
		Issuer: idt.Issuer, Subject: idt.Subject, Nonce: idt.Nonce,
		Name: c.Name, PreferredUsername: c.PreferredUsername, Email: c.Email,
		Groups: c.Groups, ACR: c.ACR,
	}
	if c.AuthTime > 0 {
		t := time.Unix(c.AuthTime, 0).UTC()
		out.AuthTime = &t
	}
	return out, nil
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
