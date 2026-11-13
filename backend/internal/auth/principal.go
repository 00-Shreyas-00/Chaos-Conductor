package auth

import (
	"context"
	"slices"
	"time"
)

// Principal is the authenticated caller of a request, established from a server-side session.
type Principal struct {
	IdentityID  string
	Issuer      string
	Subject     string
	DisplayName string
	Roles       []Role
	// ACR is the authentication context class reported by the IdP at login
	// (Keycloak: "1" = interactive login, "0" = SSO cookie). Used for step-up later.
	ACR       string
	AuthTime  *time.Time
	CSRFToken string
}

// HasRole reports whether the principal holds role r.
func (p Principal) HasRole(r Role) bool { return slices.Contains(p.Roles, r) }

type principalKey struct{}

// WithPrincipal stores p in ctx.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the principal stored in ctx, if any.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}
