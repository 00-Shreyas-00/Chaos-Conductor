package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
)

// tokenLen is the length of a base64url-encoded 32-byte random token.
const tokenLen = 43

// newToken returns 256 bits of CSPRNG output, base64url-encoded without padding.
func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error (Go ≥ 1.24)
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashToken returns SHA-256(token). Only hashes of session tokens and OAuth state values are
// stored, so read access to the database does not yield usable sessions.
func hashToken(t string) []byte {
	h := sha256.Sum256([]byte(t))
	return h[:]
}

// SafeReturnTo accepts only same-origin, relative application paths and returns "/" for
// anything else, preventing open redirects after login.
func SafeReturnTo(s string) string {
	if s == "" || len(s) > 512 || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") ||
		strings.ContainsAny(s, "\\\r\n\t") {
		return "/"
	}
	u, err := url.Parse(s)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil {
		return "/"
	}
	// Never bounce back into auth or API endpoints (loops, unexpected side effects).
	for _, p := range []string{"/auth/", "/api/", "/healthz", "/readyz"} {
		if strings.HasPrefix(u.Path, p) {
			return "/"
		}
	}
	return s
}
