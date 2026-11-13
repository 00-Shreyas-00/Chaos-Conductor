// Package logging builds the structured JSON logger with a redaction layer that keeps
// credentials and OIDC material out of logs, even when they appear inside error strings
// produced by third-party libraries.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
)

// Redacted replaces sensitive values.
const Redacted = "[REDACTED]"

// sensitiveKeys are attribute keys whose values are always replaced, whatever their content.
var sensitiveKeys = map[string]bool{
	"password": true, "secret": true, "client_secret": true, "token": true,
	"id_token": true, "access_token": true, "refresh_token": true, "logout_token": true,
	"code": true, "code_verifier": true, "state": true, "nonce": true,
	"cookie": true, "set-cookie": true, "authorization": true, "csrf": true, "csrf_token": true,
	"session": true, "session_token": true, "dsn": true, "database_url": true,
}

var patterns = []struct {
	re   *regexp.Regexp
	repl string
}{
	// JWT / JWS / JWE compact serialisations (ID tokens, access tokens, logout tokens).
	{regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*(\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*)?`), Redacted},
	// OAuth/OIDC parameters in URLs and form bodies.
	{regexp.MustCompile(`(?i)\b(code|state|nonce|id_token|access_token|refresh_token|logout_token|client_secret|code_verifier|code_challenge|session_state|token)=([^&\s"'<>]+)`), "${1}=" + Redacted},
	// The same names as JSON members.
	{regexp.MustCompile(`(?i)"(code|state|nonce|id_token|access_token|refresh_token|logout_token|client_secret|code_verifier|csrfToken|password)"\s*:\s*"[^"]*"`), `"${1}":"` + Redacted + `"`},
	// HTTP authorization schemes.
	{regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/-]+=*`), "${1} " + Redacted},
	// Session cookie values.
	{regexp.MustCompile(`(__Host-kc_session=)[^;\s"']+`), "${1}" + Redacted},
	// Passwords embedded in connection URLs (postgres://user:pass@host).
	{regexp.MustCompile(`([a-z][a-z0-9+.-]*://[^:/\s@]+:)[^@\s/]+@`), "${1}" + Redacted + "@"},
}

// Redact removes credentials and OIDC material from s.
func Redact(s string) string {
	for _, p := range patterns {
		s = p.re.ReplaceAllString(s, p.repl)
	}
	return s
}

// ReplaceAttr is a slog.HandlerOptions.ReplaceAttr that redacts sensitive attributes.
// Errors and Stringers are rendered to strings first so their text can be scrubbed.
func ReplaceAttr(_ []string, a slog.Attr) slog.Attr {
	if sensitiveKeys[strings.ToLower(a.Key)] {
		return slog.String(a.Key, Redacted)
	}
	switch a.Value.Kind() {
	case slog.KindString:
		a.Value = slog.StringValue(Redact(a.Value.String()))
	case slog.KindAny:
		switch v := a.Value.Any().(type) {
		case error:
			a.Value = slog.StringValue(Redact(v.Error()))
		case fmt.Stringer:
			a.Value = slog.StringValue(Redact(v.String()))
		case []byte:
			a.Value = slog.StringValue(Redacted) // raw bytes are never logged
		}
	}
	return a
}

// New returns a JSON logger with redaction applied to every attribute (including the message).
func New(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.MessageKey && len(groups) == 0 {
				return slog.String(a.Key, Redact(a.Value.String()))
			}
			return ReplaceAttr(groups, a)
		},
	}))
}
