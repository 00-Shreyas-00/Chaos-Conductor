package logging

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsIm5vbmNlIjoieCJ9.c2lnbmF0dXJlLXZhbHVlLWhlcmU"

func TestRedact(t *testing.T) {
	cases := map[string]struct{ in, secret string }{
		"bare jwt":           {"verify failed for " + jwt, jwt},
		"jwe 5 parts":        {"token eyJhbGciOiJSU0EiLCJlbmMiOiJBMjU2In0.QUJDREVG.SVYxMjM0.Q0lQSEVS.VEFHVEFH end", "QUJDREVG"},
		"callback url code":  {"GET /auth/callback?state=s3cr3tState&code=c0de-value&session_state=abc", "c0de-value"},
		"callback url state": {"GET /auth/callback?state=s3cr3tState&code=x", "s3cr3tState"},
		"form body":          {"grant_type=authorization_code&code=AUTHCODE123&code_verifier=VERIFIERxyz&client_secret=CS", "VERIFIERxyz"},
		"client secret form": {"client_id=kubechaos-api&client_secret=TopSecretValue", "TopSecretValue"},
		"token json":         {`oauth2: "invalid_grant" {"access_token":"AT-VALUE","id_token":"IDT","error":"x"}`, "AT-VALUE"},
		"refresh token json": {`{"refresh_token": "RT-VALUE"}`, "RT-VALUE"},
		"bearer header":      {"Authorization: Bearer abc.def-ghi_jkl", "abc.def-ghi_jkl"},
		"session cookie":     {"Cookie: __Host-kc_session=SESSIONTOKENVALUE; other=1", "SESSIONTOKENVALUE"},
		"postgres dsn":       {"connect postgres://kubechaos_app:DbPassw0rd@127.0.0.1:5432/kubechaos failed", "DbPassw0rd"},
		"csrf token json":    {`{"csrfToken":"CSRFVALUE"}`, "CSRFVALUE"},
		"logout token form":  {"logout_token=" + jwt, "c2lnbmF0dXJl"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			out := Redact(c.in)
			if strings.Contains(out, c.secret) {
				t.Fatalf("secret survived redaction:\n in: %s\nout: %s", c.in, out)
			}
			if !strings.Contains(out, Redacted) {
				t.Fatalf("no redaction marker: %s", out)
			}
		})
	}
}

func TestRedactKeepsOrdinaryText(t *testing.T) {
	for _, s := range []string{
		"login succeeded", "GET /api/v1/me", "role holds UPDATE on audit.events",
		"http://localhost:8180/realms/kubechaos", "invalid_grant", "subject d427ab39-629d-453a-9432-9766f95d10af",
	} {
		if got := Redact(s); got != s {
			t.Errorf("Redact(%q) = %q", s, got)
		}
	}
}

type stringer string

func (s stringer) String() string { return string(s) }

func TestLoggerRedactsAttributesErrorsAndMessages(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, slog.LevelDebug)
	l.Info("callback ?code=MSGCODE",
		slog.String("client_secret", "KeyedSecret"),
		slog.String("Cookie", "plain-cookie-value"),
		slog.Any("error", fmt.Errorf("exchange: %w", errors.New(`{"id_token":"ERRIDT"} `+jwt))),
		slog.Any("url", stringer("https://idp/auth?state=STRINGERSTATE")),
		slog.Any("raw", []byte("RAWBYTES")),
		slog.Group("req", slog.String("authorization", "Bearer GROUPED")),
		slog.String("subject", "alice"),
	)
	out := buf.String()
	for _, secret := range []string{"MSGCODE", "KeyedSecret", "plain-cookie-value", "ERRIDT", "c2lnbmF0dXJl", "STRINGERSTATE", "RAWBYTES", "GROUPED"} {
		if strings.Contains(out, secret) {
			t.Errorf("%q leaked into log: %s", secret, out)
		}
	}
	if !strings.Contains(out, `"subject":"alice"`) {
		t.Errorf("ordinary attributes must survive: %s", out)
	}
}
