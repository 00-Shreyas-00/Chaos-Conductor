package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeDB struct{ err error }

func (f fakeDB) Ping(context.Context) error { return f.err }

func newTestServer(t *testing.T, db Pinger) *httptest.Server {
	t.Helper()
	h := NewRouter(Deps{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), DB: db, MaxBodyBytes: 1024, Version: "test"})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func decodeProblem(t *testing.T, resp *http.Response) Problem {
	t.Helper()
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content-type = %q, want application/problem+json", ct)
	}
	var p Problem
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHealthz(t *testing.T) {
	srv := newTestServer(t, fakeDB{err: errors.New("db down")}) // liveness ignores dependencies
	if resp := get(t, srv.URL+"/healthz"); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestReadyz(t *testing.T) {
	if resp := get(t, newTestServer(t, fakeDB{}).URL+"/readyz"); resp.StatusCode != http.StatusOK {
		t.Fatalf("ready: status = %d", resp.StatusCode)
	}
	resp := get(t, newTestServer(t, fakeDB{err: errors.New("dial tcp 10.0.0.5:5432: secret-host-detail")}).URL+"/readyz")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("not ready: status = %d", resp.StatusCode)
	}
	if p := decodeProblem(t, resp); strings.Contains(p.Detail, "secret-host-detail") {
		t.Fatal("internal error details leaked to client")
	}
}

// The API must be deny-by-default: every /api/v1 path, known or unknown, any method,
// returns 401 while no authentication mechanism exists.
func TestAPIv1DenyByDefault(t *testing.T) {
	srv := newTestServer(t, fakeDB{})
	cases := []struct{ method, path string }{
		{"GET", "/api/v1/me"},
		{"GET", "/api/v1/experiments"},
		{"POST", "/api/v1/experiments"},
		{"POST", "/api/v1/execute"},
		{"DELETE", "/api/v1/audit"},
		{"GET", "/api/v1/"},
	}
	for _, c := range cases {
		req, _ := http.NewRequest(c.method, srv.URL+c.path, strings.NewReader(`{"command":"kubectl delete pods --all"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer forged") // bearer tokens are not an accepted credential
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s: status = %d, want 401", c.method, c.path, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestSecurityHeadersAndRequestID(t *testing.T) {
	srv := newTestServer(t, fakeDB{})
	req, _ := http.NewRequest("GET", srv.URL+"/healthz", nil)
	req.Header.Set("X-Request-Id", "attacker-controlled-id")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	want := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
		"Referrer-Policy":         "no-referrer",
		"Cache-Control":           "no-store",
	}
	for k, v := range want {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	id := resp.Header.Get("X-Request-Id")
	if len(id) != 32 || strings.Contains(id, "attacker") {
		t.Errorf("request id must be server-generated 32 hex chars, got %q", id)
	}
}

func TestNotFoundAndMethodNotAllowedAreProblems(t *testing.T) {
	srv := newTestServer(t, fakeDB{})
	if p := decodeProblem(t, get(t, srv.URL+"/nope")); p.Status != http.StatusNotFound {
		t.Fatalf("status = %d", p.Status)
	}
	resp, err := http.Post(srv.URL+"/healthz", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if p := decodeProblem(t, resp); p.Status != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", p.Status)
	}
}

func TestPanicIsGeneric500(t *testing.T) {
	h := recoverer(slog.New(slog.NewJSONHandler(io.Discard, nil)))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom: secret internals")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "secret internals") {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMaxBody(t *testing.T) {
	var readErr error
	h := maxBody(10)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("x", 11))))
	var mbe *http.MaxBytesError
	if !errors.As(readErr, &mbe) {
		t.Fatalf("expected MaxBytesError, got %v", readErr)
	}
}
