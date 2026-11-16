package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kubechaos/kubechaos/backend/internal/auth"
	"github.com/kubechaos/kubechaos/backend/internal/auth/authtest"
)

// multiUser is one router with several logged-in users.
type multiUser struct {
	h   http.Handler
	as  *authtest.MemStore
	idp *authtest.FakeIdP
}

func newMultiUser() *multiUser {
	as, idp := authtest.NewMemStore(), &authtest.FakeIdP{}
	h, _, _ := newRouterWithCluster(fakeDB{}, newAuth(as, idp))
	return &multiUser{h: h, as: as, idp: idp}
}

func (m *multiUser) login(t *testing.T, subject string, groups ...string) session {
	t.Helper()
	at := time.Now().Add(-time.Minute)
	m.idp.Claims = auth.Claims{Issuer: "https://idp.test", Subject: subject, Name: subject, Groups: groups, ACR: "1", AuthTime: &at}
	rec := httptest.NewRecorder()
	m.h.ServeHTTP(rec, httptest.NewRequest("GET", "/auth/login", nil))
	rec = httptest.NewRecorder()
	m.h.ServeHTTP(rec, httptest.NewRequest("GET", "/auth/callback?code=c&state="+url.QueryEscape(m.idp.LastState), nil))
	s := session{h: m.h}
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.SessionCookie {
			s.cookie = c
		}
	}
	if s.cookie == nil {
		t.Fatal("login failed")
	}
	var me currentUser
	_ = json.Unmarshal(s.do("GET", "/api/v1/me", "").Body.Bytes(), &me)
	s.csrf = me.CSRFToken
	return s
}

func scheduleBody(name string) string {
	exp := time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	return `{"name":"` + name + `","description":"web pods","minInterval":"1h","meanInterval":"2h","confirm":true,
	  "window":{"days":["Mon","Tue","Wed","Thu","Fri"],"from":"10:00","to":"16:00","timeZone":"UTC"},"expiresAt":"` + exp + `",
	  "template":{"maxDuration":"2m","steps":[{"fault":{"type":"PodKill","target":{"namespace":"demo","selector":{"app":"web"}},"podKill":{"count":1}}}]}}`
}

func TestScheduleEndpoints(t *testing.T) {
	m := newMultiUser()
	alice := m.login(t, "alice", "kubechaos-experimenter")
	eve := m.login(t, "eve", "kubechaos-viewer")
	bob := m.login(t, "bob", "kubechaos-approver")

	if rec := eve.do("POST", "/api/v1/schedules", scheduleBody("by-viewer")); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer create: %d", rec.Code)
	}
	noCSRF := alice
	noCSRF.csrf = ""
	if rec := noCSRF.do("POST", "/api/v1/schedules", scheduleBody("no-csrf")); rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF: %d", rec.Code)
	}
	if rec := alice.do("POST", "/api/v1/schedules", strings.Replace(scheduleBody("x"), `"confirm":true`, `"confirm":true,"owner":"bob"`, 1)); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", rec.Code)
	}
	if rec := alice.do("POST", "/api/v1/schedules", strings.Replace(scheduleBody("bad-ns"), `"demo"`, `"ledger"`, 1)); rec.Code != http.StatusUnprocessableEntity || code(rec) != "policy_violation" {
		t.Fatalf("policy: %d %s", rec.Code, rec.Body)
	}

	rec := alice.do("POST", "/api/v1/schedules", scheduleBody("web-monkey"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var s struct {
		ID, State, OwnerSubject string
		NextRunAt               *time.Time
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &s)
	if s.State != "Active" || s.OwnerSubject != "alice" || s.NextRunAt == nil {
		t.Fatalf("created: %s", rec.Body)
	}
	if rec := eve.do("GET", "/api/v1/schedules", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), s.ID) {
		t.Fatalf("list: %d", rec.Code)
	}
	if rec := eve.do("GET", "/api/v1/schedules/"+s.ID, ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"runs":[]`) {
		t.Fatalf("get: %d %s", rec.Code, rec.Body)
	}
	if rec := eve.do("POST", "/api/v1/schedules/"+s.ID+"/pause", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer pause: %d", rec.Code)
	}
	if rec := bob.do("POST", "/api/v1/schedules/"+s.ID+"/pause", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"state":"Paused"`) {
		t.Fatalf("approver pause: %d %s", rec.Code, rec.Body)
	}
	if rec := bob.do("POST", "/api/v1/schedules/"+s.ID+"/resume", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("approver resume: %d", rec.Code)
	}
	if rec := alice.do("POST", "/api/v1/schedules/"+s.ID+"/resume", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"state":"Active"`) {
		t.Fatalf("owner resume: %d %s", rec.Code, rec.Body)
	}
	if rec := alice.do("DELETE", "/api/v1/schedules/"+s.ID, ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"state":"Deleted"`) {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if rec := alice.do("POST", "/api/v1/schedules/"+s.ID+"/pause", ""); rec.Code != http.StatusConflict {
		t.Fatalf("pause deleted: %d", rec.Code)
	}
	if rec := alice.do("GET", "/api/v1/schedules/not-a-uuid", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown: %d", rec.Code)
	}
}
