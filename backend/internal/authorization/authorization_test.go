package authorization

import (
	"testing"

	"github.com/kubechaos/kubechaos/backend/internal/auth"
)

func p(roles ...auth.Role) auth.Principal {
	return auth.Principal{Issuer: "https://idp", Subject: "alice", Roles: roles}
}

func TestMatrix(t *testing.T) {
	all := []Action{ReadExperiments, CreateExperiment, CancelOwn, CancelAny, ReadClusters, ReadCatalog, ReadLock, EngageLock, ReadAudit}
	want := map[auth.Role][]Action{
		auth.RoleViewer:       {ReadExperiments, ReadClusters, ReadCatalog, ReadLock},
		auth.RoleExperimenter: {ReadExperiments, CreateExperiment, CancelOwn, ReadClusters, ReadCatalog, ReadLock},
		auth.RoleApprover:     {ReadExperiments, CancelAny, ReadClusters, ReadCatalog, ReadLock},
		auth.RoleAdmin:        {ReadExperiments, CancelAny, ReadClusters, ReadCatalog, ReadLock, EngageLock},
		auth.RoleAuditor:      {ReadAudit},
	}
	for role, allowed := range want {
		for _, a := range all {
			exp := false
			for _, x := range allowed {
				if x == a {
					exp = true
				}
			}
			if got := Allowed(p(role), a); got != exp {
				t.Errorf("%s / %s: got %v want %v", role, a, got, exp)
			}
		}
	}
}

func TestNoRolesNothingAllowed(t *testing.T) {
	for _, a := range []Action{ReadExperiments, CreateExperiment, ReadAudit, EngageLock} {
		if Allowed(p(), a) {
			t.Errorf("principal without roles allowed %s", a)
		}
	}
	if Allowed(p("superuser"), ReadExperiments) {
		t.Error("unknown roles must grant nothing")
	}
}

func TestSeparationOfDuties(t *testing.T) {
	if Allowed(p(auth.RoleAdmin), ReadAudit) {
		t.Error("admins must not read the audit log")
	}
	if Allowed(p(auth.RoleAuditor), ReadExperiments) || Allowed(p(auth.RoleAuditor), EngageLock) {
		t.Error("auditors read audit only")
	}
	if Allowed(p(auth.RoleApprover), CreateExperiment) {
		t.Error("approvers do not request experiments")
	}
}

func TestCanCancel(t *testing.T) {
	if !CanCancel(p(auth.RoleExperimenter), "https://idp", "alice") {
		t.Error("experimenter cancels own")
	}
	if CanCancel(p(auth.RoleExperimenter), "https://idp", "bob") {
		t.Error("experimenter must not cancel others")
	}
	if CanCancel(p(auth.RoleExperimenter), "https://other-idp", "alice") {
		t.Error("same subject at another issuer is a different person")
	}
	if !CanCancel(p(auth.RoleAdmin), "https://idp", "bob") || !CanCancel(p(auth.RoleApprover), "https://idp", "bob") {
		t.Error("admin and approver cancel any")
	}
	if CanCancel(p(auth.RoleViewer), "https://idp", "alice") {
		t.Error("viewer cannot cancel")
	}
}
