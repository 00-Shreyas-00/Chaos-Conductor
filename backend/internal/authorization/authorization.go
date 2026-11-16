// Package authorization answers "what may this user do?" (architecture §5). It is a closed,
// explicit table: an action not granted to any of the principal's roles is denied.
// "Is this specific experiment permitted?" is a separate question answered by ChaosPolicy.
package authorization

import (
	"slices"

	"github.com/kubechaos/kubechaos/backend/internal/auth"
)

// Action is something a principal may attempt.
type Action string

const (
	ReadExperiments  Action = "experiments.read"
	CreateExperiment Action = "experiments.create"
	CancelOwn        Action = "experiments.cancel.own"
	CancelAny        Action = "experiments.cancel.any"
	ReadClusters     Action = "clusters.read"
	ReadCatalog      Action = "catalog.read"
	ReadLock         Action = "lock.read"
	EngageLock       Action = "lock.engage"
	ReadAudit        Action = "audit.read"
)

var read = []Action{ReadExperiments, ReadClusters, ReadCatalog, ReadLock}

// grants maps roles to actions. Separation of duties: the auditor reads the audit log and
// nothing else; admins cannot read the audit log; nobody can unlock from the web tier.
var grants = map[auth.Role][]Action{
	auth.RoleViewer:       read,
	auth.RoleExperimenter: append(slices.Clone(read), CreateExperiment, CancelOwn),
	auth.RoleApprover:     append(slices.Clone(read), CancelAny),
	auth.RoleAdmin:        append(slices.Clone(read), CancelAny, EngageLock),
	auth.RoleAuditor:      {ReadAudit},
}

// Allowed reports whether any of the principal's roles grants the action.
func Allowed(p auth.Principal, a Action) bool {
	for _, r := range p.Roles {
		if slices.Contains(grants[r], a) {
			return true
		}
	}
	return false
}

// CanCancel reports whether p may cancel an experiment requested by (ownerIssuer, ownerSubject).
func CanCancel(p auth.Principal, ownerIssuer, ownerSubject string) bool {
	if Allowed(p, CancelAny) {
		return true
	}
	return Allowed(p, CancelOwn) && p.Issuer == ownerIssuer && p.Subject == ownerSubject
}
