package auth

import (
	"slices"
	"strings"
)

// Role is a coarse application role derived from IdP group membership (D10).
// Fine-grained scopes (cluster, namespace) are added by the authorization package later.
type Role string

const (
	RoleViewer       Role = "viewer"
	RoleExperimenter Role = "experimenter"
	RoleApprover     Role = "approver"
	RoleAdmin        Role = "admin"
	RoleAuditor      Role = "auditor"
)

// GroupPrefix is the required prefix of IdP groups that map to roles.
const GroupPrefix = "kubechaos-"

var knownRoles = map[string]Role{
	"viewer":       RoleViewer,
	"experimenter": RoleExperimenter,
	"approver":     RoleApprover,
	"admin":        RoleAdmin,
	"auditor":      RoleAuditor,
}

// RolesFromGroups maps IdP groups to roles using an explicit allow-list. Unknown groups,
// nested group paths and anything without the exact prefix are ignored (fail closed: an
// unrecognised group grants nothing). The result is sorted and de-duplicated.
func RolesFromGroups(groups []string) []Role {
	set := map[Role]struct{}{}
	for _, g := range groups {
		g = strings.TrimPrefix(g, "/") // tolerate full-path group claims for top-level groups
		name, ok := strings.CutPrefix(g, GroupPrefix)
		if !ok {
			continue
		}
		if r, ok := knownRoles[name]; ok {
			set[r] = struct{}{}
		}
	}
	out := make([]Role, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	slices.Sort(out)
	return out
}
