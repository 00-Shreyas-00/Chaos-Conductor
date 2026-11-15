# KubeChaos

A security-conscious, Kubernetes-native chaos testing platform. Users create **typed,
policy-bounded** failure experiments; a cluster-local operator is the only component that
acts on Kubernetes. There is no shell and no `kubectl` passthrough.

**Status:** foundation phase. Done: architecture, dev environment, minimal Angular SPA,
minimal Go API (deny-by-default), PostgreSQL migrations with append-only audit table,
Keycloak/OIDC login (backend-for-frontend, server-side sessions, CSRF), minimal hardened
Kubernetes operator (identity, leader election, least-privilege RBAC, NetworkPolicy),
`ChaosExperiment` CRD with API-server-enforced validation, and the first fault primitive,
**PodKill** (development clusters and opted-in namespaces only, at-most-once, never the
last Ready replica).
Next: hardened experiment lifecycle.

### Operator (kind)
```bash
make operator-image operator-deploy   # build distroless image, load into kind, install chart
make operator-verify                  # assert effective RBAC (kubectl auth can-i matrix)
make rbac-check                       # rendered RBAC must equal the reviewed snapshot
make crd-verify                       # ChaosExperiment validation/immutability/admission, live
make podkill-verify                   # 10 PodKill scenarios against deploy/demo (deletes demo pods)
make generate                         # regenerate deepcopy + CRD from pkg/chaosapi types
```
The operator reads its cluster identity from the immutable ConfigMap
`kubechaos-system/kubechaos-cluster-identity` (Helm values `clusterIdentity.*`) and refuses
to start without a valid one.

### Dev users
The imported `kubechaos` realm seeds `alice` (experimenter), `bob` (approver), `carol`
(admin), `dave` (auditor), `eve` (viewer) and `mallory` (no roles). They share the password
in `.env` → `KEYCLOAK_DEV_USER_PASSWORD`. The Keycloak admin console is at
http://localhost:8180 (`KEYCLOAK_ADMIN_USER` / `KEYCLOAK_ADMIN_PASSWORD`). After changing
`deploy/keycloak/import/`, run `make keycloak-reset` to re-import.

## Documentation
- [Architecture](docs/architecture/architecture.md)
- [Resolved decisions](docs/architecture/decisions.md)
- [Threat model](docs/security/threat-model.md)

## Repository layout
| Path | Purpose |
|------|---------|
| `frontend/` | Angular SPA (`app`) and Approver UI (`approver`); client-side only, no SSR |
| `backend/` | Go control plane: API, authN/Z, policy pre-check, audit, SSE |
| `approver/` | Go Approval Service: four-eyes approvals, signs attestations |
| `operator/` | Go operator: CRDs, admission webhook, reconciler, fault primitives |
| `pkg/chaosapi/` | Shared Go module: CRD types, fault schemas, policy evaluator, metric templates |
| `cli/` | `kubechaosctl`: emergency stop / unlock / audit verify (break-glass path) |
| `api/openapi/` | OpenAPI specification (source of truth for API types) |
| `deploy/` | kind, Helm, Keycloak realm, Postgres init |
| `docs/` | Architecture, security, experiment docs |

## Local development
Use the devcontainer (VS Code: *Reopen in Container*) or WSL2 with Go, Node 22, Docker,
kind, kubectl, helm and make installed.

```bash
make dev        # generate .env, start Postgres + Keycloak, create kind cluster
make migrate    # apply DB migrations (migrator role)
make api        # control plane on 127.0.0.1:8080 (app role; refuses over-privileged roles)
make fe         # SPA on 127.0.0.1:4200, proxies /api to the API
make test test-integration test-e2e fe-test fe-build
make sessions-revoke ARGS="--role admin"   # break-glass session revocation
make status
make dev-down   # stop (keeps data)
make dev-reset  # destroy data volumes and cluster
```

Without VS Code, use the Dev Containers CLI: `npx @devcontainers/cli up --workspace-folder .`,
then `docker exec -it -u vscode -w /workspaces/<repo-dir> <container> bash`. On Windows the
CLI has been seen to hang after "Container started" without running `postCreateCommand`. If
that happens, run `bash .devcontainer/post-create.sh` inside the container. From Git Bash,
set `MSYS_NO_PATHCONV=1` so Linux paths are not rewritten.

After a devcontainer rebuild, the kind cluster may come back with duplicate node IPs and
never become Ready (kind does not support Docker daemon restarts reliably). It holds no
state, so recreate it with `make kind-down dev`.

`.env` holds randomly generated **dev-only** secrets and is gitignored. All services bind
to `127.0.0.1` only.
