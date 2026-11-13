# KubeChaos

A security-conscious, Kubernetes-native chaos testing platform. Users create **typed,
policy-bounded** failure experiments; a cluster-local operator is the only component that
acts on Kubernetes. There is no shell and no `kubectl` passthrough.

**Status:** foundation phase. Architecture accepted; dev environment in place; no
application code yet.

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
make status
make dev-down   # stop (keeps data)
make dev-reset  # destroy data volumes and cluster
```

Without VS Code, use the Dev Containers CLI: `npx @devcontainers/cli up --workspace-folder .`,
then `docker exec -it -u vscode -w /workspaces/<repo-dir> <container> bash`. On Windows the
CLI has been seen to hang after "Container started" without running `postCreateCommand`. If
that happens, run `bash .devcontainer/post-create.sh` inside the container. From Git Bash,
set `MSYS_NO_PATHCONV=1` so Linux paths are not rewritten.

`.env` holds randomly generated **dev-only** secrets and is gitignored. All services bind
to `127.0.0.1` only.
