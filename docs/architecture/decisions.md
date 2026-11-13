# KubeChaos — Open Architectural Decisions

Status: **RESOLVED 2026-11-12.** Accepted decisions become ADRs under `docs/architecture/adr/`.

| # | Resolution |
|---|-----------|
| D1 | Accepted: BFF sessions |
| D2 | Accepted: in-cluster ChaosPolicy, control plane read-only |
| D3 | Accepted: double enforcement |
| **D4** | **Changed:** build a **separate Approval Service** now. Head Developers / Dev Team leads approve execution. The operator verifies signed approval attestations. See architecture.md §15. |
| D5–D7 | Accepted as recommended |
| **D8** | **Confirmed:** the UI can stop experiments and engage the lock. Lock *release* stays CLI-only. |
| D9, D10 | Accepted as recommended |
| **D11** | **Confirmed:** step-up + four-eyes approval, production clusters **in scope for v1** |
| D12, D13 | Accepted as recommended (no SIEM named → stdout JSON for now) |
| **D14** | **Refined:** Prometheus is an **optional** observability provider. Core criteria use the Kubernetes API only. PromQL is generated only from server-side templates and never accepted from users, under any circumstance. |
| D15 | Accepted: devcontainer (WSL2 works too) |
| D16, D17 | Accepted as recommended |
| D6 | Default: never kill the last ready replica (policy may relax per environment) |

Legend: 🔴 security-critical · 🟡 significant · ⚪ tooling

---

### D1 🔴 Session model: BFF (server-side tokens + cookie) vs SPA holds OIDC tokens
- **Recommend BFF.** The Go control plane is the OIDC confidential client, and the
  browser gets only an HttpOnly `__Host-` cookie.
- **Why:** tokens are unreachable by XSS or malicious npm deps (T3). `EventSource` (SSE)
  cannot send bearer headers, so cookies are needed anyway. Session revocation is
  server-side.
- **Cost:** CSRF must be handled (SameSite=Strict + header token + Origin check), and the
  control plane is stateful about sessions (DB table).

### D2 🔴 Where the authoritative experiment policy lives
- **Recommend: in-cluster `ChaosPolicy` CRD, written only by cluster admins (Helm/GitOps).**
  The control plane has read-only access. The DB is not authoritative for policy.
- **Why:** the brief assumes the web tier can be compromised. If policy were in the DB,
  compromising the API would also compromise the limits. Here the cluster owner sets the
  ceiling.
- **Cost:** you cannot edit policy from the web UI. A policy change is a cluster-admin
  action (which is arguably correct for a security control).

### D3 🔴 Double enforcement (control plane + operator webhook + operator reconcile)
- **Recommend yes**, using one shared Go evaluator package run independently in each
  tier. The webhook uses `failurePolicy: Fail`.
- **Cost:** the operator must be running for any experiment to be created (fail closed,
  as intended).

### D4 🔴 What the operator trusts about *who* asked
In dev/CRD mode the operator cannot verify that a real user approved an experiment, since
`spec.requestedBy` is asserted by the control plane.
- **Recommend for MVP:** the operator trusts nothing about identity. It enforces only
  policy, lock, RBAC and opt-in, and those caps are the security boundary. **Critical-risk
  primitives (NodeDrain, NodeCordon, network faults affecting nodes) are rejected by the
  operator until D4b exists.**
- **D4b (later):** the operator verifies an approval attestation that a compromised
  control plane cannot mint. Options: (a) a Keycloak-signed token bound to the spec hash
  via token exchange, verified by the operator against IdP JWKS; (b) a second approver's
  signature from a separate approval service. Choose before adding critical primitives.

### D5 🔴 Target opt-in
- **Recommend: a namespace is targetable only if** labelled
  `chaos.kubechaos.io/enabled=true` **and** the Helm chart has been told to create the
  operator RoleBinding there. Workloads can additionally opt out with
  `chaos.kubechaos.io/protected=true`. Built-in protected namespaces cannot be overridden.
- **Alternative:** deny-list only (target anything except kube-system…). This is
  rejected because it is not fail-closed.

### D6 🟡 PodKill semantics
- **Recommend:** `PodKill` = `DELETE pod` with configurable grace period (true failure
  simulation, ignores PDBs). The operator additionally refuses if it would drop the
  workload below policy `minHealthyReplicas` (default: never kill the last ready
  replica). `PodEviction` (respects PDBs) comes later as a separate primitive.
- **Question for you:** is "never kill the last ready replica" the right default, or do
  you want total-outage experiments possible when policy allows?

### D7 🔴 Execution semantics on operator crash
- **Recommend at-most-once.** Record the intent before acting. On restart with an intent
  but no result, mark the step Unknown and abort; never re-run a destructive action.
- **Cost:** an occasional experiment ends `Unknown` instead of completing.

### D8 🔴 Emergency stop / lock release authority
- **Recommend:** a cluster-scoped `ChaosLock` CRD where the presence of any object means
  locked. The web UI and control plane can **engage** (create) but **cannot release**
  (no delete RBAC). Release happens only via `kubechaosctl unlock` with the break-glass
  kubeconfig on the control node. `--hard` also scales the operator to 0 and removes its
  RoleBindings.
- **Question for you:** should the web UI admin be able to engage the lock at all, or is
  the lock CLI-only? (Recommend: UI can engage, since stopping is cheap to allow.)

### D9 🟡 Multi-cluster connectivity direction (phase 2)
- **Recommend: the agent dials out** to the control plane (gRPC bidi stream, mTLS,
  cluster ID in cert SAN). Clusters expose no inbound endpoint, and the control plane
  never holds per-cluster kubeconfigs.
- **Alternative:** the control plane dials into each cluster with stored kubeconfigs. This
  is rejected because it puts N clusters' credentials in the most exposed tier.

### D10 🟡 Authorization data source
- **Recommend:** coarse roles come from Keycloak groups (viewer / experimenter / approver
  / admin / auditor). Fine-grained scopes `(cluster, namespace-pattern)` live in DB role
  bindings that only admins edit (audited, no self-grant). The in-cluster policy is the
  ceiling regardless.
- **Alternative:** encode scopes as Keycloak groups such as `chaos:dev:payments`. Simpler,
  but it gets clumsy at scale and is harder to audit within the app.

### D11 🔴 Step-up triggers and four-eyes approval
- **Recommend step-up (Keycloak LoA `acr=2`, `max_age=0`, WebAuthn or TOTP)** when any of
  these hold: primitive risk ≥ High, cluster environment = production, or affected
  targets > 1 (configurable per policy).
- **Recommend four-eyes** (a second user with `approver` role, who cannot be the
  requester) for **any production** experiment.
- **Question for you:** do you have production clusters in scope for v1, or is v1
  dev/staging only? This affects how much of D4b/D11 is needed early.

### D12 🟡 Audit integrity and external sink
- **Recommend:** DB grants (INSERT/SELECT only) + blocking trigger + SHA-256 hash chain +
  both tiers emitting JSON audit logs to stdout for collection (Loki/ELK/cloud logging),
  with periodic anchoring of the head hash to that sink. WORM storage (S3 Object Lock or
  similar) later for production.
- **Question for you:** is there an existing log platform/SIEM we should target?

### D13 🟡 Implementation approach for later primitives (needed before CPUStress/MemoryStress/ContainerRestart)
- **Recommend: ephemeral containers** (`pods/ephemeralcontainers` patch) running a pinned,
  in-house stress image (digest enforced by a ValidatingAdmissionPolicy). For
  ContainerRestart, use `targetContainerName` to share the PID namespace and send
  SIGKILL to PID 1. **No privileged node DaemonSet** (Chaos Mesh-style chaos-daemon) in v1.
- **Trade-off:** ephemeral containers cannot be removed (only exit) and cannot set
  resource limits, so stress must be self-limiting and time-boxed in-process.
  `pods/ephemeralcontainers` is a powerful permission (code execution in the target pod's
  context), which is why the image pinning is mandatory.
- Not needed for PodKill. It can be decided later, but flagged now because it is the
  largest future RBAC expansion.

### D14 🔴 Success-criteria metrics
- **Recommend a fixed metric catalog** (`available_replicas`, `ready_replicas`,
  `recovery_time`, `restart_count`, plus Prometheus-backed `http_error_rate`,
  `http_p99_latency` from **server-side PromQL templates** with typed, validated
  parameters such as a service label). Users cannot supply raw PromQL.
- **Question for you:** is Prometheus available in target clusters, and what are the
  standard HTTP metric names (e.g. Istio, ingress-nginx, OTel semconv)?

### D15 ⚪ Development environment on Windows
`go`, `kind`, `helm`, and `make` are not installed. Docker, kubectl and Node are.
- **Recommend: a VS Code devcontainer (or WSL2)** with Go, kind, helm, make, kubebuilder
  tools and the Angular CLI. `make dev` then works the same on any machine and in CI.
- **Alternative:** native Windows with Scoop/winget installs plus a `Taskfile.yml`
  instead of Make. This works, but scripts diverge from CI.

### D16 ⚪ Tooling choices (low risk, will proceed unless you object)
- Go: current stable, Go workspaces; chi; pgx + sqlc; goose migrations; `log/slog` JSON;
  `coreos/go-oidc` + `golang.org/x/oauth2`; oapi-codegen (server types from OpenAPI).
- Operator: kubebuilder scaffold, controller-runtime, envtest for integration tests.
- Frontend: current Angular LTS, standalone components, Material, signals, typed reactive
  forms; API client generated from OpenAPI.
- Proxy (dev): Caddy (automatic local TLS). Prod: your choice of ingress.
- CRD group `chaos.kubechaos.io`, version `v1alpha1`.

### D17 🔴 Operator RBAC shape
- **Recommend: RoleBindings per opted-in namespace** (pods get/list/watch/delete etc.)
  rather than a ClusterRoleBinding with pod delete. The namespace allow-list is then
  enforced by Kubernetes itself, not only by our code.
- **Cost:** opting a namespace in requires a Helm value change or a cluster-admin action
  (deliberate friction).
