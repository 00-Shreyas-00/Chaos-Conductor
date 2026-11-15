# KubeChaos — Architecture Proposal

Status: **ACCEPTED 2026-11-12** (decisions resolved; see `docs/architecture/decisions.md`).
Items marked **[DECISION n]** refer to that file. §15–§16 were added after review.

---

## 0. Current repository state (2026-11-12)

- The directory is empty and is **not** a git repository.
- Local tooling: `docker`, `kubectl`, `node`/`npm` present; **`go`, `kind`, `helm`, `make` absent**.
  Host is Windows 11 → see [DECISION 15] on the dev environment.

---

## 1. Design principles

1. **The internet-facing tier is assumed compromisable.** The thing that limits damage is
   the operator and its in-cluster policy and RBAC, not the API or UI.
2. **Defense in depth on every destructive path.** Each check happens at least twice:
   the control plane checks it (for UX and early denial), and the operator checks it
   (for enforcement). Kubernetes RBAC then bounds what even a buggy operator can do.
3. **Fail closed.** If any input to a decision is missing, unknown, malformed or
   unavailable, the experiment is denied.
4. **Finite, typed vocabulary.** There are only failure primitives with schema-validated
   parameters. There is no shell, no `kubectl` passthrough, no free-form PromQL and no
   user-supplied images.
5. **Every fault is time-bounded by construction.** Each fault expires on its own even
   if the operator, control plane and DB all die mid-experiment (TTLs,
   `activeDeadlineSeconds`, owner references).
6. **Kubernetes is the source of truth for Kubernetes state.** PostgreSQL holds
   application intent, history, results and audit, never a mirror of cluster objects.

---

## 2. Component architecture

```
 Browser (Angular SPA, static files)
   │  HTTPS, session cookie (HttpOnly, Secure, SameSite=Strict) — no tokens in JS
   ▼
 Reverse proxy (TLS termination, HSTS, rate limiting, request size limits, CSP headers)
   │  serves /            → static SPA bundle
   │  routes /api/v1/*    → control plane
   │  routes /auth/*      → control plane (OIDC callback / logout)
   ▼
 Go control plane  (stateless; N replicas)
   ├─ internal/api            chi router, OpenAPI-generated types, request validation
   ├─ internal/auth           OIDC (BFF confidential client), sessions, step-up
   ├─ internal/authorization  RBAC: role × scope(cluster, namespace) × action
   ├─ internal/policy         Reads in-cluster ChaosPolicy; pre-flight evaluation
   ├─ internal/experiments    Experiment model, validation, state machine, scoring
   ├─ internal/faults         Primitive registry (shared schema package with operator)
   ├─ internal/clusters       Cluster registry, cluster identity, connector interface
   ├─ internal/audit          Append-only, hash-chained audit writer
   ├─ internal/events         Per-experiment event fan-out → SSE
   ├─ internal/repository     PostgreSQL (pgx + sqlc), migrations
   └─ internal/config         Typed config, fail-fast on missing values
   │
   │  Dev: Kubernetes API (CRDs, namespace-scoped SA)       ┐ behind a ClusterConnector
   │  Later: mTLS gRPC, agent dials OUT to control plane    ┘ interface [DECISION 9]
   ▼
 Go operator / agent  (one per cluster; controller-runtime)
   ├─ api/v1alpha1            CRDs: ChaosExperiment, ChaosPolicy, ChaosLock
   ├─ webhook/                Validating admission webhook (schema + policy + lock)
   ├─ controllers/            ChaosExperiment reconciler (state machine)
   ├─ faults/                 Primitive implementations (PodKill first)
   ├─ observe/                Watches targets; records timeline; computes metrics
   └─ policy/                 Same evaluation library as the control plane, run independently
   │
   ▼
 Kubernetes API → target workloads
```

Shared code: a small `pkg/chaosapi` module (CRD types, primitive schemas and
**policy evaluation**) is imported by both the control plane and the operator. The
two tiers then run the same evaluation code, each on its own copy of the inputs.

### Repository layout (proposed, keeps your structure)

```
kubechaos/
├── frontend/                 Angular SPA (no SSR)
├── backend/                  Go control plane (cmd/kubechaos-api, internal/…)
├── approver/                 Go Approval Service (separate binary, DB schema, signing key) §15
├── operator/                 Go operator (cmd/manager, api/, controllers/, webhook/, config/)
├── pkg/chaosapi/             Shared Go module: CRD types, fault schemas, policy evaluator
├── cli/                      kubechaosctl (emergency stop, lock/unlock, status)
├── api/openapi/              openapi.yaml (source of truth; Go + TS types generated)
├── deploy/
│   ├── kind/                 kind cluster config, local certs
│   ├── helm/kubechaos/       operator + control plane charts (RBAC documented inline)
│   └── keycloak/             realm export for dev (roles, groups, LoA flows)
├── docs/{architecture,security,experiments}/
├── Makefile
├── docker-compose.dev.yml    Postgres, Keycloak, (proxy) for local dev
└── README.md
```

Material deviation from the suggested layout: `pkg/chaosapi` (shared policy + types) and
`cli/` were added. A Go workspace (`go.work`) ties `backend`, `operator`, `pkg`, `cli` together.

---

## 3. Trust boundaries

See `docs/security/threat-model.md` §2 for the full diagram. In summary:

| # | Boundary | Crossing | What crosses | Enforcement on the receiving side |
|---|----------|----------|--------------|-----------------------------------|
| TB1 | Internet → proxy | HTTPS | Untrusted requests | TLS, rate limits, size limits, WAF-lite |
| TB2 | Browser → control plane | HTTPS + cookie | User intent | Session auth, CSRF, authZ, schema validation, policy pre-check |
| TB3 | IdP ↔ control plane | OIDC back-channel | Identity assertions | Token signature, iss/aud/nonce/exp, PKCE, `acr`/`auth_time` |
| TB4 | Control plane → cluster | K8s API (dev) / mTLS gRPC (later) | Experiment *requests* | Admission webhook + reconciler re-validate everything; control plane RBAC confined to one namespace |
| TB5 | Operator → target workloads | K8s API | Destructive actions | Per-namespace RBAC (RoleBindings only in opted-in namespaces) |
| TB6 | Control plane → PostgreSQL | TLS | App state, audit | Least-privilege DB roles; audit table INSERT/SELECT only |
| TB7 | Admin (SSH/control node) → cluster | kubeconfig | Emergency stop / unlock | Separate break-glass identity, not reachable via web tier |

---

## 4. Authentication flow (OIDC, BFF pattern) [DECISION 1]

```
Browser            Control plane (confidential client)          Keycloak
  │ GET /auth/login ─────▶ create state, nonce, PKCE verifier
  │ ◀──── 302 to Keycloak /authorize (code, S256, state, nonce)
  │ ───────────────── login (password + MFA per realm policy) ───────▶
  │ ◀──────────────── 302 /auth/callback?code&state ─────────────────
  │ GET /auth/callback ───▶ verify state; POST /token (code + verifier + client secret)
  │                         verify ID token sig/iss/aud/nonce/exp
  │                         upsert identity (sub, iss) in DB; map groups → roles
  │                         create server-side session (opaque id, DB/Redis-backed)
  │ ◀──── Set-Cookie: __Host-kc_session=…; HttpOnly; Secure; SameSite=Strict; Path=/
```

- Access/refresh tokens stay **server-side**. The SPA only sees `GET /api/v1/me`
  (subject, display name, roles, auth level).
- Cookie sessions also fit SSE: `EventSource` cannot send `Authorization` headers.
- CSRF: `SameSite=Strict`, plus a required custom header (`X-KubeChaos-CSRF`, double-submit
  token) on every state-changing request, plus an `Origin` check.
- Session: idle timeout 30 min, absolute 8 h, rotated on login and on step-up, server-side
  revocation, and logout performs RP-initiated logout at Keycloak.

**As implemented (foundation step 9):**
- Sessions live in `app.sessions`. Only `SHA-256(token)` is stored, so a database read does
  not yield usable cookies. In-flight logins live in `app.login_requests` (hashed state,
  nonce, PKCE verifier, sanitised `returnTo`) and are consumed atomically
  (`DELETE … RETURNING`), so each state value works exactly once.
- The application stores **no OIDC tokens at all**: it does not need access or refresh
  tokens yet. Roles are taken from the ID token's `groups` claim at login and fixed for
  the session's lifetime (re-login refreshes them).
- CSRF uses a per-session synchronizer token returned by `GET /api/v1/me`. The SPA sends it
  in `X-KubeChaos-CSRF` on unsafe methods (same-origin URLs only), and the server also
  requires `Origin` to equal the public origin. A double-submit cookie was not needed.
- Keycloak independently enforces S256 PKCE, exact redirect URIs, and no implicit or
  password grants for `kubechaos-api` (verified in development).
- **Role-tiered session lifetime.** Sessions holding a high-privilege role (`admin`,
  `approver`) get a 10 min idle / 1 h absolute limit instead of 30 min / 8 h. Each session
  stores its own idle timeout. Misconfiguration can only make the high-privilege limits
  stricter, never longer than the ordinary ones.
- **Revocation (three independent paths):**
  1. *IdP-driven:* OIDC Back-Channel Logout at `POST /auth/backchannel-logout`. When a user
     is signed out in Keycloak (for example by an admin after a group change), Keycloak
     POSTs a signed logout token. It is verified for signature, iss, aud, iat freshness,
     the back-channel-logout event, and absence of a nonce. A token naming a subject revokes
     **every** session of that subject here, not only the matching `sid`, because Keycloak
     was observed sending a single token for a multi-session user. Responses use
     `Connection: close`, because Keycloak does not retry and a stale pooled keep-alive
     connection was observed silently dropping a revocation.
  2. *Break-glass CLI:* `kubechaos-api sessions revoke --email|--subject|--role|--all --yes`.
     It needs only the database, so it works with the IdP or web tier down.
  3. *Expiry:* the short high-privilege lifetimes bound exposure if both paths above are missed.
- **Log hygiene.** Every log line passes through `internal/logging`. It always redacts
  sensitive attribute keys and scrubs JWTs, OAuth parameters (`code`, `state`, tokens,
  secrets), bearer credentials, session cookies and connection-string passwords from all
  strings and error texts. Token-endpoint failures are logged as status plus OAuth error code
  only, never the response body. The OIDC e2e test scans the captured logs for every real
  code, state, cookie, CSRF token, client secret and password it saw.
- **Not yet implemented:** step-up (`acr_values`/`max_age=0`) and elevation grants. These
  arrive with experiment submission, the first operation that requires them. The session
  already records `acr` and `auth_time`. Login/logout audit events arrive with the audit
  writer (foundation step 14).

### Step-up authentication [DECISION 11]

```
POST /api/v1/experiments/{id}/submit
   → 403 {"error":"step_up_required","required_acr":"kc-aal2","challenge":"<id>"}
SPA → GET /auth/step-up?challenge=<id>
   → Keycloak /authorize with acr_values=kc-aal2, max_age=0, prompt=login
   → callback: verify ID token acr ≥ required AND auth_time ≥ challenge.created_at
   → server records an *elevation grant*:
        { session, experiment_id, spec_sha256, acr, expires: +5 min, single_use: true }
SPA → shows explicit confirmation (typed experiment name), re-POSTs submit
   → server consumes the grant (atomically), proceeds
```

The grant is bound to the experiment **and the hash of its spec**. If the spec changes
after step-up, the grant is invalid. The frontend confirmation dialog is UX, not a
security control.

---

## 5. Authorization flow

Three separate questions, evaluated in order. Any "no" or "unknown" means DENY:

1. **Authentication**: valid session? Is the auth level sufficient for this action?
2. **Authorization (RBAC)**: does the user hold a role granting `action` on
   `(cluster, namespace)`?
   - Roles come from Keycloak groups (`kubechaos-viewer`, `-experimenter`, `-approver`,
     `-admin`, `-auditor`). Scopes come from **role bindings stored in the DB**, which only
     `admin` can manage and which are themselves audited [DECISION 10].
   - Separation of duties: `auditor` reads audit and nothing else. `admin` manages bindings
     and clusters but **cannot** read/modify audit history and cannot release a lock (§10).
3. **Experiment policy**: does this specific experiment satisfy the cluster's
   `ChaosPolicy` (environment, allowed faults, namespaces, kinds, max targets, max duration,
   max concurrency, forbidden targets)? Is the cluster unlocked?

Steps 1–3 run in the control plane. **Step 3 then runs again in the operator** (admission
webhook and again at execution time against the *actually selected* targets). The
operator does not trust the control plane's verdict.

Each decision produces a structured `Decision{allow, reasons[], policy_version, evaluated_at}`
that is written to the audit log whether it allows or denies.

---

## 6. Experiment model and lifecycle

### Declarative definition (constrained)

```yaml
apiVersion: chaos.kubechaos.io/v1alpha1
kind: ChaosExperiment
metadata: { name: exp-7f3a, namespace: kubechaos-system }
spec:
  clusterID: dev-kind-01                 # must match operator's configured identity
  requestedBy: { sub: "...", iss: "..." }  # informational to operator (see threat model)
  maxDuration: 120s                      # hard ceiling; operator aborts after this
  steps:
    - fault:
        type: PodKill
        target: { namespace: payments, kind: Deployment, name: payment-api }
        params: { count: 1, gracePeriodSeconds: 0 }
    - wait: { duration: 30s }
  successCriteria:
    - metric: available_replicas        # from a fixed metric catalog [DECISION 14]
      operator: ">="
      value: 3
    - metric: recovery_time
      operator: "<"
      value: 30s
  cancel: false                          # control plane sets true to request cancellation
```

Rules: `steps` is a closed union (`fault | wait | validate`). Unknown fields are rejected
(structural schema plus `x-kubernetes-preserve-unknown-fields: false`). Unknown fault types
are rejected. Targets are a **named workload or a label selector within one namespace**,
never cluster-wide.

### State machine (owned by operator, mirrored into DB by control plane)

```
 Draft ─(submit)─▶ PendingApproval ─(step-up/approval)─▶ Submitted
   (DB only)          (DB only)                            │ CR created
                                                           ▼
                                                      Validating ──deny──▶ Rejected
                                                           │ (webhook + reconciler policy check)
                                                           ▼
                                                     SelectingTargets ──blast radius exceeded──▶ Rejected
                                                           │ (snapshot of exact targets recorded in status)
                                                           ▼
                                                        Injecting ──error──▶ Failed ─┐
                                                           │                         │
                                                           ▼                         │
                                                        Observing ──timeout──▶ Failed┤
                                                           │                         │
                                                           ▼                         ▼
                                                       Evaluating ──────────▶ Completed (Passed|Failed)
    any non-terminal ──cancel / lock / maxDuration──▶ Aborting ──cleanup──▶ Aborted
```

- Transitions are a pure function `Next(state, event) → (state, error)` with exhaustive
  unit tests. Illegal transitions are errors, never no-ops.
- **At-most-once execution** [DECISION 7]: before a destructive action the operator writes
  `status.actions[i] = {intent, targets, startedAt}`. If it restarts and finds an intent with
  no result, it does **not** retry. It marks the step `Unknown` and moves to Aborting.
- CRs are garbage-collected after a TTL (default 24 h) once terminal. History lives in the DB.

---

## 7. Operator architecture

- controller-runtime manager, leader election (Lease in `kubechaos-system`),
  `MaxConcurrentReconciles` bounded, cluster identity from a mounted ConfigMap.
- **Validating admission webhook** on `ChaosExperiment` CREATE/UPDATE:
  schema → primitive validation → lock check → policy check. `failurePolicy: Fail`
  (fail closed: if the webhook is down, no experiments can be created).
  On UPDATE, `spec` is immutable except `spec.cancel: false → true`.
- **Reconciler** re-runs the policy check at execution time, because policy or lock may
  have changed since admission, then resolves targets, re-checks blast radius against the
  *resolved* set, executes, observes and evaluates.
- **Fault primitive interface** (open for extension; the engine never changes):

```go
type Primitive interface {
    Name() string                       // "PodKill"
    Description() string
    RiskLevel() RiskLevel               // Low | Medium | High | Critical
    RequiredPermissions() []rbacv1.PolicyRule   // documented and checked at startup
    ParamsSchema() *apiextv1.JSONSchemaProps
    Validate(params json.RawMessage, pol *Policy) error
    SelectTargets(ctx, target Target, pol *Policy) ([]TargetRef, error)
    Inject(ctx, targets []TargetRef, params) (InjectionRecord, error)
    Observe(ctx, rec InjectionRecord, sink EventSink) (Observation, error)
    Cleanup(ctx, rec InjectionRecord) error    // idempotent; also invoked on abort
}
```

- **Protected-by-default targets**, enforced in the shared evaluator and impossible to
  disable via policy: `kube-system`, `kube-public`, `kube-node-lease`, the operator's own
  namespace, pods with `chaos.kubechaos.io/protected=true`, static/mirror pods, and
  control-plane components (etcd, apiserver, scheduler, controller-manager).
- **Opt-in**: a namespace is targetable only if it is labelled
  `chaos.kubechaos.io/enabled=true` **and** the operator has a RoleBinding there [DECISION 5, 17].

### Operator RBAC (MVP, PodKill only)

| Scope | Resource | Verbs | Why |
|-------|----------|-------|-----|
| ClusterRole | `chaos.kubechaos.io/chaosexperiments`, `/status`, `/finalizers` | get list watch update patch | Reconcile |
| ClusterRole | `chaos.kubechaos.io/chaospolicies`, `chaoslocks` | get list watch | Read policy & lock (**no write**) |
| ClusterRole | `namespaces` | get list watch | Read opt-in labels |
| Role (kubechaos-system) | `coordination.k8s.io/leases` | get create update | Leader election |
| Role (kubechaos-system) | `events` | create patch | Emit timeline events |
| **RoleBinding per opted-in namespace** | `pods` | get list watch **delete** | PodKill |
| RoleBinding per opted-in namespace | `apps/deployments, replicasets, statefulsets` | get list watch | Resolve targets, observe recovery |
| RoleBinding per opted-in namespace | `events` | create patch | Event on target |

No `nodes`, no `secrets`, no `pods/exec`, no `pods/ephemeralcontainers`, no
cluster-wide `delete`. Later primitives add rules only when they are introduced,
each documented in this table.

**As implemented (foundation step 10).** Only namespace-scoped rules in
`kubechaos-system`, with no ClusterRole at all yet:

| Resource | Verbs | Restriction |
|----------|-------|-------------|
| `configmaps` | get | `resourceNames: [kubechaos-cluster-identity]`, no list/watch (read uncached) |
| `coordination.k8s.io/leases` | create; get, update | get/update limited to `kubechaos-operator.chaos.kubechaos.io` |
| `events`, `events.k8s.io/events` | create, patch | own namespace |

Enforcement around it:
- `deploy/helm/kubechaos-operator/rbac.snapshot.yaml` and `make rbac-check`: any RBAC change
  is a reviewed diff.
- `make operator-verify` asserts the live ServiceAccount's allow/deny matrix with
  `kubectl auth can-i`.
- The cluster identity ConfigMap is `immutable`. Re-labelling a cluster (for example
  production → development) requires deleting and recreating it, which the operator
  cannot do. The operator refuses to start on a missing or invalid identity.
- The pod runs as UID 65532 on distroless with a read-only root filesystem, all
  capabilities dropped, seccomp `RuntimeDefault`, in a namespace enforcing Pod Security
  `restricted`.
- A NetworkPolicy denies all ingress and allows egress only to the API server:
  ports 443/6443 and destination IPs `networkPolicy.apiServerCIDRs`, which lists both the
  Service IP and the real endpoint. Verified in kind, where kindnet enforces policy. With no
  CIDRs the policy limits only ports, and a probe pod could then reach `1.1.1.1:443`. That
  is why `make operator-deploy` pins the CIDRs and the chart refuses a production install
  without them.
- Metrics are disabled until they can be served authenticated (TokenReview/SAR).

### Control-plane RBAC (dev CRD mode)

| Scope | Resource | Verbs |
|-------|----------|-------|
| Role (kubechaos-system) | `chaosexperiments` | create get list watch patch (patch limited to `spec.cancel` by webhook) |
| ClusterRole | `chaospolicies` | get list watch |
| ClusterRole | `chaoslocks` | get list watch **create** (engage only; **no delete**: cannot unlock) |

The control plane has **no access to pods or any workload**. A target preview ("which
pods would match?") is a `dryRun: true` ChaosExperiment that the operator resolves and
reports back in its status.

---

## 8. Database responsibilities

| Table group | Contents | Notes |
|-------------|----------|-------|
| `identities` | (iss, sub), display name, last login | No passwords, ever |
| `role_bindings` | identity/group → role → (cluster, namespace pattern) | Changes audited |
| `clusters` | id, display name, environment, connector config ref, status | No kubeconfigs in DB |
| `experiments` | definition (JSONB, schema-validated), spec hash, owner, state, timestamps | Intent + history |
| `experiment_steps`, `experiment_results`, `criteria_results` | per-step outcome, metrics, score | Written from CR status |
| `experiment_events` | timeline (append-only) | Feeds SSE and the UI timeline |
| `elevation_grants` | step-up grants (single use, TTL) | |
| `sessions` | server-side sessions | Or Redis later |
| `audit.events` | append-only, hash-chained | Separate schema and grants (§9) |
| `scenarios` | saved, reusable experiment templates | |

**Policies are not stored in the DB** [DECISION 2]. The authoritative ChaosPolicy lives in
the cluster and is managed by cluster admins (GitOps/Helm). The control plane can only
read it. The DB may cache a copy for display, labelled with its `resourceVersion`.

DB roles: `kubechaos_migrator` (DDL, used only by the migration job),
`kubechaos_app` (DML on app tables; **INSERT, SELECT only** on `audit.events`),
`kubechaos_auditor_ro` (SELECT on audit). A trigger on `audit.events` rejects
UPDATE/DELETE/TRUNCATE even from owners, as a guard against mistakes. Tooling: pgx + sqlc,
goose migrations.

---

## 9. Audit

- One audit event per security-relevant action: login, step-up, authorization decision
  (allow **and** deny), experiment create/submit/cancel, role binding change, cluster
  registration, lock engage/release, and every destructive action executed.
- Fields: `id, ts, actor{iss,sub,name}, auth_level(acr), session_id_hash, source_ip,
  action, cluster_id, namespace, resource, fault_type, params, requested_blast_radius,
  decision{allow,reasons,policy_version}, experiment_id, result, affected_resources,
  prev_hash, hash`.
- **Hash chain**: `hash = SHA-256(prev_hash || canonical_json(event))` using the standard
  library, with no custom crypto. The chain makes deletion or reordering detectable, and a
  `kubechaosctl audit verify` command checks it.
- **Two independent audit streams.** The control plane records *requests and decisions*.
  The operator independently emits structured JSON logs and Kubernetes Events for every
  action it *executes*. A compromised API can stop writing its own audit, but it cannot
  suppress the operator's record of what actually happened. Both streams should ship to an
  external log sink [DECISION 12].
- `GET /api/v1/audit` is read-only, `auditor` role only, paginated. The API has **no**
  write or delete route for audit.

---

## 10. Emergency stop

Mechanism: a cluster-scoped **`ChaosLock`** CRD. **The system counts as locked if any
ChaosLock object exists.**

| Who | Can engage | Can release |
|-----|-----------|-------------|
| `kubechaosctl emergency-stop` (break-glass kubeconfig on control node, via SSH) | yes | yes (`kubechaosctl unlock`) |
| Web UI `admin` (via control plane SA: `create` only) | yes | **no** |
| Control plane automated (e.g. policy unreadable) | yes | no |

When locked:
- the admission webhook rejects all new ChaosExperiments;
- the reconciler moves every non-terminal experiment to `Aborting` and runs `Cleanup`;
- the control plane refuses submissions and shows a banner.

Defense in depth if the operator itself is broken: `kubechaosctl emergency-stop --hard`
also scales the operator Deployment to 0 and deletes its target-namespace RoleBindings.
Because every fault is self-expiring (§1.5), the cluster converges back without the
operator. PodKill needs no cleanup at all, and future stress pods carry
`activeDeadlineSeconds` and owner refs.

`kubechaosctl` talks **directly to the Kubernetes API** with its own credentials, so it
works when the control plane, DB or IdP is down. It also engages the DB-level lock flag
when the DB is reachable.

---

## 11. Cluster communication

- **Phase 1 (dev):** the control plane uses a ServiceAccount confined to
  `kubechaos-system` (table in §7) and talks CRDs directly. This goes through a
  `ClusterConnector` interface (`Submit, Cancel, Watch, GetPolicy, EngageLock`) so
  phase 2 is a new implementation, not a rewrite.
- **Phase 2 (multi-cluster):** each cluster runs an agent that **dials out** to the
  control plane over gRPC with mTLS [DECISION 9]. Clusters expose no inbound port. The
  agent's client certificate SAN carries the cluster ID, and the control plane matches it
  against the registry (cluster identity). The agent translates messages into local CRs,
  so the admission webhook and RBAC enforcement stay identical. Certificates are
  short-lived (cert-manager or SPIFFE/SPIRE).

---

## 12. Failure handling (fail closed)

| Condition | Behavior |
|-----------|----------|
| ChaosPolicy missing/unreadable/invalid | DENY; operator treats as "no faults allowed" |
| Multiple conflicting policies | DENY (exactly one policy per cluster in MVP) |
| Webhook unavailable | API server rejects CR creation (`failurePolicy: Fail`) |
| IdP unreachable | No new logins/step-ups; existing sessions continue read-only after token expiry |
| DB unavailable | Control plane rejects submissions (cannot audit → cannot act). Running experiments continue under operator control, bounded by `maxDuration`. |
| Audit write fails | The triggering request fails. Never "execute without audit". |
| clusterID mismatch | Rejected at webhook |
| Selector matches 0 targets | Rejected (Unknown target) |
| Selector matches > limit | Rejected; never "pick N of them" silently, unless the primitive's `count` is explicitly a sample size bounded by policy |
| Operator crash mid-action | At-most-once; Unknown → Aborting |
| Lost watch/SSE | Clients re-sync from DB with `Last-Event-ID` |

---

## 13. API surface (REST + SSE)

As in the brief, plus `GET /api/v1/me`, `POST /api/v1/experiments/{id}/submit`,
`POST /api/v1/experiments/{id}/dry-run`, `GET/POST /api/v1/admin/role-bindings`,
`POST /api/v1/admin/lock` (engage only). All request bodies are validated against
OpenAPI schemas with `additionalProperties: false`. There are hard limits on body size,
page size, and per-user SSE connections. Idempotency keys are required on create/submit.

---

## 14. Observability

- **Injection vs observation are separate modules**. Observation starts *before*
  injection (baseline snapshot), runs during the injection, and continues to a recovery
  condition or timeout.
- Prometheus metrics on both binaries (`kubechaos_experiments_total{result}`,
  `kubechaos_policy_denials_total{reason}`, `kubechaos_recovery_seconds`, …).
- OpenTelemetry tracing across API → connector → operator, with the trace ID carried in
  a CR annotation.
- Resilience score = weighted share of passed criteria, from explicit criteria only.
  The weights are part of the experiment definition, so the score can be reproduced.

---

## 15. Approval Service (four-eyes, independent trust domain) [DECISION 4, 11]

### Goal
A fully compromised control plane must **not** be able to run an approval-requiring
experiment on its own. A human approver (a Head Developer or Dev Team lead who owns the
target namespace) must review the exact spec. The operator must be able to verify that
approval **without trusting the control plane**.

### Components

```
           ┌──────────────────────┐   approval request (spec, hash)   ┌─────────────────────────┐
 Requester │ Control plane (API)  │ ────────────────────────────────▶ │ Approval Service        │
  (SPA) ──▶│ no signing key       │ ◀──── signed attestation (JWS) ── │ kubechaos-approver      │
           └──────────┬───────────┘                                   │ own DB schema + role    │
                      │ CR + attestation annotation                   │ own OIDC client         │
                      ▼                                               │ own origin / UI         │
           ┌──────────────────────┐   verifies signature with         │ Ed25519 signing key     │
           │ Operator (webhook +  │   public keys from ChaosPolicy    └──────────▲──────────────┘
           │ reconciler)          │   (written by cluster admins)                │ approve/reject
           └──────────────────────┘                                     Approver (Head Dev), step-up
```

- **Separate deployment**, namespace (`kubechaos-approval`), DB schema and DB role, OIDC
  client (`kubechaos-approver`), and **separate origin** (e.g. `approve.<domain>`), so XSS
  in the main SPA cannot drive the approval UI. It has **no Kubernetes credentials**.
- The approver UI is a small separate Angular build (`frontend/approver`). It shares
  components but is deployed to its own origin.
- **The control plane cannot mint approvals.** It holds no signing key. The signing key
  lives only in the approval service (dev: a K8s Secret in `kubechaos-approval`; prod:
  KMS/HSM via a `Signer` interface). The signature is Ed25519 via Go's standard
  `crypto/ed25519`, with no custom crypto.

### Approver authority (who may approve what)
- A namespace's owning team is declared by cluster admins on the namespace:
  `chaos.kubechaos.io/approver-group: /teams/payments/head-developers`.
- Approver identity: Keycloak group membership in that group (the group is managed in
  Keycloak, not in either app DB).
- The approval service learns namespace→approver-group from its **own GitOps config**
  (`approval-routing.yaml`). The **operator independently checks** that the attestation's
  `approver_group` equals the namespace annotation. A compromised approval service
  therefore cannot route approvals to an arbitrary group either.

### Flow

```
1. Requester creates experiment (Draft) in control plane.
2. Control plane runs authZ + policy pre-check + dry-run target resolution (operator).
3. Control plane computes canonical spec (RFC 8785 JCS) and spec_sha256, sends
   ApprovalRequest{experiment_id, cluster_id, environment, namespace, spec, spec_sha256,
   requester{iss,sub}, dry_run_targets} → approval service.  State: PendingApproval.
4. Approval service RE-COMPUTES spec_sha256 from the spec it received (never trusts the
   supplied hash), validates the spec with the shared validator, and routes the request
   to the approver group for the namespace.
5. Approver logs into approver UI → sees the rendered spec, target list, environment,
   risk level, blast radius → step-up (acr=2, max_age=0) → approves or rejects with comment.
   Rules enforced by approval service:
     - approver.sub ≠ requester.sub
     - approver ∈ required group, acr ≥ required, auth_time fresh
     - required approval count met (policy: minApprovals, distinct approvers)
6. Approval service issues attestation (compact JWS, alg=EdDSA, kid):
     { iss: "kubechaos-approver", aud: "kubechaos-operator/<cluster_id>",
       jti, iat, nbf, exp (≤ 1h execution window),
       cluster_id, environment, namespace, spec_sha256,
       requester: {iss, sub},
       approvals: [{sub, name, acr, auth_time, at}],
       approver_group }
7. Control plane: requester performs own step-up (if required), confirms, and the control
   plane creates the ChaosExperiment CR with annotation
   chaos.kubechaos.io/approval: <JWS>.
8. Operator (webhook AND reconciler) verifies:
     signature against ChaosPolicy.spec.approval.trustedKeys[kid]   (admin-written)
     aud == own cluster ID; cluster_id, environment, namespace match CR + policy
     spec_sha256 == SHA-256(JCS(cr.spec))                           (spec not altered)
     approver_group == namespace annotation
     len(distinct approvals) ≥ policy.minApprovals; no approver == requester
     now ∈ [nbf, exp]
     jti unused: operator CREATEs a cluster-scoped ChaosAttestationUse/<jti>;
                 AlreadyExists ⇒ replay ⇒ DENY   (control plane has no RBAC on this kind)
   Any failure ⇒ Rejected.
```

### When approval is required (enforced by the operator from in-cluster policy)

```yaml
# ChaosPolicy (excerpt)
spec:
  environment: production
  approval:
    required: always            # always | riskAtLeast | never  (never forbidden when env=production)
    riskAtLeast: High           # used when required=riskAtLeast
    minApprovals: 1             # distinct approvers, excluding requester (four-eyes)
    maxAttestationAge: 1h
    trustedKeys:
      - kid: approver-2026-11
        publicKey: "<base64 ed25519>"
```

Defaults: production = `always`, minApprovals ≥ 1 (the operator rejects a production policy
that says otherwise; fail closed). Staging/dev = `riskAtLeast: High`.

Operator RBAC addition: `chaosattestationuses` (cluster-scoped) **create get**. The control
plane gets no access to this kind.

### Step-up (D11) applies to both sides
- Requester: step-up at submit if risk ≥ High, environment = production, or targets > 1.
- Approver: **always** step-up to approve.

### Cancellation / emergency stop (D8)
Any experimenter (own experiments), approver (their team's namespaces) and admin can
**cancel** from the UI. Admin can **engage** the lock from the UI. Cancelling never needs
approval or step-up, because stopping is cheap to allow. Lock **release** is CLI-only.

### What each compromise yields
| Compromised | Can do | Cannot do |
|-------------|--------|-----------|
| Control plane only | Run experiments that the policy allows *without* approval (dev, below risk threshold) | Any approval-required experiment (no key) |
| Approval service only | Sign attestations | Create CRs (no K8s access); route to wrong group (operator checks annotation) |
| Both | Run anything within ChaosPolicy limits | Exceed policy, touch non-opted-in namespaces, unlock |

---

## 16. Observability providers and success criteria [DECISION 14]

- **Core provider: Kubernetes API (always available).** Metrics:
  `available_replicas`, `ready_replicas`, `ready_ratio`, `recovery_time`,
  `restart_count`, `pod_reschedule_time`. These are computed by the operator from watches.
- **Optional provider: Prometheus**, configured per cluster
  (`ChaosPolicy.spec.observability.prometheus.url`, set by cluster admins). Metrics:
  `http_error_rate`, `http_latency_p99`, `cpu_utilization`, `memory_working_set`.
  If not configured, criteria using these metrics are **rejected at validation**
  (fail closed). They are never silently skipped.
- **PromQL is never accepted from users. There is no field anywhere in the API, CRD, or
  UI that carries a query string.** A criterion is `{metric: <enum>, operator: <enum>,
  value: <typed>, window: <bounded duration>}`. The query is built in Go from a compiled-in
  template:
  - template parameters come only from the **resolved target** (namespace, workload
    name, label values read from Kubernetes), not from user text;
  - every interpolated value is checked against `^[a-zA-Z0-9_.:/-]{1,253}$` and escaped
    as a PromQL string literal; failure ⇒ reject;
  - windows are bounded (e.g. 30s–15m), and queries carry a timeout and a max-samples limit.
- Which HTTP metric family a cluster exposes (Istio, ingress-nginx, OTel semconv) is a
  per-cluster enum in policy that selects a template set. It is not free text.
- Queries execute in the **operator** (in-cluster, close to Prometheus). Templates live
  in `pkg/chaosapi/metrics` and are unit-tested for injection resistance (fuzzed).
