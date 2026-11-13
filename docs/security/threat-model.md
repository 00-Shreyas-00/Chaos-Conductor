# KubeChaos — Threat Model

Status: **DRAFT — for review.** Companion to `docs/architecture/architecture.md`.

## 1. Assets

| Asset | Why it matters |
|-------|----------------|
| A1 Ability to execute faults | The core hazard: it can cause DoS against workloads and clusters |
| A2 Operator ServiceAccount credentials | Direct destructive power (pod delete in opted-in namespaces) |
| A3 Control plane SA / connector credentials | Can create experiment requests |
| A4 ChaosPolicy / ChaosLock | Define and stop the hazard |
| A5 User sessions, OIDC client secret | Impersonation |
| A6 Audit trail | Accountability, forensics |
| A7 Role bindings | Who may do what |
| A8 Availability of the platform's own stop path | Ability to halt damage |

## 2. Trust-boundary diagram

```
 ╔═══════════════ UNTRUSTED ═══════════════╗
 ║  Internet / user browsers / attackers   ║
 ╚══════════════════╤══════════════════════╝
                    │ TB1  HTTPS
 ┌──────────────────▼─────────────────────────────────────────────┐
 │ DMZ: Reverse proxy (TLS, rate-limit, size-limit, CSP)          │
 └──────────────────┬─────────────────────────────────────────────┘
                    │ TB2  HTTPS + session cookie + CSRF header
 ┌──────────────────▼──────────────────── "ASSUMED COMPROMISABLE" ─┐
 │ Control plane (API, authN, authZ, policy pre-check, audit)      │
 │   │ TB3 OIDC ───────────▶ Keycloak (separate trust domain)      │
 │   │ TB6 TLS ────────────▶ PostgreSQL (app role: no audit UPDATE)│
 └───┼─────────────────────────────────────────────────────────────┘
     │ TB4  K8s API, SA confined to kubechaos-system (dev)
     │      mTLS gRPC, agent dials out (later)
 ┌───▼──────────────────────── CLUSTER TRUST DOMAIN ───────────────┐
 │  kubechaos-system ns                                            │
 │   ┌────────────────────────────────────────────────────┐        │
 │   │ Admission webhook ─▶ Operator reconciler           │        │
 │   │  (re-validates schema, policy, lock, cluster ID,   │        │
 │   │   blast radius on resolved targets)                │        │
 │   └───────────────┬────────────────────────────────────┘        │
 │                   │ TB5  RBAC: RoleBindings ONLY in opted-in ns │
 │   ┌───────────────▼──────────┐   ┌──────────────────────────┐   │
 │   │ Opted-in target ns       │   │ Protected: kube-system,  │   │
 │   │ (label + RoleBinding)    │   │ kubechaos-system, etc.   │   │
 │   └──────────────────────────┘   │ (no RBAC, deny-listed)   │   │
 │                                  └──────────────────────────┘   │
 │  ChaosPolicy / ChaosLock: written ONLY by cluster admins ◀──────┼── TB7 kubechaosctl
 └─────────────────────────────────────────────────────────────────┘   (SSH / control node,
                                                                        break-glass kubeconfig)
```

The key property: **everything above TB4 can be fully compromised and the damage is still
bounded by ChaosPolicy + Kubernetes RBAC + opt-in labels, which the control plane cannot
change.**

## 3. Threats and mitigations

Residual risk is stated honestly where mitigation is partial.

### T1 Unauthenticated attacker
- **Attacks:** hitting API endpoints, brute-force, scanning, exploiting parser bugs, DoS.
- **Mitigations:** every `/api` route requires a session (deny-by-default middleware, with
  an explicit allow-list of public routes: `/auth/login`, `/auth/callback`, `/healthz`).
  No password handling in the app, since Keycloak handles brute-force lockout and MFA.
  Proxy rate limits and body size limits. Strict OpenAPI validation. The operator is not
  internet-reachable, and in phase 2 the cluster exposes no inbound port.
- **Residual:** zero-days in proxy/Go stdlib, handled by patching cadence and minimal images (distroless).

### T2 Stolen user session
- **Attacks:** cookie theft (XSS, malware, shared machine), then running experiments as the victim.
- **Mitigations:** HttpOnly + Secure + `__Host-` + SameSite=Strict cookies, and no tokens
  in JS (BFF). Idle and absolute timeouts. Session rotation on login and step-up.
  **Destructive submissions above a risk threshold require step-up with `max_age=0`**, so
  a stolen cookie alone cannot launch high-risk experiments. Elevation grants are
  single-use, bound to session + experiment + spec hash, and expire after 5 min.
  Server-side revocation through three paths: IdP back-channel logout (revokes all of the
  subject's sessions), the break-glass `sessions revoke` CLI, and expiry. `admin`/`approver`
  sessions last 10 min idle / 1 h absolute. Optional binding of the session to a coarse
  client fingerprint as an anomaly signal only, not as auth.
- **Known limit:** roles are fixed at login. A group removal in Keycloak takes effect
  at the next login, or immediately if the admin also signs the user out in Keycloak (which
  triggers back-channel logout). Back-channel delivery is best-effort (Keycloak does not
  retry), which is why the CLI path and short high-privilege lifetimes exist.
- **Residual:** low-risk experiments within policy can still be run by a session thief.
  Policy limits bound the damage, and audit records it.

### T3 Compromised frontend (malicious JS: XSS, supply-chain in npm deps, tampered bundle)
- **Mitigations:** the frontend holds no credentials or tokens. Strict CSP (`script-src
  'self'`, no inline/eval, `frame-ancestors 'none'`) plus Trusted Types. Angular's default
  sanitization, with no `bypassSecurityTrust*` without review. No third-party fonts,
  icons or scripts (system font, no CDN). Production builds use Subresource Integrity and
  disable inline critical CSS. **Implementation note:** with SRI enabled, Angular emits
  lazy-chunk hashes in an inline `<script type="importmap">`, so the proxy's CSP must
  allow exactly that script by hash (`'sha256-…'`, computed at build time), never via
  `'unsafe-inline'`. Lockfile with `npm ci`,
  dependency review, and SRI where possible. **All enforcement is in the backend and
  operator**: a malicious client can send any request, and every request is validated
  as if hostile.
- **Residual:** malicious JS acting within a live session = T2 without the cookie theft.
  Step-up limits it: the attacker cannot complete an IdP re-auth without the user, but
  could trick the user into one ("confirm this"). The step-up prompt at Keycloak should
  show the experiment summary (the `binding_message`-style text sent to the IdP).

### T4 Compromised API / control plane (RCE, stolen SA token, malicious insider deploy)
This is the threat the architecture is built around.
- **Attacker gains:** the control plane's K8s SA, DB credentials, OIDC client secret,
  and ability to forge any user identity in requests it sends to the operator.
- **Mitigations:**
  - Control plane SA: create/patch ChaosExperiments **only in `kubechaos-system`**. No pod,
    node, secret or workload access. Read-only on ChaosPolicy. Create-only on ChaosLock
    (it can stop the system, not unlock it).
  - The operator re-validates everything (webhook + reconciler) against **in-cluster
    policy the control plane cannot write**: allowed faults, namespaces, max targets, max
    duration, max concurrency, environment.
  - Operator RBAC exists only in opted-in namespaces, so even a policy bug cannot reach
    `kube-system`.
  - The operator emits its own audit stream (logs + K8s Events), so hidden execution is not possible.
  - **Approval-required experiments (all production, plus risk ≥ High elsewhere) need an
    Ed25519-signed attestation from the separate Approval Service**, verified by the
    operator against public keys in admin-written ChaosPolicy, bound to the spec hash,
    cluster, namespace and approver group, and single-use (architecture.md §15). The
    control plane holds no signing key.
  - DB role cannot UPDATE/DELETE audit rows, and the hash chain plus external log sink
    detect tampering.
- **Residual (explicit):** a fully compromised control plane can launch any experiment
  **that the cluster's ChaosPolicy permits without approval** (non-production, below the
  risk threshold), attributed to any user it chooses. Production and high-risk
  experiments additionally require compromising the Approval Service (T16) **or**
  tricking a real approver.

### T5 Malicious authenticated user
- **Attacks:** exceeding their scope, crafting requests beyond UI limits, targeting other
  teams' namespaces, abusing selectors to match many pods, resource exhaustion via
  experiments.
- **Mitigations:** RBAC per (cluster, namespace). Policy limits enforced in both tiers.
  Selector resolution happens in the operator, and **the blast radius is checked against
  the resolved set**. Per-user and global concurrency limits. Production environments
  require four-eyes approval [DECISION 11]. Full attribution in audit.
- **Residual:** the user can do anything their role and policy allow. That is the product working as intended.

### T6 Compromised operator
- **Attacker gains:** operator SA, meaning delete pods in opted-in namespaces and read
  workloads there.
- **Mitigations:** narrow RBAC (no secrets, no exec, no nodes, no cluster-wide writes,
  no RBAC verbs, no `escalate`/`bind`/`impersonate`). Distroless non-root image,
  read-only root FS, `seccompProfile: RuntimeDefault`, all capabilities dropped, no host
  namespaces. NetworkPolicy: egress only to the API server (+ control plane in phase 2).
  Pinned image digests, enforced via a ValidatingAdmissionPolicy on `kubechaos-system`.
  `kubechaosctl emergency-stop --hard` removes its RoleBindings.
- **Residual:** within opted-in namespaces it can delete pods at will. Later primitives
  (ephemeral containers, eviction) widen this, so each new permission requires a threat
  model update.

### T7 Compromised cluster (cluster admin / node root is hostile)
- **Position:** a hostile cluster admin already has more power than KubeChaos, so we
  can't protect that cluster from them. What we protect is **the control plane and the
  *other* clusters**.
- **Mitigations:** in phase 2, per-cluster identity (mTLS cert per agent, cluster ID in
  SAN). The control plane treats agent-reported data (status, metrics, events) as
  untrusted input: schema-validated, size-capped, HTML-escaped in the UI. An agent can only
  act on its own cluster ID. A cluster's agent cannot issue commands to the control plane,
  only report.
- **Residual:** that cluster's results and audit (operator stream) may be falsified.

### T8 Malicious experiment definition
- **Attacks:** unknown fault types, injected fields, huge counts, wildcard selectors,
  cross-namespace targets, negative/overflow durations, deeply nested or huge payloads,
  PromQL injection via success criteria, YAML bombs.
- **Mitigations:** closed set of primitives with typed params and OpenAPI/CRD structural
  schemas (`additionalProperties: false`). Bounds on every number. Single-namespace
  targets. Selectors must be non-empty and contain at least one equality match. Max steps
  per experiment and max total duration. JSON only on the API (no YAML parsing
  server-side). Body size limit. Success criteria from a **fixed metric catalog** whose
  queries are server-side templates with typed parameters, never user PromQL
  [DECISION 14]. Webhook and reconciler re-validate.

### T9 Credential theft
- **Targets:** OIDC client secret, DB password, control plane SA token, operator SA
  token, break-glass kubeconfig, mTLS keys.
- **Mitigations:** secrets come from K8s Secrets / an external secret manager and are
  never logged. Every log line passes through a redaction layer covering sensitive keys,
  JWTs, OAuth parameters, bearer credentials, session cookies and DSN passwords, including
  inside third-party error strings. Token-endpoint errors are reduced to status plus error
  code. An e2e test scans logs for every real secret value it handled. Projected,
  audience-bound, short-lived SA tokens. Short-lived mTLS certs. The break-glass kubeconfig
  is only on the control node, ideally using a short-lived credential (OIDC to the API
  server or a cert valid for hours), with its use recorded in K8s audit logs. No
  kubeconfigs in the DB or UI ever. DB connections use TLS.
- **Residual:** theft of the break-glass credential = cluster admin compromise, out of
  scope for app-level controls.

### T10 Replay attacks
- **Attacks:** replaying a submit request, an elevation, an OIDC callback, or an old CR.
- **Mitigations:** OIDC `state` + `nonce` + PKCE. Single-use, spec-hash-bound, short-TTL
  elevation grants consumed atomically (`UPDATE … WHERE used_at IS NULL RETURNING`).
  Idempotency keys on create/submit. CR names are server-generated. The operator executes
  each CR UID at most once. A CR older than `admissionMaxAge` (e.g. 10 min) without having
  started is rejected. CSRF tokens tie requests to the session.

### T11 Privilege escalation
- **Paths:** user grants self roles, experimenter → admin, control plane SA → workload
  access, operator SA → cluster-admin via RBAC verbs, ephemeral containers to read
  secrets, abuse of the webhook.
- **Mitigations:** role bindings are only editable by `admin`, audited, and admins cannot
  edit their own bindings (four-eyes for admin grants). A revoked high-privilege grant stops
  working within at most 1 h without any action, or immediately via Keycloak sign-out
  (back-channel logout) or `kubechaosctl`/`kubechaos-api sessions revoke --role admin`. Roles derive from IdP groups
  managed outside the app. Neither SA has `escalate`, `bind`, `impersonate`, RBAC write,
  `pods/exec`, or secrets. Any future ephemeral-container primitive must be constrained
  by an admission policy pinning the image digest and forbidding privileged settings.
  Every RBAC change ships with an update to the permission table in
  architecture.md §7 and a CI check that diffs the Helm-rendered RBAC against an
  approved snapshot.

### T12 Audit-log tampering
- **Mitigations:** no update/delete API. DB role separation (app = INSERT/SELECT) plus a
  trigger blocking UPDATE/DELETE/TRUNCATE. Hash chain with a periodic verification job
  that publishes the head hash to the external log sink, so any rewrite is detectable.
  Operator audit stream is independent of the DB. K8s API server audit logs (cluster-side)
  record CR creation and pod deletions with the SA identity. Auditor role is separate
  from admin.
- **Residual:** a DB superuser can rewrite the chain consistently. External anchoring of
  the head hash detects this after the fact.

### T13 Resource exhaustion
- **Against the platform:** rate limits per IP and per user, bounded DB pool, per-user
  SSE connection limit with heartbeat and idle timeout, pagination caps, request
  timeouts, a `count/chaosexperiments.chaos.kubechaos.io` ResourceQuota in
  `kubechaos-system`, CR TTL cleanup, bounded `MaxConcurrentReconciles`, event retention.
- **Via the platform (fault as weapon):** policy `maxConcurrentExperiments` and per-user
  quotas. Stress primitives (later) capped as a percentage of the target's own limits.
  Mandatory `maxDuration`. Self-expiring faults. Global lock.

### T14 (additional) Confused cluster identity
- A request meant for `dev` executes on `prod`.
- **Mitigation:** `spec.clusterID` must equal the operator's configured identity. Each
  cluster's ChaosPolicy declares its `environment`, and the operator rejects experiments
  whose declared environment doesn't match. The UI shows the environment prominently, and
  production requires approval.

### T15 (additional) Supply chain of the operator/control plane
- **Mitigations:** minimal dependencies, `govulncheck` + `npm audit` in CI, pinned base
  images by digest, signed images (cosign) verified at admission later, SBOM generation.

### T16 (additional) Compromised or bypassed Approval Service
- **Attacks:** forging approvals; approving one spec then executing another; replaying
  an old attestation; approver self-approving their own request; a compromised control
  plane presenting a misleading summary to the approver; routing to a friendly approver
  group.
- **Mitigations:** separate deployment, origin, OIDC client, DB role, and no K8s
  credentials. Signing key only there (KMS in prod). The approval service recomputes the
  spec hash itself and renders the approver view **from the canonical spec**, not from
  control-plane-supplied text. The operator verifies signature, `aud`, cluster, namespace,
  environment, spec hash, expiry, distinct approvers ≠ requester, approver group ==
  namespace annotation (admin-set), and single-use `jti` via an AlreadyExists-guarded
  cluster object the control plane cannot create. Approvers must step up. Key rotation
  via `kid` with multiple trusted keys in policy.
- **Residual:** compromise of both control plane and approval service = experiments up
  to the ChaosPolicy ceiling. A social-engineered approver (a legitimate approval of a
  harmful spec) is bounded only by policy and recorded in audit.

### T17 (additional) PromQL injection / expensive queries
- **Mitigation:** no query field exists in any interface. Templates are compiled into
  the binary, parameters come from resolved Kubernetes objects and are validated and
  escaped, and windows, timeouts and sample limits are bounded (architecture.md §16).
  Fuzz tests on the template builder.

## 4. Security test obligations (derived)

Unit: authZ matrix, policy evaluator (including protected namespaces that policy cannot
override), blast radius on resolved targets, primitive param validation (fuzz with Go
native fuzzing), state machine transitions (exhaustive), elevation grant
binding/expiry/single-use, audit hash chain, fail-closed paths (policy missing, policy
duplicated, lock present).

Integration: API→DB, API→CR creation, webhook rejection cases, **"compromised control
plane" test**: submit an over-limit CR directly with the control plane SA and assert it
is rejected, and assert the control plane SA cannot delete pods or unlock. Full PodKill
lifecycle on kind.
