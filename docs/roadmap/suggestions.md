# Suggestions: lessons from Netflix Chaos Monkey and beyond

Status: proposal (2026-11-16). This document compares KubeChaos with Netflix's chaos tooling
(Chaos Monkey, the Simian Army, and the later ChAP/Monocle platform), lists what is worth
adopting, and proposes further improvements. Each suggestion keeps the project's core rules:
typed primitives only, backend/operator enforcement, policy-bounded blast radius, fail
closed, audit everything.

---

## 1. What Netflix built

### 1.1 Chaos Monkey (2011; v2 integrated with Spinnaker)
Chaos Monkey randomly terminates production instances so teams are forced to build
services that tolerate instance loss. As configured per application in Spinnaker:

| Setting | Behaviour |
|---------|-----------|
| `enabled` | Opt-in per application. |
| Mean time between kills (work days, default 2) | On each work day, for every enabled group, a biased coin decides whether one random instance in that group is terminated. |
| Min time between kills (work days, default 1) | Hard floor: a group is never hit more often, even if several Chaos Monkey instances share one database. |
| Grouping: `app` / `stack` / `cluster` | Defines a "group" and so the maximum kills per day (one per app, per stack, or per cluster). |
| Regions are independent | By default each region is a separate group; can be disabled for cross-region systems (e.g. databases). |
| Exceptions | Opt-outs by account / region / stack / detail, with `*` wildcards. |
| Supporting pieces | An **outage checker** (do not kill during an ongoing outage) and a **tracker** (record/notify every termination). Runs during business hours only. |

**What it deliberately does not do:** it has one fault (terminate an instance), no
hypothesis or metrics, no automatic abort, no approval step, and no notion of "was the
system fine afterwards?". It relies on randomness plus people noticing problems.

### 1.2 The Simian Army (2011–2012)
| Tool | Purpose |
|------|---------|
| Latency Monkey | Adds artificial delay to client–server (REST) calls to simulate degradation, or unavailability with long delays. |
| Conformity Monkey | Finds instances that break best practices (e.g. not in an auto-scaling group) and shuts them down; later folded into Spinnaker. |
| Doctor Monkey | Health checks; removes unhealthy instances. |
| Janitor Monkey | Cleans up unused resources. |
| Security Monkey | Finds security misconfigurations. |
| Chaos Gorilla | Simulates the loss of an entire availability zone. |
| Chaos Kong | Simulates the loss of an entire region. |

### 1.3 FIT, ChAP and Monocle (2014–2019)
Netflix moved from random destruction to **controlled experiments**:
- **ChAP (Chaos Automation Platform):** for an experiment it deploys a *baseline* and a
  *canary* cluster (each ~1% of the original). The routing layer sends a small user
  cohort to the canary with a fault-injection rule (e.g. "fail calls to the bookmark
  service"). It compares customer KPIs (canary users vs baseline users) and service
  health (canary cluster vs baseline cluster); Kayenta performs the statistical analysis.
- **Safety:** weekday business hours only; never while a region is failed over; all
  concurrent experiments together may affect at most **5% of traffic** in a region; stop
  immediately on excessive customer impact.
- **Monocle:** self-serve uptake was low, so Monocle discovers each service's
  dependencies from telemetry, tracing and runtime config. For every dependency it
  generates three experiments: failure, latency just *below* the timeout, and latency
  that *causes* failure. It ranks them by a criticality score (priority, call volume,
  retries, number of dependents) and a safety score, and skips unsafe, running,
  recently-run or unreviewed-failed experiments.
- **Lessons:** automated experiments found misaligned timeouts and services more critical
  than their owners believed. Raw error rates were noisy (one bad device skews results),
  so abort thresholds had to be robust. Human review of findings was valuable but became
  a bottleneck.

---

## 2. Where KubeChaos already stands

| Area | Chaos Monkey | KubeChaos today |
|------|--------------|-----------------|
| Fault types | Instance termination | Typed `PodKill` (more primitives planned) |
| Targeting | Random instance in an opted-in group | Label selector in opted-in namespaces; random selection (crypto/rand shuffle); `protected` label; never the last Ready replica |
| Blast radius | One kill per group per day | `ChaosPolicy`: allowed faults/namespaces, max pods, max duration, concurrency, min Ready replicas |
| Hypothesis / result | None | Success criteria → resilience score (built-in metrics + Prometheus templates, no user PromQL) |
| Approval | None | Four-eyes approval service; Ed25519 attestation verified by the operator; single use |
| Stop | Disable the app's config | `kubechaosctl emergency-stop` (independent of UI), UI cancel, lock aborts running experiments |
| Audit | Tracker | Hash-chained append-only audit log, verifiable |
| Identity | Spinnaker users | Keycloak OIDC BFF, step-up for high risk, back-channel logout |
| Scheduling | Continuous, randomized | **Manual, one-off submissions only** |
| Incident awareness | Outage checker | **None** (only the manual lock) |
| Analysis | None | **End-of-run** criteria; no baseline comparison, no live abort on metrics |

KubeChaos is already stronger on safety, governance and evidence. Its gaps are
*continuous practice* (scheduling), *automatic safety signals* (incidents, live
abort), *breadth of faults*, and *experiment design help* (what should we test?).

---

## 3. Suggestions adopted from Chaos Monkey

### S1. `ChaosSchedule`: continuous, randomized, opt-in chaos  ★ high value
A cluster-scoped CRD (admin-owned, like `ChaosPolicy`) plus a scheduler in the operator:
```yaml
kind: ChaosSchedule
spec:
  template: { steps: [ { fault: { type: PodKill, target: { namespace: demo, selector: { app: web } }, podKill: { count: 1 } } } ] }
  grouping: workload              # workload | namespace | cluster  (≈ Chaos Monkey cluster/stack/app)
  meanTimeBetweenRuns: 2d          # biased-coin per eligible window
  minTimeBetweenRuns: 1d           # hard floor per group
  window: { days: [Mon-Fri], from: "10:00", to: "16:00", timeZone: Europe/London }
  blackoutCalendars: [ holidays-uk, release-freeze ]
  expires: 2027-01-31              # schedules must not live forever
```
- Each firing creates an ordinary `ChaosExperiment`, so every existing gate (policy,
  lock, concurrency, survivors, audit, scoring) still applies.
- **Approval interplay:** add a *standing approval*. The approver signs a bounded
  attestation for the schedule (template hash, max runs, expiry), and each run consumes
  one use. This keeps four-eyes without approving every run.
- Random choice uses `crypto/rand` (as PodKill already does); record the seed/decision in
  audit so every run is explainable.

### S2. Incident guard ("outage checker")  ★ high value, cheap
- Before admitting an experiment (and periodically while it runs), the operator checks
  incident signals. It aborts or skips when any is active:
  - Alertmanager firing alerts matching an admin-defined matcher (e.g. `severity=critical`)
  - an active ChaosLock (already implemented)
  - optional PagerDuty/Opsgenie "incident open" via the control plane
- Optional **auto-lock**: an authenticated Alertmanager webhook receiver engages
  `ChaosLock` automatically. Releasing it stays CLI-only, consistent with D8.
- Fail closed: if the incident source is configured but unreachable, nothing starts.

### S3. Exceptions and grouping in `ChaosPolicy`
- `exclusions:` label selectors (workload, namespace or node) beyond the `protected` pod
  label, with mandatory reasons (shown in UI and audit).
- Per-group rate limits (`maxRunsPerDay` per workload, namespace or cluster), mirroring
  Chaos Monkey's grouping-based ceiling. These defend against floods of manual
  submissions too.

### S4. Termination tracker → notifications
- Emit Kubernetes `Event`s on the affected workloads ("KubeChaos terminated pod X in
  experiment Y") so owners see them in their usual tooling.
- Outbound notifications (Slack/Teams/webhook/email) on start, abort, finish and
  approval-needed. Delivery is signed (HMAC) and retried. Payloads carry links and
  summaries, never tokens.

---

## 4. Suggestions from the Simian Army

### S5. More fault primitives, ordered by the privilege they need  ★ high value
Prefer primitives that only need **Kubernetes API** permissions over ones that need a
privileged node agent:

| Tier | Primitive | Mechanism | Netflix analogue |
|------|-----------|-----------|------------------|
| API-only | `NetworkPartition` | Temporary deny `NetworkPolicy` between selectors (needs a CNI that enforces it) | Latency Monkey (unavailability) |
| API-only | `HTTPFault` (abort / delay %) | Service-mesh fault injection (Istio `VirtualService` fault, or Gateway API filters) | Latency Monkey / FIT |
| API-only | `ScaleDown` | Temporarily lower replicas (restored by the operator) | — |
| API-only | `NodeDrain` / `NodeCordon` | Eviction API (respects PDBs) | Chaos Gorilla (partial) |
| API-only | `ZoneOutage` | Cordon + drain all nodes with a `topology.kubernetes.io/zone` value, capped by policy (`maxZones: 1`, survivors per workload) | Chaos Gorilla |
| API-only | `DependencyBlackhole` | NetworkPolicy deny egress to a named Service/CIDR | FIT |
| Agent | `NetworkLatency` / `PacketLoss` | `tc netem` in the pod's netns via a minimal, signed node agent | Latency Monkey |
| Agent | `CPUStress` / `MemoryStress` / `DiskFill` | Agent-launched, cgroup-bounded stressor | — |
| Agent (high risk) | `ClockSkew`, `DNSFailure` | Agent; production-forbidden by default | — |

Rules for every new primitive:
- a typed schema with CEL bounds
- a `FaultRisk` entry in the catalog
- an at-most-once injection record and a **guaranteed revert**: reverts are
  operator-owned, run on abort, lock and deadline, and are idempotent
- "revert on operator restart" tests

### S6. Resilience readiness checks ("Conformity Monkey", without the killing)  ★ cheap
A read-only scan per opted-in workload, shown in the UI and as a pre-flight warning:
- a PodDisruptionBudget exists
- replicas ≥ 2
- readiness and liveness probes are set
- topology spread or anti-affinity across nodes and zones
- resource requests and limits are set
- `terminationGracePeriodSeconds` is sane
- no single-replica dependency in the call graph (when tracing is available)

Produce a **readiness score** next to the resilience score. The policy can require a
minimum readiness score before a fault may run.

### S7. Steady-state pre-check ("Doctor Monkey")
Before injection, evaluate the experiment's success criteria once as a *steady-state
hypothesis*. If the system is already unhealthy, the experiment is **Rejected
(`SteadyStateNotMet`)** instead of blaming the fault later.

### S8. Janitor
TTL-based cleanup of finished `ChaosExperiment`s and old `ChaosAttestationUse` records,
keeping enough to prevent replays: keep each record until its attestation expires plus
a margin. DB retention for timelines stays under audit rules.

### S9. Region / cluster failure ("Chaos Kong") — later
With multi-cluster support (S15), a `ClusterEvacuation` scenario can be orchestrated:
fail traffic away at the global load balancer or DNS layer, then verify the remaining
clusters' criteria. This needs explicit production approvals with two approvers.

---

## 5. Suggestions from ChAP and Monocle

### S10. Live abort guards  ★ high value
Today criteria are evaluated at the end, while abort happens only on lock, deadline or
cancel. Add `abortConditions` evaluated every N seconds while the experiment runs. They
use the same compiled metric templates, so there is still no user-written PromQL.
```yaml
abortConditions:
  - { metric: http_error_rate, operator: gt, value: "0.05", for: 30s }
  - { metric: available_replicas, operator: lt, value: "1" }
```
On a breach: revert, set `Aborted (GuardrailBreached)`, audit, notify. Use robust
statistics (median over a window, a minimum sample count) because, as Netflix learned,
a single noisy source can trip naive thresholds. If metrics are unavailable, abort: fail
closed.

### S11. Baseline vs experiment comparison  ★ high value (needs mesh)
Run an *experiment cohort* and a *control cohort* simultaneously, for example
mesh-routed 1–5% of requests by header or weight, or two equal sets of pods. Compare
their metrics with a non-parametric test such as Mann–Whitney U, Kayenta-style. Report
"the fault increased p99 latency by X% (p < 0.01)" rather than absolute thresholds.
This makes scores meaningful in noisy environments.

### S12. Global impact budget
Beyond `maxConcurrentExperiments`, add a cluster- or region-wide budget: the sum over
running experiments of the share of a workload's replicas, or of its traffic, under
fault must stay ≤ X% (Netflix: 5%). The operator computes this at admission.

### S13. Automated experiment suggestions ("Monocle")
- Discover dependencies from service-mesh telemetry or OpenTelemetry traces (which
  service calls which, timeouts, retries, call volume).
- For each dependency, *suggest* (not auto-run) three experiments: dependency failure,
  latency just below the configured timeout, and latency above it. Flag **misaligned
  timeouts**, where a caller's timeout is shorter than the callee's timeout times its
  retries.
- Rank by criticality (call volume, number of dependents, retries) and safety; skip
  recently run ones.
- Suggestions go through the normal submit and approval path. Auto-run is allowed only
  under a `ChaosSchedule` with a standing approval.

### S14. Findings workflow
Turn results into **findings**: a weakness, its evidence, its owner, a status and a
re-test link. Include a review queue so resilience engineers can confirm a finding before
notifying owners; Netflix found this review step valuable. Re-running the experiment
after a fix closes the finding automatically when it passes.

---

## 6. Beyond Netflix

| # | Suggestion | Why |
|---|-----------|-----|
| S15 | **Multi-cluster fleet:** an in-cluster agent with an outbound-only connection to the control plane, per-cluster identity and per-cluster policy | Avoids holding kubeconfigs centrally (threat model T4) |
| S16 | **CI/CD gates:** a scoped service-account API (token exchange, no browser credentials) and a GitHub Actions/GitLab job that runs a scenario on staging and fails the pipeline if the score is below a threshold | Shifts resilience left and makes it routine |
| S17 | **GitOps experiments:** scenarios stored in Git, with commits signed and reviewed, and submission by reference so the spec hash ties back to the commit | Change control and reproducibility |
| S18 | **SLO / error-budget gating:** only run when the service has budget left; record the budget consumed | Aligns chaos with reliability goals |
| S19 | **Game days:** multi-step scenarios with roles, a timeline, notes, and runbook links per step; a post-game-day report | Exercises people and processes, not only software |
| S20 | **Dry-run / target preview:** the operator resolves the targets that *would* be hit (without injecting) and shows them before submit and to approvers | Approvers see real targets, not just selectors |
| S21 | **Scorecards and trends:** per-service resilience and readiness scores over time; regressions flagged | Visible progress; prioritises work |
| S22 | **Evidence export:** a signed PDF/JSON experiment report and audit export to a SIEM (with chain proofs) | Compliance (SOC 2, DORA operational resilience testing) |
| S23 | **More observability providers:** Datadog, CloudWatch and OTel Collector templates behind the same "no user query language" rule | Not every user runs Prometheus |
| S24 | **ChatOps:** Slack/Teams commands for status and emergency stop. Stop is cheap to allow (D8); never allow start or unlock from chat | Faster incident response |
| S25 | **Production hardening:** a KMS/HSM signer for attestations, Helm charts for the control plane and approval service, mTLS between control plane and approval service (replacing the shared token), rate limits per user | Already identified as gaps |

---

## 7. Proposed roadmap

| Phase | Items | Rationale |
|-------|-------|-----------|
| **Next** | S2 incident guard, S10 live abort guards, S7 steady-state pre-check, S6 readiness checks, S20 dry-run preview, S25 KMS signer + deployment | Safety first: these make every existing and future fault safer, and most need no new privileges |
| **Then** | S5 API-only primitives (NetworkPartition, HTTPFault, NodeDrain, ScaleDown), S4 notifications, S3 exclusions/grouping, S8 janitor | Breadth without a privileged agent |
| **Then** | S1 ChaosSchedule + standing approvals, S12 impact budget, S16 CI/CD gates, S21 scorecards | Continuous practice, as Chaos Monkey intended |
| **Later** | S11 baseline comparison, S13 suggestions, S14 findings, S15 multi-cluster, ZoneOutage/Chaos Kong, agent-tier primitives, S17–S19, S22–S24 | Larger investments; some need a service mesh or node agent |

Every item adds tests on the same basis as today: unit tests for the rules, live kind
verification scripts for operator behaviour, and e2e tests for user-facing flows. Security
impacts are recorded in `docs/security/threat-model.md`. In particular, any node-agent
primitive needs its own threat-model entry: privileged DaemonSet, image signing and
attack surface.

---

## Sources
- [Chaos Monkey documentation (Netflix)](https://netflix.github.io/chaosmonkey/)
- [Configuring Chaos Monkey behaviour via Spinnaker](https://netflix.github.io/chaosmonkey/Configuring-behavior-via-Spinnaker/)
- [The Netflix Simian Army (Netflix Tech Blog, 2011)](https://techblog.netflix.com/2011/07/netflix-simian-army.html)
- [The Simian Army overview (Gremlin)](https://gremlin.com/chaos-monkey/the-simian-army)
- [Automating chaos experiments in production (Basiri et al., ICSE 2019)](https://arxiv.org/abs/1905.04648)
- [Summary of the ChAP/Monocle paper (The Morning Paper)](https://blog.acolyer.org/2019/07/05/automating-chaos-experiments-in-production/)
- [Lorin Hochstein: What I have learned doing chaos at Netflix](https://www.chaos.conf.kth.se/wp-content/uploads/sites/28/2018/12/Lorin-Hochstein-What-I-have-learned-doing-chaos-at-Netfix.pdf)
