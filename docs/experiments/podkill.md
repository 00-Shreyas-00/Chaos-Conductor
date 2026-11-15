# PodKill

Deletes up to `count` pods matching a label selector in **one** namespace, then observes
until the workload has as many Ready pods as before.

| Property | Value |
|---|---|
| Risk level | Medium |
| Operator permissions | `pods: get, list, delete`, only in opted-in namespaces |
| Hard limits (API) | `count` 1–10, `gracePeriodSeconds` 0–300 (default 30) |
| Cleanup | None needed: controllers recreate the pods |

## Example

```yaml
apiVersion: chaos.kubechaos.io/v1alpha1
kind: ChaosExperiment
metadata:
  name: web-podkill
  namespace: kubechaos-system        # the only namespace experiments may live in
spec:
  clusterID: dev-kind-01             # must equal the operator's cluster identity
  requestedBy: { issuer: "http://localhost:8180/realms/kubechaos", subject: "alice" }
  maxDuration: 2m                    # hard deadline for the whole experiment
  steps:
    - fault:
        type: PodKill
        target:
          namespace: demo            # must be opted in (label + Helm grant)
          selector: { app: web }     # non-empty; all labels must match
        podKill: { count: 1, gracePeriodSeconds: 0 }
    - wait: { duration: 30s }
```

## What is refused, and why

| Situation | Result |
|---|---|
| Namespace not granted to the operator, or without `chaos.kubechaos.io/enabled=true` | `Rejected / NamespaceNotOptedIn` |
| Namespace or pod labelled `chaos.kubechaos.io/protected=true` | Not selectable |
| Pod without a controller (bare pod), static pod, not Ready, terminating | Not selectable |
| Killing `count` pods would leave a workload with no Ready replica | `Failed`: blast radius exceeded; nothing deleted |
| Selector matches nothing | `Failed`: selector matches no pods |
| Cluster is staging or production (until ChaosPolicy and approvals exist) | `Pending / ExecutionDisabled` |
| Operator restarted between recording intent and recording the result | `Failed / InjectionInterrupted`; never retried |

## Reading the result

```bash
kubectl -n kubechaos-system get chaosexp web-podkill
kubectl -n kubechaos-system get chaosexp web-podkill -o jsonpath='{.status.steps[0]}'
kubectl -n kubechaos-system get events --field-selector involvedObject.name=web-podkill
```

`status.steps[0].targets` lists the exact pods (with UIDs) chosen before anything was
deleted, and `recoveryMillis` records how long the workload took to return to full readiness.
