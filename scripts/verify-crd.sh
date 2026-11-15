#!/usr/bin/env bash
# Verifies, against the live cluster, that the API server itself enforces the ChaosExperiment
# contract (schema + CEL + admission policy) and that the operator records its decision.
# Run with an admin kubeconfig after `make operator-deploy`.
set -uo pipefail

NS=kubechaos-system
CLUSTER_ID=$(kubectl -n "$NS" get cm kubechaos-cluster-identity -o jsonpath='{.data.clusterID}')
fail=0
pass() { printf "  ok    %s\n" "$1"; }
bad()  { printf "  FAIL  %s\n        %s\n" "$1" "$2"; fail=1; }

# exp NAME NAMESPACE STEPS_JSON [EXTRA_SPEC_JSON] -> ChaosExperiment JSON
exp() {
  cat <<EOF
{"apiVersion":"chaos.kubechaos.io/v1alpha1","kind":"ChaosExperiment",
 "metadata":{"name":"$1","namespace":"$2"},
 "spec":{"clusterID":"$CLUSTER_ID","requestedBy":{"issuer":"http://localhost:8180/realms/kubechaos","subject":"alice"},
         "maxDuration":"2m","steps":$3 ${4:+,$4}}}
EOF
}
KILL='{"fault":{"type":"PodKill","target":{"namespace":"demo","selector":{"app":"web"}},"podKill":{"count":1}}}'
WAIT='{"wait":{"duration":"30s"}}'

accept() { # description json
  if out=$(echo "$2" | kubectl apply --dry-run=server -f - 2>&1); then pass "accepted: $1"; else bad "should be accepted: $1" "$out"; fi
}
reject() { # description json expected-substring
  if out=$(echo "$2" | kubectl apply --dry-run=server -f - 2>&1); then bad "should be rejected: $1" "$out"
  elif [[ "$out" == *"$3"* ]]; then pass "rejected: $1"
  else bad "rejected for the wrong reason: $1" "$out"; fi
}

echo "Schema / CEL validation (server-side dry run):"
accept "valid PodKill + wait"                 "$(exp v1 $NS "[$KILL,$WAIT]")"
reject "unknown fault type"                   "$(exp r1 $NS '[{"fault":{"type":"ShellCommand","target":{"namespace":"demo","selector":{"app":"web"}}}}]')" 'Unsupported value: "ShellCommand"'
reject "PodKill without parameters"           "$(exp r2 $NS '[{"fault":{"type":"PodKill","target":{"namespace":"demo","selector":{"app":"web"}}}}]')" "requires podKill parameters"
reject "count 10000 (blast radius cap)"       "$(exp r3 $NS '[{"fault":{"type":"PodKill","target":{"namespace":"demo","selector":{"app":"web"}},"podKill":{"count":10000}}}]')" "less than or equal to 10"
reject "count 0"                              "$(exp r4 $NS '[{"fault":{"type":"PodKill","target":{"namespace":"demo","selector":{"app":"web"}},"podKill":{"count":0}}}]')" "greater than or equal to 1"
reject "target kube-system"                   "$(exp r5 $NS '[{"fault":{"type":"PodKill","target":{"namespace":"kube-system","selector":{"app":"web"}},"podKill":{"count":1}}}]')" "protected"
reject "target kubechaos-system"              "$(exp r6 $NS '[{"fault":{"type":"PodKill","target":{"namespace":"kubechaos-system","selector":{"app":"web"}},"podKill":{"count":1}}}]')" "protected"
reject "empty selector (= every pod)"         "$(exp r7 $NS '[{"fault":{"type":"PodKill","target":{"namespace":"demo","selector":{}},"podKill":{"count":1}}}]')" "should have at least 1 properties"
reject "invalid selector key"                 "$(exp r8 $NS '[{"fault":{"type":"PodKill","target":{"namespace":"demo","selector":{"bad key!":"x"}},"podKill":{"count":1}}}]')" "valid label keys"
reject "step with fault AND wait"             "$(exp r9 $NS "[{\"fault\":$(echo "$KILL" | sed 's/^{"fault"://; s/}$//'),\"wait\":{\"duration\":\"5s\"}}]")" "exactly one of fault or wait"
reject "empty step"                           "$(exp r10 $NS '[{}]')" "exactly one of fault or wait"
reject "no steps"                             "$(exp r11 $NS '[]')" "should have at least 1 items"
reject "21 steps"                             "$(exp r12 $NS "[$(printf "$WAIT,%.0s" {1..20})$KILL]")" "must have at most 20 items"
reject "maxDuration 2h"                       "$(exp r13 $NS "[$KILL]" | sed 's/"maxDuration":"2m"/"maxDuration":"2h"/')" "between 10s and 1h"
reject "maxDuration not a duration"           "$(exp r14 $NS "[$KILL]" | sed 's/"maxDuration":"2m"/"maxDuration":"forever"/')" "maxDuration"
reject "wait 11m"                             "$(exp r15 $NS "[$KILL,{\"wait\":{\"duration\":\"11m\"}}]")" "between 1s and 10m"
reject "grace period 301s"                    "$(exp r16 $NS '[{"fault":{"type":"PodKill","target":{"namespace":"demo","selector":{"app":"web"}},"podKill":{"count":1,"gracePeriodSeconds":301}}}]')" "less than or equal to 300"
reject "missing requestedBy"                  "$(exp r17 $NS "[$KILL]" | sed 's/"requestedBy":{[^}]*},//')" "requestedBy"
reject "unknown field (strict validation)"    "$(exp r18 $NS "[$KILL]" '"command":"kubectl delete pods --all"')" 'unknown field "spec.command"'

echo "Admission policy:"
kubectl create ns kubechaos-crd-test >/dev/null 2>&1 || true
reject "experiment outside kubechaos-system"  "$(exp n1 kubechaos-crd-test "[$KILL]")" "may only exist in namespace kubechaos-system"
kubectl delete ns kubechaos-crd-test --wait=false >/dev/null 2>&1

echo "Immutability and operator decision (real objects):"
kubectl -n "$NS" delete chaosexperiment crd-verify-ok crd-verify-other --ignore-not-found >/dev/null
# Starts with a 60s wait and is cancelled before its kill step: verifies execution starts in a
# development cluster without ever killing a pod.
exp crd-verify-ok $NS "[{\"wait\":{\"duration\":\"60s\"}},$KILL]" | kubectl apply -f - >/dev/null
exp crd-verify-other $NS "[$KILL]" | sed "s/\"clusterID\":\"$CLUSTER_ID\"/\"clusterID\":\"prod-eu-1\"/" | kubectl apply -f - >/dev/null
phase() { for _ in $(seq 1 30); do p=$(kubectl -n "$NS" get chaosexperiment "$1" -o jsonpath='{.status.phase}'); [ -n "$p" ] && { echo "$p"; return; }; sleep 1; done; echo "<none>"; }
[ "$(phase crd-verify-ok)" = "Running" ]     && pass "operator: valid experiment in opted-in namespace -> Running (waiting)" || bad "operator: valid experiment" "phase=$(phase crd-verify-ok)"
[ "$(phase crd-verify-other)" = "Rejected" ] && pass "operator: other cluster's experiment -> Rejected (ClusterMismatch)" || bad "operator: clusterID mismatch" "phase=$(phase crd-verify-other)"
reason=$(kubectl -n "$NS" get chaosexperiment crd-verify-other -o jsonpath='{.status.conditions[?(@.type=="Accepted")].reason}')
[ "$reason" = "ClusterMismatch" ] && pass "condition reason ClusterMismatch" || bad "condition reason" "$reason"

out=$(kubectl -n "$NS" patch chaosexperiment crd-verify-ok --type merge -p '{"spec":{"steps":[{"fault":{"type":"PodKill","target":{"namespace":"demo","selector":{"app":"web"}},"podKill":{"count":10}}}]}}' 2>&1) \
  && bad "steps must be immutable" "$out" || { [[ "$out" == *"spec is immutable"* ]] && pass "rejected: changing steps after creation" || bad "immutability reason" "$out"; }
out=$(kubectl -n "$NS" patch chaosexperiment crd-verify-ok --type merge -p "{\"spec\":{\"clusterID\":\"other-cluster\"}}" 2>&1) \
  && bad "clusterID must be immutable" "$out" || pass "rejected: changing clusterID after creation"
kubectl -n "$NS" patch chaosexperiment crd-verify-ok --type merge -p '{"spec":{"cancel":true}}' >/dev/null 2>&1 \
  && pass "allowed: cancel false -> true" || bad "cancel should be allowed" ""
out=$(kubectl -n "$NS" patch chaosexperiment crd-verify-ok --type merge -p '{"spec":{"cancel":false}}' 2>&1) \
  && bad "cancel must not be revertible" "$out" || { [[ "$out" == *"cannot be reverted"* ]] && pass "rejected: cancel true -> false" || bad "revert reason" "$out"; }
for _ in $(seq 1 20); do [ "$(kubectl -n "$NS" get chaosexperiment crd-verify-ok -o jsonpath='{.status.phase}')" = "Aborted" ] && break; sleep 1; done
[ "$(kubectl -n "$NS" get chaosexperiment crd-verify-ok -o jsonpath='{.status.phase}')" = "Aborted" ] \
  && pass "operator: cancelled during wait -> Aborted (kill step never ran)" || bad "operator: cancel" "phase=$(kubectl -n "$NS" get chaosexperiment crd-verify-ok -o jsonpath='{.status.phase}')"
out=$(kubectl -n "$NS" patch chaosexperiment crd-verify-other --subresource=status --type merge \
  --as=system:serviceaccount:default:default -p '{"status":{"phase":"Completed"}}' 2>&1) \
  && bad "arbitrary SA must not write status" "$out" || pass "rejected: status write by an unrelated ServiceAccount"

kubectl -n "$NS" delete chaosexperiment crd-verify-ok crd-verify-other --ignore-not-found >/dev/null
exit $fail
