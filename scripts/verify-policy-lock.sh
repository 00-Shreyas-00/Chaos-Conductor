#!/usr/bin/env bash
# Live checks for ChaosPolicy enforcement, the emergency stop (kubechaosctl) and the admission
# policies. Run with an admin kubeconfig after `make operator-deploy`.
set -uo pipefail

NS=kubechaos-system
CTL=${CTL:-bin/kubechaosctl}
CLUSTER_ID=$(kubectl -n "$NS" get cm kubechaos-cluster-identity -o jsonpath='{.data.clusterID}')
CP="system:serviceaccount:$NS:kubechaos-control-plane"
fail=0
pass() { printf "  ok    %s\n" "$1"; }
bad()  { printf "  FAIL  %s\n        %s\n" "$1" "$2"; fail=1; }

exp() { # NAME STEPS_JSON [MAXDUR]
  kubectl -n "$NS" delete chaosexperiment "$1" --ignore-not-found --wait=true >/dev/null
  cat <<EOF | kubectl apply -f - >/dev/null
{"apiVersion":"chaos.kubechaos.io/v1alpha1","kind":"ChaosExperiment","metadata":{"name":"$1","namespace":"$NS"},
 "spec":{"clusterID":"$CLUSTER_ID","requestedBy":{"issuer":"verify","subject":"script"},"maxDuration":"${3:-2m}","steps":$2}}
EOF
}
phase()  { kubectl -n "$NS" get chaosexperiment "$1" -o jsonpath='{.status.phase}'; }
reason() { kubectl -n "$NS" get chaosexperiment "$1" -o jsonpath="{.status.conditions[?(@.type==\"$2\")].reason}"; }
wait_phase() { for _ in $(seq 1 60); do [[ " $2 " == *" $(phase "$1") "* ]] && return 0; sleep 1; done; return 1; }
KILL1='[{"fault":{"type":"PodKill","target":{"namespace":"demo","selector":{"app":"web"}},"podKill":{"count":1,"gracePeriodSeconds":0}}}]'
KILL3='[{"fault":{"type":"PodKill","target":{"namespace":"demo","selector":{"app":"web"}},"podKill":{"count":3}}}]'
WAITKILL='[{"wait":{"duration":"60s"}},{"fault":{"type":"PodKill","target":{"namespace":"demo","selector":{"app":"web"}},"podKill":{"count":1}}}]'

echo "ChaosPolicy enforcement:"
exp p1 "$KILL3"; wait_phase p1 "Rejected"
[ "$(reason p1 Accepted)" = PolicyViolation ] && pass "count 3 > policy max 2 -> Rejected PolicyViolation" || bad "policy count" "$(phase p1) $(reason p1 Accepted)"
POLICY=$(kubectl get chaospolicy default -o yaml)
kubectl delete chaospolicy default >/dev/null
exp p2 "$KILL1"; wait_phase p2 "Rejected"
[ "$(reason p2 Accepted)" = PolicyUnavailable ] && pass "no policy -> Rejected PolicyUnavailable (fail closed)" || bad "no policy" "$(phase p2) $(reason p2 Accepted)"
kubectl apply --server-side -f deploy/k8s/chaospolicy-dev.yaml >/dev/null
out=$(kubectl apply --dry-run=server -f - 2>&1 <<EOF
apiVersion: chaos.kubechaos.io/v1alpha1
kind: ChaosPolicy
metadata: { name: default }
spec:
  environment: production
  allowedFaults: [PodKill]
  allowedNamespaces: [demo]
  limits: { maxPodKillCount: 1, maxDuration: 5m, maxConcurrentExperiments: 1 }
  approval: { required: Never }
EOF
) && bad "production policy without approval must be refused" "$out" || pass "API refuses a production policy without approvals (CEL)"
out=$(kubectl apply --dry-run=server -f - 2>&1 <<EOF
apiVersion: chaos.kubechaos.io/v1alpha1
kind: ChaosPolicy
metadata: { name: second }
spec: { environment: development, allowedFaults: [], allowedNamespaces: [], limits: { maxPodKillCount: 1, maxDuration: 5m, maxConcurrentExperiments: 1 }, approval: { required: Never } }
EOF
) && bad "a second policy must be refused" "$out" || pass "API refuses a second ChaosPolicy (must be named default)"

echo "Emergency stop:"
exp l1 "$WAITKILL"; wait_phase l1 "Running" && pass "experiment running (waiting before its kill step)" || bad "precondition" "$(phase l1)"
B=$(kubectl -n demo get pods -l app=web -o jsonpath='{.items[*].metadata.uid}')
"$CTL" emergency-stop --reason "verify-policy-lock" | sed 's/^/        /'
wait_phase l1 "Aborted" && [ "$(reason l1 Finished)" = SystemLocked ] && pass "running experiment aborted promptly (SystemLocked)" || bad "abort on lock" "$(phase l1) $(reason l1 Finished)"
exp l2 "$KILL1"; wait_phase l2 "Rejected"
[ "$(reason l2 Accepted)" = SystemLocked ] && pass "new experiment while locked -> Rejected SystemLocked" || bad "locked admission" "$(phase l2) $(reason l2 Accepted)"
[ "$B" = "$(kubectl -n demo get pods -l app=web -o jsonpath='{.items[*].metadata.uid}')" ] && pass "no pod deleted while locked" || bad "pods changed while locked" ""
st=$("$CTL" status); [[ "$st" == *ENGAGED* ]] && pass "kubechaosctl status shows the lock" || bad "status" "$st"
[ "$(kubectl auth can-i --as="$CP" create chaoslocks.chaos.kubechaos.io)" = yes ] && pass "control plane CAN engage the lock (create)" || bad "cp create lock" ""
[ "$(kubectl auth can-i --as="$CP" delete chaoslocks.chaos.kubechaos.io)" = no ] && pass "control plane CANNOT unlock (delete)" || bad "cp delete lock" ""
[ "$(kubectl auth can-i --as=system:serviceaccount:$NS:kubechaos-operator delete chaoslocks.chaos.kubechaos.io)" = no ] && pass "operator CANNOT unlock" || bad "operator delete lock" ""
"$CTL" unlock >/dev/null 2>&1 && bad "unlock without --yes must refuse" "" || pass "unlock without --yes refused"
"$CTL" unlock --yes | sed 's/^/        /'
exp l3 "$WAITKILL"; wait_phase l3 "Running" && pass "after unlock, experiments run again" || bad "after unlock" "$(phase l3) $(reason l3 Accepted)"
kubectl -n "$NS" patch chaosexperiment l3 --type merge -p '{"spec":{"cancel":true}}' >/dev/null; wait_phase l3 "Aborted"

echo "Admission policies:"
out=$(cat <<EOF | kubectl create -f - 2>&1
apiVersion: chaos.kubechaos.io/v1alpha1
kind: ChaosAttestationUse
metadata: { name: jti-forged }
spec: { experiment: x, specSHA256: y }
EOF
) && { bad "admin must not create attestation-use records" "$out"; kubectl delete chaosattestationuse jti-forged >/dev/null; } || pass "only the operator may record attestation use "
exp a1 "$WAITKILL"; wait_phase a1 "Running"
out=$(kubectl -n "$NS" annotate chaosexperiment a1 chaos.kubechaos.io/approval=forged 2>&1) \
  && bad "approval annotation must be immutable" "$out" || pass "approval annotation cannot be added after creation"
kubectl -n "$NS" patch chaosexperiment a1 --type merge -p '{"spec":{"cancel":true}}' >/dev/null; wait_phase a1 "Aborted"
[ "$(kubectl auth can-i --as="$CP" update chaosexperiments.chaos.kubechaos.io --subresource=status -n $NS)" = no ] && pass "control plane cannot write experiment status" || bad "cp status" ""
[ "$(kubectl auth can-i --as="$CP" delete pods -n demo)" = no ] && pass "control plane cannot touch workloads" || bad "cp pods" ""
[ "$(kubectl auth can-i --as="$CP" update chaospolicies.chaos.kubechaos.io)" = no ] && pass "control plane cannot change policy" || bad "cp policy" ""

kubectl -n "$NS" delete chaosexperiment p1 p2 l1 l2 l3 a1 --ignore-not-found >/dev/null
exit $fail
