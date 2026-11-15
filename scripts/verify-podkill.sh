#!/usr/bin/env bash
# Live PodKill scenarios against the demo workloads (deploy/demo/demo.yaml) in kind.
# For every scenario it records the UIDs of ALL demo pods before and after, so it verifies
# not only the experiment's phase but exactly which pods were (and were not) deleted.
# Run with an admin kubeconfig after `make operator-deploy`. Deletes demo pods by design.
set -uo pipefail

NS=kubechaos-system
CLUSTER_ID=$(kubectl -n "$NS" get cm kubechaos-cluster-identity -o jsonpath='{.data.clusterID}')
fail=0
pass() { printf "  ok    %s\n" "$1"; }
bad()  { printf "  FAIL  %s\n        %s\n" "$1" "$2"; fail=1; }

uids() { kubectl -n "${1:-demo}" get pods -o jsonpath='{range .items[*]}{.metadata.labels.app}={.metadata.uid}{"\n"}{end}' | sort; }
ready_web() { kubectl -n demo get pods -l app=web -o jsonpath='{range .items[*]}{.status.conditions[?(@.type=="Ready")].status}{" "}{.metadata.deletionTimestamp}{"\n"}{end}' | grep -c '^True $' ; }
settle() { for _ in $(seq 1 60); do [ "$(ready_web)" = 3 ] && [ "$(kubectl -n demo get pods -l app=web --no-headers | wc -l)" = 3 ] && return; sleep 1; done; echo "  (web did not settle to 3 Ready)"; }

# run NAME STEPS_JSON [MAXDUR] -> sets PHASE REASON MSG; waits for a terminal phase
run() {
  kubectl -n "$NS" delete chaosexperiment "$1" --ignore-not-found --wait=true >/dev/null
  cat <<EOF | kubectl apply -f - >/dev/null
{"apiVersion":"chaos.kubechaos.io/v1alpha1","kind":"ChaosExperiment","metadata":{"name":"$1","namespace":"$NS"},
 "spec":{"clusterID":"$CLUSTER_ID","requestedBy":{"issuer":"verify-podkill","subject":"script"},"maxDuration":"${3:-90s}","steps":$2}}
EOF
  [ "${NOWAIT:-}" = 1 ] && return
  wait_terminal "$1"
}
wait_terminal() {
  for _ in $(seq 1 120); do
    PHASE=$(kubectl -n "$NS" get chaosexperiment "$1" -o jsonpath='{.status.phase}')
    case "$PHASE" in Completed|Failed|Rejected|Aborted) break;; esac; sleep 1
  done
  REASON=$(kubectl -n "$NS" get chaosexperiment "$1" -o jsonpath='{.status.conditions[?(@.type=="Finished")].reason}')
  [ -z "$REASON" ] && REASON=$(kubectl -n "$NS" get chaosexperiment "$1" -o jsonpath='{.status.conditions[?(@.type=="Accepted")].reason}')
  MSG=$(kubectl -n "$NS" get chaosexperiment "$1" -o jsonpath='{.status.message}')
}
kill() { echo "{\"fault\":{\"type\":\"PodKill\",\"target\":{\"namespace\":\"${3:-demo}\",\"selector\":$1},\"podKill\":{\"count\":$2,\"gracePeriodSeconds\":0}}}"; }
changed() { comm -3 <(echo "$1") <(echo "$2") | grep -c '^[^\t]' ; }   # entries of $1 no longer present
expect_untouched() { # desc before after
  [ "$2" = "$3" ] && pass "$1: no pod deleted" || bad "$1: pods changed" "$(diff <(echo "$2") <(echo "$3"))"
}

settle
echo "Scenario 1: kill 1 of 3 web pods, then wait"
B=$(uids); run s1 "[$(kill '{"app":"web"}' 1),{\"wait\":{\"duration\":\"5s\"}}]"; A=$(uids)
[ "$PHASE" = Completed ] && pass "phase Completed ($MSG)" || bad "phase" "$PHASE $REASON: $MSG"
gone=$(comm -23 <(echo "$B") <(echo "$A")); new=$(comm -13 <(echo "$B") <(echo "$A"))
[ "$(echo "$gone" | grep -c .)" = 1 ] && [[ "$gone" == web=* ]] && pass "exactly one web pod deleted" || bad "deleted set" "$gone"
[ "$(echo "$new" | grep -c '^web=')" -ge 1 ] && pass "replacement pod created by the ReplicaSet" || bad "replacement" "$new"
[ "$(comm -23 <(echo "$B" | grep -v '^web=') <(echo "$A" | grep -v '^web='))" = "" ] && pass "solo, db and orphan untouched" || bad "collateral damage" "$(diff <(echo "$B") <(echo "$A"))"
victim=$(kubectl -n "$NS" get chaosexperiment s1 -o jsonpath='{.status.steps[0].targets[0].uid}')
[[ "$gone" == "web=$victim" ]] && pass "deleted pod UID equals the recorded intent" || bad "intent vs reality" "recorded $victim, deleted $gone"
rec=$(kubectl -n "$NS" get chaosexperiment s1 -o jsonpath='{.status.steps[0].recoveryMillis}')
[ -n "$rec" ] && pass "recovery time recorded: ${rec}ms" || bad "recovery time" "missing"
ev=$(kubectl -n "$NS" get events --field-selector involvedObject.name=s1 -o jsonpath='{range .items[*]}{.reason}{" "}{end}')
for r in Started TargetsSelected PodDeleted Recovered Completed; do [[ " $ev " == *" $r "* ]] || { bad "timeline event $r missing" "$ev"; continue 2; }; done
pass "timeline events: $ev"

settle
echo "Scenario 2: kill 2 of 3 web pods"
B=$(uids); run s2 "[$(kill '{"app":"web"}' 2)]"; A=$(uids)
[ "$PHASE" = Completed ] && [ "$(comm -23 <(echo "$B") <(echo "$A") | grep -c '^web=')" = 2 ] && pass "Completed, exactly 2 web pods deleted" || bad "kill 2" "$PHASE $MSG"

settle
echo "Scenario 3: kill 3 of 3 web pods (would remove the last Ready replica)"
B=$(uids); run s3 "[$(kill '{"app":"web"}' 3)]"; A=$(uids)
[ "$PHASE" = Failed ] && [[ "$MSG" == *"blast radius exceeded"* ]] && pass "Failed: $MSG" || bad "kill 3" "$PHASE $MSG"
expect_untouched "kill 3" "$B" "$A"

echo "Scenario 4: kill the only replica of solo"
B=$(uids); run s4 "[$(kill '{"app":"solo"}' 1)]"; A=$(uids)
[ "$PHASE" = Failed ] && [[ "$MSG" == *"blast radius exceeded"* ]] && pass "Failed: blast radius" || bad "solo" "$PHASE $MSG"
expect_untouched "solo" "$B" "$A"

echo "Scenario 5: protected pods (db)"
B=$(uids); run s5 "[$(kill '{"app":"db"}' 1)]"; A=$(uids)
[ "$PHASE" = Failed ] && [[ "$MSG" == *"no eligible pods"* ]] && pass "Failed: no eligible pods" || bad "protected" "$PHASE $MSG"
expect_untouched "protected" "$B" "$A"

echo "Scenario 6: bare pod without a controller (orphan)"
B=$(uids); run s6 "[$(kill '{"app":"orphan"}' 1)]"; A=$(uids)
[ "$PHASE" = Failed ] && [[ "$MSG" == *"no eligible pods"* ]] && pass "Failed: no eligible pods" || bad "orphan" "$PHASE $MSG"
expect_untouched "orphan" "$B" "$A"

echo "Scenario 7: selector matching nothing"
run s7 "[$(kill '{"app":"does-not-exist"}' 1)]"
[ "$PHASE" = Failed ] && [[ "$MSG" == *"matches no pods"* ]] && pass "Failed: selector matches no pods" || bad "no match" "$PHASE $MSG"

echo "Scenario 8: namespace labelled but NOT granted by RBAC"
kubectl create ns chaos-notgranted >/dev/null 2>&1; kubectl label ns chaos-notgranted chaos.kubechaos.io/enabled=true --overwrite >/dev/null
kubectl -n chaos-notgranted create deployment web --image=registry.k8s.io/pause@sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a --replicas=2 >/dev/null 2>&1
kubectl -n chaos-notgranted rollout status deployment/web --timeout=90s >/dev/null
B=$(uids chaos-notgranted); run s8 "[$(kill '{"app":"web"}' 1 chaos-notgranted)]"; A=$(uids chaos-notgranted)
[ "$PHASE" = Rejected ] && [ "$REASON" = NamespaceNotOptedIn ] && pass "Rejected: NamespaceNotOptedIn (RBAC denies the operator)" || bad "not granted" "$PHASE $REASON $MSG"
expect_untouched "not granted" "$B" "$A"
kubectl delete ns chaos-notgranted --wait=false >/dev/null

echo "Scenario 9: granted namespace with the opt-in label removed"
kubectl label ns demo chaos.kubechaos.io/enabled- >/dev/null
B=$(uids); run s9 "[$(kill '{"app":"web"}' 1)]"; A=$(uids)
kubectl label ns demo chaos.kubechaos.io/enabled=true --overwrite >/dev/null
[ "$PHASE" = Rejected ] && [ "$REASON" = NamespaceNotOptedIn ] && pass "Rejected: NamespaceNotOptedIn (label missing)" || bad "label gate" "$PHASE $REASON $MSG"
expect_untouched "label gate" "$B" "$A"

echo "Scenario 10: cancel while waiting (before the kill step)"
B=$(uids); NOWAIT=1 run s10 "[{\"wait\":{\"duration\":\"30s\"}},$(kill '{"app":"web"}' 1)]"
for _ in $(seq 1 20); do [ "$(kubectl -n "$NS" get chaosexperiment s10 -o jsonpath='{.status.steps[0].phase}')" = Running ] && break; sleep 1; done
kubectl -n "$NS" patch chaosexperiment s10 --type merge -p '{"spec":{"cancel":true}}' >/dev/null
wait_terminal s10; A=$(uids)
steps=$(kubectl -n "$NS" get chaosexperiment s10 -o jsonpath='{.status.steps[*].phase}')
[ "$PHASE" = Aborted ] && [ "$steps" = "Skipped Skipped" ] && pass "Aborted, steps: $steps" || bad "cancel" "$PHASE steps=$steps $MSG"
expect_untouched "cancel" "$B" "$A"

kubectl -n "$NS" delete chaosexperiment s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 --ignore-not-found >/dev/null
settle
exit $fail
