#!/usr/bin/env bash
# Asserts the operator ServiceAccount's effective permissions against the live cluster.
# Every line is an expectation; any mismatch fails the script. Run with an admin kubeconfig.
set -euo pipefail

NS=kubechaos-system
SA="system:serviceaccount:${NS}:kubechaos-operator"
fail=0

check() { # expected verb resource [extra kubectl args...]
  local want=$1; shift
  local got
  got=$(kubectl auth can-i --as="$SA" "$@" 2>/dev/null || true)
  if [ "$got" = "$want" ]; then
    printf "  ok    %-4s %s\n" "$want" "$*"
  else
    printf "  FAIL  want %-4s got %-4s %s\n" "$want" "$got" "$*"
    fail=1
  fi
}

echo "Must be allowed:"
check yes get configmaps/kubechaos-cluster-identity -n "$NS"
check yes create leases.coordination.k8s.io -n "$NS"
check yes update leases.coordination.k8s.io/kubechaos-operator.chaos.kubechaos.io -n "$NS"
check yes create events -n "$NS"
check yes list chaosexperiments.chaos.kubechaos.io -n "$NS"
check yes watch chaosexperiments.chaos.kubechaos.io -n "$NS"
check yes update chaosexperiments.chaos.kubechaos.io --subresource=status -n "$NS"

echo "Must be denied (experiments: status only, own namespace only):"
check no  create chaosexperiments.chaos.kubechaos.io -n "$NS"
check no  update chaosexperiments.chaos.kubechaos.io -n "$NS"
check no  patch chaosexperiments.chaos.kubechaos.io -n "$NS"
check no  delete chaosexperiments.chaos.kubechaos.io -n "$NS"
check no  update chaosexperiments.chaos.kubechaos.io --subresource=finalizers -n "$NS"
check no  list chaosexperiments.chaos.kubechaos.io -n default
check no  list chaosexperiments.chaos.kubechaos.io -A
check no  update customresourcedefinitions.apiextensions.k8s.io
check no  delete validatingadmissionpolicies.admissionregistration.k8s.io

echo "Must be denied (foundation step 10 — no workload access yet):"
check no  get configmaps/other -n "$NS"
check no  list configmaps -n "$NS"
check no  update configmaps/kubechaos-cluster-identity -n "$NS"
check no  delete configmaps/kubechaos-cluster-identity -n "$NS"
check no  update leases.coordination.k8s.io/someone-elses-lease -n "$NS"
check no  create leases.coordination.k8s.io -n kube-system
check no  get secrets -n "$NS"
check no  list secrets -A
check no  delete pods -n default
check no  delete pods -n kube-system
check no  list pods -A
check no  create pods/exec -n default
check no  patch pods/ephemeralcontainers -n default
check no  create pods/eviction -n default
check no  get nodes
check no  patch nodes
check no  create clusterroles
check no  create rolebindings -n "$NS"
check no  escalate roles -n "$NS"
check no  bind clusterroles
check no  impersonate serviceaccounts
check no  create serviceaccounts/token -n "$NS"
check no  delete namespaces
check no  update deployments.apps -n "$NS"
check no  '*' '*'

exit $fail
