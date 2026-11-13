#!/usr/bin/env bash
# Installs pinned CLI tools not covered by devcontainer features.
set -euo pipefail

KIND_VERSION="v0.29.0"

# The workspace is bind-mounted from the host with a different owner UID; allow git
# (and Go's VCS stamping) to read it. Scoped to this one directory only.
git config --global --add safe.directory "$(pwd)"

go install "sigs.k8s.io/kind@${KIND_VERSION}"

# kubectl pinned to the kind node version (kind v0.29.0 → Kubernetes v1.33.1) to stay within
# the supported ±1 version skew. Installed from the official, GPG-signed Kubernetes apt repo.
KUBECTL_MINOR="v1.33"
KUBECTL_PKG_VERSION="1.33.1-1.1"
if ! kubectl version --client 2>/dev/null | grep -q "v${KUBECTL_PKG_VERSION%%-*}"; then
  sudo install -d -m 0755 /etc/apt/keyrings
  curl -fsSL "https://pkgs.k8s.io/core:/stable:/${KUBECTL_MINOR}/deb/Release.key" \
    | sudo gpg --dearmor --yes -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
  echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/${KUBECTL_MINOR}/deb/ /" \
    | sudo tee /etc/apt/sources.list.d/kubernetes.list >/dev/null
  sudo apt-get update -o Dir::Etc::sourcelist=sources.list.d/kubernetes.list -o Dir::Etc::sourceparts=- -qq
  sudo apt-get install -y -qq "kubectl=${KUBECTL_PKG_VERSION}"
  sudo apt-mark hold kubectl >/dev/null
fi

# Named volumes are created root-owned; hand node_modules to the dev user, then install
# exactly what package-lock.json pins.
sudo chown "$(id -u):$(id -g)" frontend/node_modules
(cd frontend && npm ci --no-audit --no-fund)

echo "Tool versions:"
go version
node --version
kind version
kubectl version --client
helm version --short
