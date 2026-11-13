#!/usr/bin/env bash
# Installs pinned CLI tools not covered by devcontainer features.
set -euo pipefail

KIND_VERSION="v0.29.0"

go install "sigs.k8s.io/kind@${KIND_VERSION}"

echo "Tool versions:"
go version
node --version
kind version
kubectl version --client
helm version --short
