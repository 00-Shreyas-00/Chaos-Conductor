# KubeChaos developer entry points. Intended to run inside the devcontainer (D15).
SHELL         := /usr/bin/env bash
.SHELLFLAGS   := -euo pipefail -c
.DEFAULT_GOAL := help

KIND_CLUSTER  := kubechaos-dev
COMPOSE       := docker compose -f docker-compose.dev.yml --env-file .env

.PHONY: help
help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

## ---------- local environment ----------

.PHONY: env
env: ## Create .env / add missing keys with random dev-only secrets (never overwrites, never committed)
	@bash scripts/gen-env.sh .env

.PHONY: dev
dev: env infra-up kind-up ## Start local infrastructure: Postgres, Keycloak, kind cluster
	@echo "Infrastructure ready. Postgres :5432, Keycloak http://localhost:8180, kind context kind-$(KIND_CLUSTER)"

.PHONY: dev-down
dev-down: infra-down kind-down ## Stop everything (keeps volumes)

.PHONY: dev-reset
dev-reset: ## Destroy infrastructure INCLUDING data volumes and the kind cluster
	$(COMPOSE) down -v
	kind delete cluster --name $(KIND_CLUSTER) || true

.PHONY: infra-up
infra-up: env ## Start Postgres + Keycloak and wait for health
	$(COMPOSE) up -d --wait

.PHONY: keycloak-reset
keycloak-reset: env ## Recreate Keycloak's dev data so the realm is re-imported from deploy/keycloak/import
	$(COMPOSE) rm -sf keycloak
	-docker volume rm kubechaos-dev_keycloak-data
	$(COMPOSE) up -d --wait keycloak

.PHONY: infra-down
infra-down: ## Stop Postgres + Keycloak
	$(COMPOSE) down

.PHONY: kind-up
kind-up: ## Create the kind cluster if absent
	@if kind get clusters | grep -qx '$(KIND_CLUSTER)'; then \
	  echo "kind cluster $(KIND_CLUSTER) already exists; (re)exporting kubeconfig"; \
	  kind export kubeconfig --name $(KIND_CLUSTER); \
	else \
	  kind create cluster --config deploy/kind/kind-config.yaml --wait 120s; \
	fi
	@kubectl --context kind-$(KIND_CLUSTER) wait --for=condition=Ready nodes --all --timeout=180s || { \
	  echo "Nodes not Ready. After a devcontainer/Docker restart kind nodes can come back with duplicate IPs;"; \
	  echo "recreate the cluster with: make kind-down kind-up  (then redeploy: make operator-image operator-deploy)"; exit 1; }
	@dups=$$(kubectl --context kind-$(KIND_CLUSTER) get nodes -o jsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}' | sort | uniq -d); \
	if [ -n "$$dups" ]; then \
	  echo "kind nodes share IP(s) $$dups (happens after a Docker restart); Ready status is stale and networking is broken."; \
	  echo "recreate the cluster with: make kind-down kind-up  (then redeploy: make operator-image operator-deploy)"; exit 1; fi
	kubectl --context kind-$(KIND_CLUSTER) get nodes

.PHONY: kind-down
kind-down: ## Delete the kind cluster
	kind delete cluster --name $(KIND_CLUSTER) || true

## ---------- backend ----------

# Dev DSNs are derived from .env (hex passwords are URL-safe). Plaintext is allowed only
# because KUBECHAOS_ENV=development; the API refuses non-verify-full DSNs elsewhere.
DB_HOST := 127.0.0.1:5432
dsn = postgres://$(1):$${$(2)}@$(DB_HOST)/kubechaos?sslmode=disable
BACKEND_DEV_ENV = set -a; . ./.env; set +a; export KUBECHAOS_ENV=development; \
	export KUBECHAOS_DATABASE_URL="$(call dsn,kubechaos_app,KUBECHAOS_APP_PASSWORD)"; \
	export KUBECHAOS_MIGRATE_DATABASE_URL="$(call dsn,kubechaos_migrator,KUBECHAOS_MIGRATOR_PASSWORD)"; \
	export KUBECHAOS_PUBLIC_URL="$${KUBECHAOS_PUBLIC_URL:-http://localhost:4200}"; \
	export KUBECHAOS_OIDC_ISSUER="http://localhost:8180/realms/kubechaos"; \
	export KUBECHAOS_OIDC_CLIENT_ID="kubechaos-api"; \
	export KUBECHAOS_HTTP_ADDR="$${KUBECHAOS_HTTP_ADDR:-0.0.0.0:8080}"

.PHONY: test
test: ## Run Go unit tests
	go vet ./backend/...
	go test -count=1 ./backend/...

.PHONY: test-integration
test-integration: env ## Run Go integration tests against dev Postgres (needs make infra-up)
	@$(BACKEND_DEV_ENV); \
	export KUBECHAOS_TEST_MIGRATOR_URL="$$KUBECHAOS_MIGRATE_DATABASE_URL"; \
	export KUBECHAOS_TEST_APP_URL="$$KUBECHAOS_DATABASE_URL"; \
	export KUBECHAOS_TEST_AUDITOR_URL="$(call dsn,kubechaos_auditor_ro,KUBECHAOS_AUDITOR_PASSWORD)"; \
	go test -count=1 -tags integration ./backend/...

.PHONY: test-e2e
test-e2e: env ## OIDC end-to-end tests against dev Keycloak + Postgres (needs make dev migrate; not with make api)
	@$(BACKEND_DEV_ENV); go test -count=1 -tags e2e -run E2E -v ./backend/internal/api/

.PHONY: migrate
migrate: env ## Apply database migrations (migrator role)
	@$(BACKEND_DEV_ENV); go run ./backend/cmd/kubechaos-api migrate up

.PHONY: sessions-revoke
sessions-revoke: env ## Break-glass: revoke sessions, e.g. make sessions-revoke ARGS="--role admin"
	@$(BACKEND_DEV_ENV); go run ./backend/cmd/kubechaos-api sessions revoke $(ARGS)

.PHONY: api
api: env ## Run the control plane API on :8080 inside the devcontainer (reachable by Keycloak for back-channel logout)
	@$(BACKEND_DEV_ENV); go run ./backend/cmd/kubechaos-api serve

## ---------- API types / CRDs ----------

# Code generators are pinned in tools/go.mod (separate module: shipped modules stay lean).
CONTROLLER_GEN := bin/controller-gen
$(CONTROLLER_GEN): tools/go.mod tools/go.sum
	cd tools && GOWORK=off go build -o ../$(CONTROLLER_GEN) sigs.k8s.io/controller-tools/cmd/controller-gen

.PHONY: generate
generate: $(CONTROLLER_GEN) ## Regenerate deepcopy code and CRD manifests from pkg/chaosapi types
	cd pkg/chaosapi && ../../$(CONTROLLER_GEN) object paths=./...
	cd pkg/chaosapi && ../../$(CONTROLLER_GEN) crd paths=./... output:crd:artifacts:config=../../deploy/crds

.PHONY: generate-check
generate-check: generate ## Fail if generated code/CRDs are out of date
	@git diff --exit-code -- pkg/chaosapi deploy/crds && echo "generated files are up to date"

.PHONY: crds-install
crds-install: ## Install CRDs and admission policies (cluster-admin action)
	$(KUBECTL) apply --server-side -f deploy/crds/

## ---------- operator ----------

OPERATOR_IMAGE   := kubechaos-operator:dev
OPERATOR_CHART   := deploy/helm/kubechaos-operator
OPERATOR_VALUES  := --set clusterIdentity.clusterID=dev-kind-01 --set clusterIdentity.environment=development
KUBECTL          := kubectl --context kind-$(KIND_CLUSTER)

.PHONY: operator-test
operator-test: ## Run operator unit tests
	go vet ./operator/...
	go test -count=1 ./operator/...

.PHONY: operator-image
operator-image: ## Build the operator image and load it into kind
	docker build -f operator/Dockerfile -t $(OPERATOR_IMAGE) --build-arg VERSION=$$(git rev-parse --short HEAD 2>/dev/null || echo dev) .
	kind load docker-image $(OPERATOR_IMAGE) --name $(KIND_CLUSTER)

.PHONY: operator-deploy
operator-deploy: crds-install ## Deploy the operator into kind (CRDs, namespace with Pod Security labels, chart)
	$(KUBECTL) apply -f deploy/k8s/namespace.yaml
	@# Pin NetworkPolicy egress to the API server: Service IP and real endpoint, discovered live.
	@svc=$$($(KUBECTL) get svc kubernetes -o jsonpath='{.spec.clusterIP}'); \
	ep=$$($(KUBECTL) get endpointslices -l kubernetes.io/service-name=kubernetes -o jsonpath='{.items[0].endpoints[0].addresses[0]}'); \
	[ -n "$$svc" ] && [ -n "$$ep" ] || { echo "could not discover API server addresses"; exit 1; }; \
	echo "NetworkPolicy egress pinned to $$svc/32 and $$ep/32"; \
	helm --kube-context kind-$(KIND_CLUSTER) upgrade --install kubechaos-operator $(OPERATOR_CHART) \
	  -n kubechaos-system $(OPERATOR_VALUES) --set "networkPolicy.apiServerCIDRs={$$svc/32,$$ep/32}" --wait --timeout 120s
	$(KUBECTL) -n kubechaos-system rollout restart deployment/kubechaos-operator
	$(KUBECTL) -n kubechaos-system rollout status deployment/kubechaos-operator --timeout 120s

.PHONY: operator-undeploy
operator-undeploy: ## Remove the operator from kind
	-helm --kube-context kind-$(KIND_CLUSTER) uninstall kubechaos-operator -n kubechaos-system

.PHONY: operator-verify
operator-verify: ## Check the deployed operator's effective RBAC against expectations
	@bash scripts/verify-operator-rbac.sh

.PHONY: crd-verify
crd-verify: ## Check ChaosExperiment validation, immutability and admission policy against kind
	@bash scripts/verify-crd.sh

RBAC_SNAPSHOT := $(OPERATOR_CHART)/rbac.snapshot.yaml
rbac_render = helm template kubechaos-operator $(OPERATOR_CHART) -n kubechaos-system $(OPERATOR_VALUES) \
	| awk 'BEGIN{RS="---\n"} /\nkind: (Cluster)?Role(Binding)?\n|^kind: (Cluster)?Role(Binding)?\n/ {printf "---\n%s", $$0}' \
	| grep -vE '^\s+(app.kubernetes.io/(version|managed-by)|helm.sh/chart):'

.PHONY: rbac-check
rbac-check: ## Fail if the operator's rendered RBAC differs from the reviewed snapshot
	@$(rbac_render) | diff -u $(RBAC_SNAPSHOT) - && echo "RBAC matches $(RBAC_SNAPSHOT)"

.PHONY: rbac-snapshot
rbac-snapshot: ## Re-record the RBAC snapshot (review the diff before committing!)
	@$(rbac_render) > $(RBAC_SNAPSHOT) && echo "wrote $(RBAC_SNAPSHOT)"

## ---------- frontend ----------

.PHONY: fe-install
fe-install: ## Install frontend dependencies exactly from package-lock.json
	cd frontend && npm ci

.PHONY: fe-test
fe-test: ## Run frontend unit tests (Vitest)
	cd frontend && npx ng test app --watch=false

.PHONY: fe-build
fe-build: ## Production build of the SPA
	cd frontend && npx ng build app --configuration production

.PHONY: fe
fe: ## Serve the SPA on 127.0.0.1:4200, proxying /api to the API (run `make api` too)
	cd frontend && npx ng serve app

.PHONY: status
status: ## Show infrastructure status
	$(COMPOSE) ps
	-kubectl --context kind-$(KIND_CLUSTER) get nodes
