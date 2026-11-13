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
	kubectl --context kind-$(KIND_CLUSTER) wait --for=condition=Ready nodes --all --timeout=180s
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
