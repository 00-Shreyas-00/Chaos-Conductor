#!/usr/bin/env bash
# Runs once, on first initialisation of the dev Postgres volume.
# Creates separate databases and least-privilege roles for the control plane and the
# Approval Service (separate trust domains, see docs/architecture/architecture.md §8, §15).
# Table-level grants (e.g. INSERT/SELECT-only on audit) are applied by migrations, not here.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v kc_migrator_pw="$KUBECHAOS_MIGRATOR_PASSWORD" \
  -v kc_app_pw="$KUBECHAOS_APP_PASSWORD" \
  -v kc_auditor_pw="$KUBECHAOS_AUDITOR_PASSWORD" \
  -v ap_migrator_pw="$APPROVER_MIGRATOR_PASSWORD" \
  -v ap_app_pw="$APPROVER_APP_PASSWORD" <<'SQL'
-- Control plane
CREATE ROLE kubechaos_migrator   LOGIN PASSWORD :'kc_migrator_pw';
CREATE ROLE kubechaos_app        LOGIN PASSWORD :'kc_app_pw';
CREATE ROLE kubechaos_auditor_ro LOGIN PASSWORD :'kc_auditor_pw';
CREATE DATABASE kubechaos OWNER kubechaos_migrator;
REVOKE ALL ON DATABASE kubechaos FROM PUBLIC;
GRANT CONNECT ON DATABASE kubechaos TO kubechaos_app, kubechaos_auditor_ro;

-- Approval Service (no control-plane role may connect)
CREATE ROLE approver_migrator LOGIN PASSWORD :'ap_migrator_pw';
CREATE ROLE approver_app      LOGIN PASSWORD :'ap_app_pw';
CREATE DATABASE kubechaos_approval OWNER approver_migrator;
REVOKE ALL ON DATABASE kubechaos_approval FROM PUBLIC;
GRANT CONNECT ON DATABASE kubechaos_approval TO approver_app;
SQL

# Remove the default CREATE-on-public-schema privilege in both databases.
for db in kubechaos kubechaos_approval; do
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$db" \
    -c "REVOKE ALL ON SCHEMA public FROM PUBLIC;"
done
