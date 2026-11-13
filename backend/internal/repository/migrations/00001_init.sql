-- Initial schema. Run ONLY as kubechaos_migrator (owner of database kubechaos).
-- Privileges are granted explicitly per object; the app role never owns anything.

-- +goose Up
CREATE SCHEMA app;
CREATE SCHEMA audit;
REVOKE ALL ON SCHEMA app, audit FROM PUBLIC;
GRANT USAGE ON SCHEMA app TO kubechaos_app;
GRANT USAGE ON SCHEMA audit TO kubechaos_app, kubechaos_auditor_ro;

-- Identities from the OIDC provider. No credentials are ever stored.
CREATE TABLE app.identities (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer        text        NOT NULL CHECK (length(issuer) BETWEEN 1 AND 512),
    subject       text        NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
    display_name  text        CHECK (length(display_name) <= 255),
    email         text        CHECK (length(email) <= 320),
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz,
    UNIQUE (issuer, subject)
);
GRANT SELECT, INSERT, UPDATE ON app.identities TO kubechaos_app;

-- Registered clusters. Connection credentials are NOT stored here (architecture §8).
CREATE TABLE app.clusters (
    id           text        PRIMARY KEY CHECK (id ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    display_name text        NOT NULL CHECK (length(display_name) BETWEEN 1 AND 128),
    environment  text        NOT NULL CHECK (environment IN ('development', 'staging', 'production')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE ON app.clusters TO kubechaos_app;

-- Append-only, hash-chained audit log (architecture §9, threat model T12).
--   hash = SHA-256(prev_hash || canonical_json(event)), computed by internal/audit.
--   The first event's prev_hash is 32 zero bytes.
--   UNIQUE(prev_hash) forbids forks: two events can never claim the same predecessor.
CREATE TABLE audit.events (
    seq                    bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    id                     uuid        NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    occurred_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    actor_issuer           text,
    actor_subject          text,
    actor_display_name     text,
    auth_level             text,
    session_id_hash        text,
    source_ip              inet,
    action                 text        NOT NULL CHECK (action ~ '^[a-z][a-z0-9_.]{0,63}$'),
    cluster_id             text,
    namespace              text,
    resource               text,
    fault_type             text,
    experiment_id          uuid,
    parameters             jsonb,
    requested_blast_radius jsonb,
    decision               text        CHECK (decision IN ('allow', 'deny')),
    decision_reasons       jsonb,
    policy_version         text,
    result                 text,
    affected_resources     jsonb,
    prev_hash              bytea       NOT NULL UNIQUE CHECK (octet_length(prev_hash) = 32),
    hash                   bytea       NOT NULL UNIQUE CHECK (octet_length(hash) = 32)
);
CREATE INDEX events_occurred_at_idx   ON audit.events (occurred_at);
CREATE INDEX events_experiment_id_idx ON audit.events (experiment_id) WHERE experiment_id IS NOT NULL;
CREATE INDEX events_actor_idx         ON audit.events (actor_issuer, actor_subject);

-- Guard against modification even by roles that hold privileges (e.g. the owner by mistake).
-- +goose StatementBegin
CREATE FUNCTION audit.reject_modification() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit.events is append-only: % rejected', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION audit.reject_modification() FROM PUBLIC;

CREATE TRIGGER events_reject_update_delete
    BEFORE UPDATE OR DELETE ON audit.events
    FOR EACH ROW EXECUTE FUNCTION audit.reject_modification();
CREATE TRIGGER events_reject_truncate
    BEFORE TRUNCATE ON audit.events
    FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_modification();

-- App: append and read (needs the last hash to extend the chain). Auditor: read only.
GRANT INSERT, SELECT ON audit.events TO kubechaos_app;
GRANT SELECT ON audit.events TO kubechaos_auditor_ro;

-- +goose Down
-- Deliberately irreversible: rolling back would destroy the audit trail.
-- +goose StatementBegin
DO $$
BEGIN
    RAISE EXCEPTION '00001_init is irreversible (it owns the audit log); restore from backup instead';
END
$$;
-- +goose StatementEnd
