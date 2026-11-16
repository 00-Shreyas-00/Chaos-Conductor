-- Approval service database (kubechaos_approval). Run ONLY as approver_migrator.
-- A separate trust domain: the control plane's roles cannot connect here (deploy/postgres/init).

-- +goose Up
CREATE SCHEMA app;
CREATE SCHEMA approval;
REVOKE ALL ON SCHEMA app, approval FROM PUBLIC;
GRANT USAGE ON SCHEMA app, approval TO approver_app;

-- Approver logins (own OIDC client, own sessions). Same shape as the control plane's tables.
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
CREATE TABLE app.login_requests (
    state_hash    bytea       PRIMARY KEY CHECK (octet_length(state_hash) = 32),
    nonce         text        NOT NULL CHECK (length(nonce) BETWEEN 16 AND 128),
    pkce_verifier text        NOT NULL CHECK (length(pkce_verifier) BETWEEN 43 AND 128),
    return_to     text        NOT NULL CHECK (return_to ~ '^/' AND length(return_to) <= 512),
    step_up       boolean     NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL
);
CREATE TABLE app.sessions (
    token_hash           bytea       PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    identity_id          uuid        NOT NULL REFERENCES app.identities (id),
    roles                text[]      NOT NULL CHECK (roles <@ ARRAY['viewer','experimenter','approver','admin','auditor']),
    acr                  text        CHECK (length(acr) <= 64),
    auth_time            timestamptz,
    csrf_token           text        NOT NULL CHECK (length(csrf_token) = 43),
    idp_sid              text        CHECK (length(idp_sid) <= 255),
    idle_timeout_seconds integer     NOT NULL CHECK (idle_timeout_seconds BETWEEN 60 AND 86400),
    groups               text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(groups) <= 64),
    created_at           timestamptz NOT NULL DEFAULT now(),
    last_seen_at         timestamptz NOT NULL DEFAULT now(),
    expires_at           timestamptz NOT NULL
);
CREATE INDEX sessions_idp_sid_idx ON app.sessions (idp_sid) WHERE idp_sid IS NOT NULL;
GRANT SELECT, INSERT, UPDATE ON app.identities TO approver_app;
GRANT SELECT, INSERT, DELETE ON app.login_requests TO approver_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.sessions TO approver_app;

-- Approval requests: one per experiment, state machine Pending -> Approved | Rejected | Expired.
CREATE TABLE approval.requests (
    id                uuid        PRIMARY KEY,
    experiment_id     uuid        NOT NULL UNIQUE,
    cluster_id        text        NOT NULL,
    environment       text        NOT NULL CHECK (environment IN ('development', 'staging', 'production')),
    namespaces        text[]      NOT NULL,
    approver_group    text        NOT NULL CHECK (length(approver_group) BETWEEN 1 AND 255),
    spec              jsonb       NOT NULL,
    spec_sha256       text        NOT NULL CHECK (spec_sha256 ~ '^[a-f0-9]{64}$'),
    risk              text        NOT NULL,
    requester_issuer  text        NOT NULL,
    requester_subject text        NOT NULL,
    requester_name    text        NOT NULL DEFAULT '',
    min_approvals     integer     NOT NULL CHECK (min_approvals BETWEEN 1 AND 5),
    state             text        NOT NULL CHECK (state IN ('Pending', 'Approved', 'Rejected', 'Expired')),
    attestation       text        CHECK (length(attestation) <= 16384),
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL,
    decided_at        timestamptz
);
CREATE INDEX requests_pending_idx ON approval.requests (state, created_at) WHERE state = 'Pending';
GRANT SELECT, INSERT, UPDATE ON approval.requests TO approver_app;

-- Decisions are append-only: one per approver per request.
CREATE TABLE approval.decisions (
    id               bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    request_id       uuid        NOT NULL REFERENCES approval.requests (id),
    approver_issuer  text        NOT NULL,
    approver_subject text        NOT NULL,
    approver_name    text        NOT NULL DEFAULT '',
    decision         text        NOT NULL CHECK (decision IN ('approve', 'reject')),
    comment          text        NOT NULL DEFAULT '' CHECK (length(comment) <= 1000),
    auth_time        timestamptz NOT NULL,
    decided_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (request_id, approver_issuer, approver_subject)
);
GRANT SELECT, INSERT ON approval.decisions TO approver_app;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'approval 00001 is irreversible (it holds approval history)'; END $$;
-- +goose StatementEnd
