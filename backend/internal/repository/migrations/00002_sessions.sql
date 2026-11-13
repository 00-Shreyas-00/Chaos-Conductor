-- Server-side sessions and in-flight OIDC login requests (BFF, D1).
-- Only SHA-256 hashes of session tokens and OAuth state values are stored.

-- +goose Up
CREATE TABLE app.login_requests (
    state_hash    bytea       PRIMARY KEY CHECK (octet_length(state_hash) = 32),
    nonce         text        NOT NULL CHECK (length(nonce) BETWEEN 16 AND 128),
    pkce_verifier text        NOT NULL CHECK (length(pkce_verifier) BETWEEN 43 AND 128),
    return_to     text        NOT NULL CHECK (return_to ~ '^/' AND length(return_to) <= 512),
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL
);
CREATE INDEX login_requests_expires_at_idx ON app.login_requests (expires_at);
GRANT SELECT, INSERT, DELETE ON app.login_requests TO kubechaos_app;

CREATE TABLE app.sessions (
    token_hash   bytea       PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    identity_id  uuid        NOT NULL REFERENCES app.identities (id),
    roles        text[]      NOT NULL CHECK (roles <@ ARRAY['viewer','experimenter','approver','admin','auditor']),
    acr          text        CHECK (length(acr) <= 64),
    auth_time    timestamptz,
    csrf_token   text        NOT NULL CHECK (length(csrf_token) = 43),
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL
);
CREATE INDEX sessions_expires_at_idx  ON app.sessions (expires_at);
CREATE INDEX sessions_identity_id_idx ON app.sessions (identity_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON app.sessions TO kubechaos_app;

-- +goose Down
DROP TABLE app.sessions;
DROP TABLE app.login_requests;
