-- Experiments (control-plane record of intent + history mirrored from the cluster), their
-- timeline, step-up login requests, and the canonical audit record used for hash verification.

-- +goose Up
-- jsonb normalises key order/whitespace, so the hash chain is computed over this exact text.
ALTER TABLE audit.events ADD COLUMN canonical text CHECK (length(canonical) <= 65536);

ALTER TABLE app.login_requests ADD COLUMN step_up boolean NOT NULL DEFAULT false;

CREATE TABLE app.experiments (
    id               uuid        PRIMARY KEY,
    name             text        NOT NULL UNIQUE CHECK (name ~ '^exp-[a-f0-9]{12}$'),
    cluster_id       text        NOT NULL REFERENCES app.clusters (id),
    requested_by     uuid        NOT NULL REFERENCES app.identities (id),
    description      text        NOT NULL DEFAULT '' CHECK (length(description) <= 500),
    spec             jsonb       NOT NULL,
    spec_sha256      text        NOT NULL CHECK (spec_sha256 ~ '^[a-f0-9]{64}$'),
    risk             text        NOT NULL CHECK (risk IN ('Low', 'Medium', 'High', 'Critical')),
    state            text        NOT NULL CHECK (state IN ('Submitting', 'Submitted', 'SubmitFailed')),
    phase            text        NOT NULL DEFAULT '' CHECK (length(phase) <= 32),
    result           text        NOT NULL DEFAULT '' CHECK (result IN ('', 'Passed', 'Failed')),
    score            integer     CHECK (score BETWEEN 0 AND 100),
    status           jsonb,
    cancel_requested boolean     NOT NULL DEFAULT false,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX experiments_created_at_idx ON app.experiments (created_at DESC);
GRANT SELECT, INSERT, UPDATE ON app.experiments TO kubechaos_app;

CREATE TABLE app.experiment_events (
    id            bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    experiment_id uuid        NOT NULL REFERENCES app.experiments (id),
    occurred_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
    type          text        NOT NULL CHECK (type ~ '^[A-Za-z]{1,64}$'),
    message       text        NOT NULL CHECK (length(message) <= 1024)
);
CREATE INDEX experiment_events_experiment_idx ON app.experiment_events (experiment_id, id);
GRANT SELECT, INSERT ON app.experiment_events TO kubechaos_app;

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    RAISE EXCEPTION '00004 is irreversible (it carries the audit canonical records)';
END
$$;
-- +goose StatementEnd
