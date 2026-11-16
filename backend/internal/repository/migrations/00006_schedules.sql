-- Scheduled chaos (Chaos Monkey style): opt-in schedules that start ordinary experiments at
-- random times inside a weekly window. Every run goes through the normal experiment pipeline.

-- +goose Up
CREATE TABLE app.schedules (
    id                   uuid        PRIMARY KEY,
    name                 text        NOT NULL CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    cluster_id           text        NOT NULL REFERENCES app.clusters (id),
    owner_id             uuid        NOT NULL REFERENCES app.identities (id),
    -- Roles of the owner when the schedule was created. Runs are authorized with this
    -- snapshot; schedules expire (at most 90 days) and can be paused by approvers/admins.
    owner_roles          text[]      NOT NULL CHECK (owner_roles <@ ARRAY['viewer','experimenter','approver','admin','auditor']),
    description          text        NOT NULL DEFAULT '' CHECK (length(description) <= 500),
    template             jsonb       NOT NULL,
    risk                 text        NOT NULL CHECK (risk IN ('Low', 'Medium', 'High', 'Critical')),
    min_interval_seconds integer     NOT NULL CHECK (min_interval_seconds BETWEEN 60 AND 2592000),
    mean_interval_seconds integer    NOT NULL CHECK (mean_interval_seconds BETWEEN 60 AND 2592000),
    window_spec          jsonb       NOT NULL,
    expires_at           timestamptz NOT NULL,
    max_runs             integer     NOT NULL DEFAULT 0 CHECK (max_runs BETWEEN 0 AND 1000),
    runs                 integer     NOT NULL DEFAULT 0 CHECK (runs >= 0),
    consecutive_denials  integer     NOT NULL DEFAULT 0 CHECK (consecutive_denials >= 0),
    state                text        NOT NULL CHECK (state IN ('Active', 'Paused', 'Finished', 'Deleted')),
    state_reason         text        NOT NULL DEFAULT '' CHECK (length(state_reason) <= 500),
    next_run_at          timestamptz,
    last_run_at          timestamptz,
    last_experiment_id   uuid        REFERENCES app.experiments (id),
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    CHECK (mean_interval_seconds >= min_interval_seconds)
);
CREATE INDEX schedules_due_idx ON app.schedules (next_run_at) WHERE state = 'Active';
GRANT SELECT, INSERT, UPDATE ON app.schedules TO kubechaos_app;

-- Append-only run history: every firing, skip and denial.
CREATE TABLE app.schedule_runs (
    id            bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    schedule_id   uuid        NOT NULL REFERENCES app.schedules (id),
    occurred_at   timestamptz NOT NULL DEFAULT now(),
    outcome       text        NOT NULL CHECK (outcome IN ('Started', 'Skipped', 'Denied', 'Failed')),
    experiment_id uuid        REFERENCES app.experiments (id),
    reason        text        NOT NULL DEFAULT '' CHECK (length(reason) <= 1024)
);
CREATE INDEX schedule_runs_schedule_idx ON app.schedule_runs (schedule_id, id DESC);
GRANT SELECT, INSERT ON app.schedule_runs TO kubechaos_app;

ALTER TABLE app.experiments ADD COLUMN schedule_id uuid REFERENCES app.schedules (id);

-- +goose Down
ALTER TABLE app.experiments DROP COLUMN schedule_id;
DROP TABLE app.schedule_runs;
DROP TABLE app.schedules;
