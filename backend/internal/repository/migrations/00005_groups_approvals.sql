-- Raw IdP groups on sessions (approval routing) and the approval workflow states on experiments.

-- +goose Up
ALTER TABLE app.sessions ADD COLUMN groups text[] NOT NULL DEFAULT '{}' CHECK (cardinality(groups) <= 64);

ALTER TABLE app.experiments DROP CONSTRAINT experiments_state_check;
ALTER TABLE app.experiments ADD CONSTRAINT experiments_state_check
    CHECK (state IN ('Submitting', 'Submitted', 'SubmitFailed', 'PendingApproval', 'ApprovalRejected', 'ApprovalExpired'));
ALTER TABLE app.experiments ADD COLUMN approval_request_id uuid;
CREATE INDEX experiments_pending_approval_idx ON app.experiments (state) WHERE state = 'PendingApproval';

-- +goose Down
DROP INDEX app.experiments_pending_approval_idx;
ALTER TABLE app.experiments DROP COLUMN approval_request_id;
ALTER TABLE app.experiments DROP CONSTRAINT experiments_state_check;
ALTER TABLE app.experiments ADD CONSTRAINT experiments_state_check
    CHECK (state IN ('Submitting', 'Submitted', 'SubmitFailed'));
ALTER TABLE app.sessions DROP COLUMN groups;
