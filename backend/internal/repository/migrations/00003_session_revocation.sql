-- Per-session idle timeout (shorter for high-privilege roles) and the IdP session ID (sid),
-- which OIDC Back-Channel Logout uses to revoke exactly the matching application sessions.

-- +goose Up
ALTER TABLE app.sessions
    ADD COLUMN idp_sid text CHECK (length(idp_sid) <= 255),
    ADD COLUMN idle_timeout_seconds integer NOT NULL DEFAULT 1800
        CHECK (idle_timeout_seconds BETWEEN 60 AND 86400);
ALTER TABLE app.sessions ALTER COLUMN idle_timeout_seconds DROP DEFAULT;
CREATE INDEX sessions_idp_sid_idx ON app.sessions (idp_sid) WHERE idp_sid IS NOT NULL;

-- +goose Down
DROP INDEX app.sessions_idp_sid_idx;
ALTER TABLE app.sessions DROP COLUMN idle_timeout_seconds, DROP COLUMN idp_sid;
