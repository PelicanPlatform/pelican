-- +goose Up
-- +goose StatementBegin

-- Capture an audit trail for who/how a User or Group record came into
-- being. Mirrors the fields we already record on invite links. Per the
-- design contract:
--   * users.created_by may be a real user ID, or one of the sentinels
--     'self-enrolled' (account auto-created on first OIDC login) or
--     'unknown' (record predates this column).
--   * groups already had created_by as a user ID; only the auth_method
--     fields are added here.
--   * creator_auth_method records 'web-cookie' / 'api-token' / 'bearer-jwt'
--     (matching database.AuthMethod constants); creator_auth_method_id
--     is the API-token short ID when known, empty otherwise.

ALTER TABLE users ADD COLUMN created_by TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE users ADD COLUMN creator_auth_method TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN creator_auth_method_id TEXT NOT NULL DEFAULT '';

ALTER TABLE groups ADD COLUMN creator_auth_method TEXT NOT NULL DEFAULT '';
ALTER TABLE groups ADD COLUMN creator_auth_method_id TEXT NOT NULL DEFAULT '';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- SQLite cannot DROP COLUMN cleanly; the down migration is a no-op.
-- +goose StatementEnd
