-- +goose Up
-- +goose StatementBegin

-- Add a bcrypt password hash column for local-account authentication.
-- Empty string means "no local password" (e.g. OIDC-only users); login must then
-- fall back to other auth paths (htpasswd bootstrap, OAuth, bearer token, ...).
ALTER TABLE users ADD COLUMN password_hash TEXT NOT NULL DEFAULT '';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- SQLite does not support DROP COLUMN cleanly; the down migration is a no-op.
-- +goose StatementEnd
