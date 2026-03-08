-- +goose Up
-- +goose StatementBegin
ALTER TABLE oidc_clients ADD COLUMN registration_access_token TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_clients ADD COLUMN client_name TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- SQLite does not support DROP COLUMN in older versions; the forward
-- migration is additive and safe to leave in place on rollback.
-- +goose StatementEnd
