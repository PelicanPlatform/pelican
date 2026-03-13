-- +goose Up
-- +goose StatementBegin
ALTER TABLE oidc_clients ADD COLUMN namespace TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_access_tokens ADD COLUMN namespace TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_refresh_tokens ADD COLUMN namespace TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_authorization_codes ADD COLUMN namespace TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_pkce_requests ADD COLUMN namespace TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_openid_sessions ADD COLUMN namespace TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_device_codes ADD COLUMN namespace TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- SQLite does not support DROP COLUMN in older versions; the forward
-- migration is additive and safe to leave in place on rollback.
-- +goose StatementEnd
