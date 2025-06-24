-- +goose Up
-- +goose StatementBegin
ALTER TABLE globus_collections ADD COLUMN transfer_refresh_token TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE globus_collections DROP COLUMN transfer_refresh_token;
-- +goose StatementEnd 