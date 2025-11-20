-- +goose Up
-- +goose StatementBegin
ALTER TABLE service_names RENAME TO server_local_metadata;
ALTER TABLE server_local_metadata DROP COLUMN type;
ALTER TABLE server_local_metadata ADD COLUMN is_origin BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE server_local_metadata ADD COLUMN is_cache BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE downtimes ADD COLUMN server_id TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE downtimes DROP COLUMN server_id;
ALTER TABLE server_local_metadata DROP COLUMN is_cache;
ALTER TABLE server_local_metadata DROP COLUMN is_origin;
ALTER TABLE server_local_metadata ADD COLUMN type TEXT NOT NULL DEFAULT '';
ALTER TABLE server_local_metadata RENAME TO service_names;
-- +goose StatementEnd
