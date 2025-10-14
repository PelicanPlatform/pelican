-- +goose Up
-- +goose StatementBegin
ALTER TABLE service_names RENAME TO server_names;
ALTER TABLE downtimes ADD COLUMN server_id TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE downtimes DROP COLUMN server_id;
ALTER TABLE server_names RENAME TO service_names;
-- +goose StatementEnd


