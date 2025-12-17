-- +goose Up
-- +goose StatementBegin
ALTER TABLE downtimes ADD COLUMN server_id TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE downtimes DROP COLUMN server_id;
-- +goose StatementEnd
