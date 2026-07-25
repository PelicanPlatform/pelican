-- +goose Up
-- +goose StatementBegin
ALTER TABLE metadata_publish_queue ADD COLUMN metadata_content_type TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE metadata_publish_queue ADD COLUMN metadata_body BLOB NOT NULL DEFAULT X'';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- The bundled modernc SQLite driver is >= 3.35, which supports
-- ALTER TABLE ... DROP COLUMN, so the reversal is a plain column drop
-- (consistent with the other origin migrations' Down steps).
ALTER TABLE metadata_publish_queue DROP COLUMN metadata_body;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE metadata_publish_queue DROP COLUMN metadata_content_type;
-- +goose StatementEnd
