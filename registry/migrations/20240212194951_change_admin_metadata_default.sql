-- +goose Up
-- +goose StatementBegin
ALTER TABLE namespace RENAME COLUMN admin_metadata TO admin_metadata_old;
ALTER TABLE namespace ADD admin_metadata TEXT CHECK (length("admin_metadata") <= 4000) DEFAULT '';
UPDATE namespace SET admin_metadata = admin_metadata_old;
ALTER TABLE namespace DROP admin_metadata_old;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- +goose StatementEnd
