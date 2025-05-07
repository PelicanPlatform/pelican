-- +goose Up
-- +goose StatementBegin
-- Persist service name and its history locally
CREATE TABLE IF NOT EXISTS service_names (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    deleted_at DATETIME
);
-- Add index to speed up retrieval of the most recently updated (currently in use) service name
CREATE INDEX IF NOT EXISTS idx_service_names_updated_at ON service_names(updated_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_service_names_updated_at;
DROP TABLE IF EXISTS service_names;
-- +goose StatementEnd
