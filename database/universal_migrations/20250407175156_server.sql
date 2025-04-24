-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS counters (
    key TEXT PRIMARY KEY,
    value INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS downtimes (
    uuid TEXT PRIMARY KEY,
    created_by TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    server_name TEXT NOT NULL,
    source TEXT NOT NULL, -- Pelican service that set this downtime
    class TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    start_time INTEGER NOT NULL,  -- Stored as Unix epoch (UTC, Milliseconds)
    end_time INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),  -- Stored as Unix epoch (UTC, Milliseconds)
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    deleted_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_downtimes_start_time ON downtimes(start_time);
CREATE INDEX IF NOT EXISTS idx_downtimes_end_time ON downtimes(end_time);
CREATE INDEX IF NOT EXISTS idx_downtimes_server_name ON downtimes(server_name);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS downtimes;
DROP TABLE IF EXISTS counters;
-- +goose StatementEnd
