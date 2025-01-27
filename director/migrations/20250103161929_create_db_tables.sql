-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';
-- +goose StatementEnd

CREATE TABLE IF NOT EXISTS server_downtimes (
    uuid TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    filter_type TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE api_keys (
    id TEXT PRIMARY KEY UNIQUE,
    name TEXT,
    hashed_value TEXT NOT NULL,
    scopes TEXT,
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT
);

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
-- +goose StatementEnd
