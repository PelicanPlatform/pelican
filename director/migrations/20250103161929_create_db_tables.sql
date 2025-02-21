-- +goose Up
-- +goose StatementBegin

CREATE TABLE api_keys (
    id TEXT PRIMARY KEY UNIQUE,
    name TEXT,
    hashed_value TEXT NOT NULL,
    scopes TEXT,
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS server_downtimes;
DROP TABLE IF EXISTS api_keys;
-- +goose StatementEnd
