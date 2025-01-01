-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS server_downtimes (
    uuid TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    filter_type TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS grafana_api_keys (
    key TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    created_at DATETIME NOT NULL
)
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- +goose StatementEnd
