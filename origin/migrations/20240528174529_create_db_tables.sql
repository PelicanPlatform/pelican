-- +goose Up
-- +goose StatementBegin
CREATE TABLE globus_collections (
    uuid TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    server_url TEXT NOT NULL DEFAULT '',
    refresh_token TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- +goose StatementEnd
