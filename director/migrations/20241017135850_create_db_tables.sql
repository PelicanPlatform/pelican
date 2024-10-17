-- +goose Up
-- +goose StatementBegin
CREATE TABLE server_status (
    uuid TEXT PRIMARY KEY,
    url TEXT NOT NULL DEFAULT '',
    downtime BOOLEAN NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- +goose StatementEnd
