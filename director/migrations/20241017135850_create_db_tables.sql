-- +goose Up
-- +goose StatementBegin
CREATE TABLE server_status (
    uuid TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    filter_type TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- +goose StatementEnd
