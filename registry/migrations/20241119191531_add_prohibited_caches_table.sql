-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';
-- +goose StatementEnd
CREATE TABLE IF NOT EXISTS prohibited_caches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    prefix_id INTEGER NOT NULL,
    cache_hostname TEXT NOT NULL,
    UNIQUE (prefix_id, cache_hostname),
    FOREIGN KEY (prefix_id) REFERENCES namespace(id)
);
-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
-- +goose StatementEnd
