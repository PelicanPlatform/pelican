-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS server_master_keys (
    key_fingerprint TEXT PRIMARY KEY,
    encrypted_master_key BLOB NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS server_master_keys;
-- +goose StatementEnd
