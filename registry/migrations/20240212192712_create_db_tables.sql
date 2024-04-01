-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS namespace (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  prefix TEXT NOT NULL UNIQUE,
  pubkey TEXT NOT NULL,
  identity TEXT,
  admin_metadata TEXT CHECK (length("admin_metadata") <= 4000),
  custom_fields TEXT CHECK (length("custom_fields") <= 4000) DEFAULT '',
  topology boolean
);

CREATE TABLE IF NOT EXISTS topology (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  prefix TEXT NOT NULL UNIQUE
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- +goose StatementEnd
