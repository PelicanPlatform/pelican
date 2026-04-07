-- +goose Up
-- +goose StatementBegin

ALTER TABLE servers ADD COLUMN last_seen DATETIME DEFAULT NULL;

-- Backfill existing servers from their own timestamps
-- so they have a meaningful last_seen rather than NULL.
UPDATE servers
SET last_seen = COALESCE(updated_at, created_at)
WHERE last_seen IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE servers DROP COLUMN last_seen;
-- +goose StatementEnd
