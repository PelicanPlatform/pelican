-- +goose Up
-- +goose StatementBegin

-- Make username GLOBALLY unique among live rows, replacing the per-issuer
-- UNIQUE(username, issuer).
DROP INDEX IF EXISTS idx_user_issuer;
CREATE UNIQUE INDEX idx_user_username_live
    ON users (username)
    WHERE deleted_at IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Restore the per-issuer partial unique index (state after 20260503120000).
DROP INDEX IF EXISTS idx_user_username_live;
CREATE UNIQUE INDEX idx_user_issuer
    ON users (username, issuer)
    WHERE deleted_at IS NULL;

-- +goose StatementEnd
