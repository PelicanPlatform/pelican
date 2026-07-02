-- +goose Up
-- +goose StatementBegin

-- Make the users uniqueness indexes ignore soft-deleted rows.
--
-- The soft-delete migration (20260425120000) added a `deleted_at`
-- column and DeleteUser flags rows via GORM soft delete rather than
-- physically removing them. But idx_user_issuer(username, issuer) and
-- idx_user_sub_issuer(sub, issuer) — created in 20250929190630 — are
-- plain (non-partial) UNIQUE indexes, so a tombstoned row keeps
-- reserving its (username, issuer) and (sub, issuer) slots forever.
--
-- Consequence being fixed: after an admin deletes "alice",
-- LookupOrBootstrapUser can't find her (GORM's default scope hides the
-- tombstone) and falls through to CreateUser, whose INSERT then hits
-- "UNIQUE constraint failed" against the still-present index entry — so
-- she can never log back in, and her username/identity can never be
-- reused by a new account. Scoping the unique indexes to live rows
-- (deleted_at IS NULL) preserves the single-live-account invariant while
-- allowing re-enrollment. The design's "historical references remain
-- resolvable" goal is unaffected: the tombstone row (and its id) still
-- exists for audit/foreign-key resolution; it just no longer blocks new
-- inserts.
DROP INDEX IF EXISTS idx_user_issuer;
DROP INDEX IF EXISTS idx_user_sub_issuer;

CREATE UNIQUE INDEX idx_user_issuer
    ON users (username, issuer)
    WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_user_sub_issuer
    ON users (sub, issuer)
    WHERE deleted_at IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Restore the original non-partial unique indexes. Note: if any
-- soft-deleted rows share a (username, issuer) / (sub, issuer) with a
-- live row, recreating the non-partial index will fail — that is the
-- exact collision this migration was written to avoid, so a clean
-- down-migration requires no such duplicates to exist.
DROP INDEX IF EXISTS idx_user_issuer;
DROP INDEX IF EXISTS idx_user_sub_issuer;

CREATE UNIQUE INDEX idx_user_issuer ON users (username, issuer);
CREATE UNIQUE INDEX idx_user_sub_issuer ON users (sub, issuer);

-- +goose StatementEnd
