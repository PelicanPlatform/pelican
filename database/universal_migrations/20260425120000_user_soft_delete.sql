-- +goose Up
-- +goose StatementBegin

-- Soft-delete column for the users table. Per the User contract (see
-- comment on the database.User struct in collection.go) IDs are never
-- reused; deletion just flags the row so historical references — group
-- memberships, audit trails, ACL grants attributed to that user — remain
-- resolvable.
--
-- A NULL value means the row is live; any non-NULL timestamp means the
-- account was deleted at that moment. GORM's gorm.DeletedAt type
-- automatically excludes soft-deleted rows from ordinary queries; callers
-- that need to see the entire history (admin tooling, audits) opt in via
-- db.Unscoped().
ALTER TABLE users ADD COLUMN deleted_at DATETIME;
CREATE INDEX idx_users_deleted_at ON users (deleted_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_users_deleted_at;
-- SQLite does not support DROP COLUMN cleanly; the down migration leaves
-- the deleted_at column in place.
-- +goose StatementEnd
