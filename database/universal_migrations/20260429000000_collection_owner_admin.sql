-- +goose Up
-- +goose StatementBegin

-- Per the user/group-design rewrite of collection ownership:
--
--   * owner_id  — the User.ID (slug) of the collection's single owner.
--                 Replaces the previous semantics where ownership was
--                 expressed via a self-referential `user-<username>`
--                 ACL row plus the legacy `owner` (username) column.
--                 Stored as User.ID rather than username so it stays
--                 stable across renames (mirrors Group.OwnerID).
--   * admin_id  — the Group.ID of an OPTIONAL admin group whose
--                 members get full collection-management authority
--                 (modify metadata, ACLs, members, ownership, delete).
--                 Mirrors the "Administrators: Group ID" half of
--                 Group's ownership model.
--
-- The legacy `owner` column (username) is left in place as an audit
-- field. New rows still populate it for back-compat; authorization no
-- longer keys off it.
--
-- Backfill owner_id where possible: any existing collection whose
-- legacy `owner` username resolves to a live User row gets the
-- corresponding User.ID. Rows that don't resolve (deleted user, test
-- fixtures with no User row) keep an empty owner_id and continue to
-- rely on the legacy `user-<username>` ACL row until the operator
-- cleans them up.

ALTER TABLE collections ADD COLUMN owner_id TEXT NOT NULL DEFAULT '';
ALTER TABLE collections ADD COLUMN admin_id TEXT NOT NULL DEFAULT '';

UPDATE collections
SET owner_id = (
    SELECT users.id FROM users
    WHERE users.username = collections.owner
      AND users.deleted_at IS NULL
)
WHERE owner_id = ''
  AND EXISTS (
    SELECT 1 FROM users
    WHERE users.username = collections.owner
      AND users.deleted_at IS NULL
  );

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- SQLite cannot DROP COLUMN cleanly; the down migration is a no-op.
-- +goose StatementEnd
