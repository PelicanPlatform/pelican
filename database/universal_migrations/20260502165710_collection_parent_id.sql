-- +goose Up
-- +goose StatementBegin

-- Shares are a special kind of collection — created by a non-admin
-- user with read access to a parent collection, delegating a subset
-- of the parent's access. The relationship is recorded by setting
-- the child collection's `parent_collection_id` to the parent's ID.
--
-- Empty string == not a share. We don't use NULL because every other
-- "optional FK" column on this row uses NOT NULL DEFAULT '' (admin_id,
-- owner_id) and the application code consistently treats the empty
-- string as the absence sentinel.
--
-- The index speeds up the per-parent listing (`/collections/:id/shares`)
-- without forcing a full table scan; partial-index on non-empty values
-- keeps the index size bounded by the number of actual shares.

ALTER TABLE collections
  ADD COLUMN parent_collection_id TEXT NOT NULL DEFAULT '';

CREATE INDEX idx_collections_parent
  ON collections(parent_collection_id)
  WHERE parent_collection_id <> '';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_collections_parent;
ALTER TABLE collections DROP COLUMN parent_collection_id;

-- +goose StatementEnd
