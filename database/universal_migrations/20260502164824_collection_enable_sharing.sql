-- +goose Up
-- +goose StatementBegin

-- Add an opt-in `enable_sharing` flag to every collection. When true,
-- callers with read access to the collection can mint a "share" — a
-- child collection (see the upcoming parent_collection_id column) that
-- delegates a subset of the parent's access to whoever the share is
-- handed to. Defaults OFF so the new capability does not retroactively
-- expand any existing collection's exposure.
--
-- Stored as an INTEGER per the SQLite-via-GORM convention (boolean
-- columns are written as 0/1). The Go side uses bool with a
-- gorm:"not null;default:false" tag.

ALTER TABLE collections
  ADD COLUMN enable_sharing INTEGER NOT NULL DEFAULT 0;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- SQLite supports DROP COLUMN since 3.35 (2021); rely on that rather
-- than the older "rebuild the table" dance, since every other recent
-- migration in this tree assumes a current SQLite.
ALTER TABLE collections DROP COLUMN enable_sharing;

-- +goose StatementEnd
