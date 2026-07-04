-- +goose Up
-- +goose StatementBegin

-- source_etag records the ETag of the object as it was fetched from
-- a remote source during a third-party copy (TPC). It is nullable —
-- objects uploaded directly (PUT) have no upstream source, so the
-- column stays NULL for them. Populated by the TPC handler after a
-- successful pull; surfaced on PROPFIND as a Pelican dead property
-- so a subsequent sync client can skip an object it already has.
ALTER TABLE object_metadata         ADD COLUMN source_etag TEXT;
ALTER TABLE object_metadata_history ADD COLUMN source_etag TEXT;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- SQLite doesn't support DROP COLUMN portably before 3.35. Callers
-- rolling back this migration should recreate the tables from the
-- prior migration if they need to reclaim the space.
-- +goose StatementEnd
