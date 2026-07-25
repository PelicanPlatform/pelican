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
-- The bundled modernc SQLite driver is >= 3.35, which supports
-- ALTER TABLE ... DROP COLUMN, so the reversal is a plain column drop.
ALTER TABLE object_metadata         DROP COLUMN source_etag;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE object_metadata_history DROP COLUMN source_etag;
-- +goose StatementEnd
