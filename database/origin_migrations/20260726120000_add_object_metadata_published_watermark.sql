-- +goose Up
-- +goose StatementBegin

-- published_at / published_etag record whether (and at what content version)
-- this origin has successfully published an object.committed/object.updated
-- webhook for the live object. They power the crash-atomic reconcile sweep:
-- a committed object whose publish never reached the catalog (crash between
-- the storage rename and the durable queue write) has a live row here with
-- published_at IS NULL — or published_etag != etag after an overwrite — and is
-- re-enqueued once it has been at rest past the settle window. Both are
-- nullable; a freshly committed row starts with NULL until its publish lands.
ALTER TABLE object_metadata ADD COLUMN published_at    DATETIME;
ALTER TABLE object_metadata ADD COLUMN published_etag  TEXT;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- The bundled modernc SQLite driver is >= 3.35, which supports
-- ALTER TABLE ... DROP COLUMN, so the reversal is a plain column drop.
ALTER TABLE object_metadata DROP COLUMN published_at;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE object_metadata DROP COLUMN published_etag;
-- +goose StatementEnd
