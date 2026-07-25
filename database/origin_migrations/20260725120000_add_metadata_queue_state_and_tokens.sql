-- +goose Up
-- Adds a terminal "state" (so a catalog's permanent-reject / 422 response can
-- stop a row from retrying forever) and two random capability tokens that let
-- the uploading client query and cancel its own eventual-mode publish without a
-- separate bearer token (possession of the unguessable URL is the authority).
-- +goose StatementBegin
ALTER TABLE metadata_publish_queue ADD COLUMN state TEXT NOT NULL DEFAULT 'pending';
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE metadata_publish_queue ADD COLUMN query_token TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE metadata_publish_queue ADD COLUMN manage_token TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- event_type lets the worker rebuild the event with its original type on retry
-- (object.committed / object.updated / object.deleted) and, for object.deleted,
-- skip the "object still exists?" check (the object being gone is the point).
-- +goose StatementBegin
ALTER TABLE metadata_publish_queue ADD COLUMN event_type TEXT NOT NULL DEFAULT 'object.committed';
-- +goose StatementEnd

-- Lookups by capability token are point queries on a long random string; a
-- plain (non-unique) index is enough and avoids collisions on the empty
-- default that transactional-mode rows carry.
-- +goose StatementBegin
CREATE INDEX idx_mpq_query_token ON metadata_publish_queue(query_token);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_mpq_manage_token ON metadata_publish_queue(manage_token);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_mpq_manage_token;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS idx_mpq_query_token;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE metadata_publish_queue DROP COLUMN event_type;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE metadata_publish_queue DROP COLUMN manage_token;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE metadata_publish_queue DROP COLUMN query_token;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE metadata_publish_queue DROP COLUMN state;
-- +goose StatementEnd
