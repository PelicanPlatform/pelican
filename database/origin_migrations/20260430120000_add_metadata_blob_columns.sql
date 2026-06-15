-- +goose Up
-- +goose StatementBegin
ALTER TABLE metadata_publish_queue ADD COLUMN metadata_content_type TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE metadata_publish_queue ADD COLUMN metadata_body BLOB NOT NULL DEFAULT X'';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- SQLite cannot drop columns in versions before 3.35. The down
-- migration recreates the original table shape.
CREATE TABLE metadata_publish_queue_v1 (
    id              INTEGER  PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT     NOT NULL UNIQUE,
    namespace       TEXT     NOT NULL,
    object_path     TEXT     NOT NULL,
    object_size     INTEGER  NOT NULL,
    etag            TEXT     NOT NULL DEFAULT '',
    object_created  DATETIME NOT NULL,
    custom_fields   TEXT     NOT NULL DEFAULT '{}',
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    next_attempt_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    attempts        INTEGER  NOT NULL DEFAULT 0,
    last_error      TEXT     NOT NULL DEFAULT ''
);
-- +goose StatementEnd

-- +goose StatementBegin
INSERT INTO metadata_publish_queue_v1
SELECT id, event_id, namespace, object_path, object_size, etag,
       object_created, custom_fields, created_at, next_attempt_at,
       attempts, last_error
  FROM metadata_publish_queue;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE metadata_publish_queue;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE metadata_publish_queue_v1 RENAME TO metadata_publish_queue;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_mpq_due ON metadata_publish_queue(next_attempt_at);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_mpq_age ON metadata_publish_queue(created_at);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_mpq_ns ON metadata_publish_queue(namespace);
-- +goose StatementEnd
