-- +goose Up
-- +goose StatementBegin
CREATE TABLE metadata_publish_queue (
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
CREATE INDEX idx_mpq_due ON metadata_publish_queue(next_attempt_at);
CREATE INDEX idx_mpq_age ON metadata_publish_queue(created_at);
CREATE INDEX idx_mpq_ns  ON metadata_publish_queue(namespace);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_mpq_ns;
DROP INDEX IF EXISTS idx_mpq_age;
DROP INDEX IF EXISTS idx_mpq_due;
DROP TABLE IF EXISTS metadata_publish_queue;
-- +goose StatementEnd
