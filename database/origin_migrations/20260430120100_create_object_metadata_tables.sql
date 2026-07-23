-- +goose Up
-- +goose StatementBegin

-- Live state for every object the origin currently tracks. Soft-deleted
-- rows stay around until removed by the object_metadata_history pruner
-- (a deleted row has its history-snapshot peer and is no longer reachable
-- by the partial UNIQUE index).
CREATE TABLE object_metadata (
    id              INTEGER  PRIMARY KEY AUTOINCREMENT,
    namespace       TEXT     NOT NULL,
    object_path     TEXT     NOT NULL,
    size            INTEGER  NOT NULL,
    etag            TEXT     NOT NULL,
    -- 'backend' = ETag supplied by the storage backend (POSIXv2's
    -- synthesised mtime+size, S3's upstream header, etc).
    -- 'origin'  = the backend declined to supply one and the origin
    --             filled in via Origin.Metadata.EtagPolicy.
    etag_source     TEXT     NOT NULL DEFAULT 'backend',
    backend_mtime   DATETIME NOT NULL,
    created_at      DATETIME NOT NULL,
    last_modified   DATETIME NOT NULL,
    -- Nullable: populated only when the namespace has TrackAccess
    -- enabled. Updates are debounced through the in-memory atime
    -- buffer, then flushed via best-effort writes.
    last_accessed   DATETIME,
    -- TODO(actor): bare token "sub" for now. The forthcoming
    -- immutable-user-id project will replace this with a stable
    -- per-user identifier (probably "<issuer>#<sub>" or a separate
    -- users table id).
    actor           TEXT     NOT NULL DEFAULT '',
    deleted_at      DATETIME
);

-- Partial unique index — only enforced on live (non-deleted) rows.
-- Lets a path be soft-deleted and then re-uploaded with a fresh row.
CREATE UNIQUE INDEX idx_object_metadata_live ON object_metadata(namespace, object_path)
    WHERE deleted_at IS NULL;
CREATE INDEX idx_object_metadata_ns_modified ON object_metadata(namespace, last_modified);
CREATE INDEX idx_object_metadata_deleted     ON object_metadata(deleted_at)
    WHERE deleted_at IS NOT NULL;

-- One row per (object, algorithm). The computed_at + etag_at_compute
-- pair lets a caller tell at a glance whether the stored checksum is
-- still valid for the object's current etag.
CREATE TABLE object_checksums (
    id                INTEGER  PRIMARY KEY AUTOINCREMENT,
    object_id         INTEGER  NOT NULL REFERENCES object_metadata(id) ON DELETE CASCADE,
    algorithm         TEXT     NOT NULL,
    value             TEXT     NOT NULL,
    computed_at       DATETIME NOT NULL,
    etag_at_compute   TEXT     NOT NULL
);
CREATE UNIQUE INDEX idx_object_checksums_object_alg ON object_checksums(object_id, algorithm);

-- Append-only history of object lifecycle events. Snapshots the live
-- row's state at the moment of the event. Pruned by the background
-- objectMetadataPruner per Origin.Metadata.History.RetentionDays
-- (origin-wide, with optional per-export override).
CREATE TABLE object_metadata_history (
    id              INTEGER  PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT     NOT NULL UNIQUE,
    namespace       TEXT     NOT NULL,
    object_path     TEXT     NOT NULL,
    -- 'commit'           = caller-driven write (POSC close)
    -- 'delete'           = caller-driven delete (DELETE / MOVE-out)
    -- 'rename'           = caller-driven rename (MOVE-in)
    -- 'external_observe' = first time we ever saw an object that we
    --                      didn't write (Stat from a PROPFIND)
    -- 'external_modify'  = Stat showed an etag different from what
    --                      we last recorded
    -- 'external_delete'  = Stat returned ENOENT for an object we had
    --                      a live row for
    event_type      TEXT     NOT NULL,
    event_ts        DATETIME NOT NULL,
    size            INTEGER,
    etag            TEXT,
    etag_source     TEXT,
    backend_mtime   DATETIME,
    -- JSON snapshot of all known checksums at event time.
    checksums_json  TEXT     NOT NULL DEFAULT '{}',
    -- Same TODO(actor) note as object_metadata.actor.
    actor           TEXT     NOT NULL DEFAULT '',
    -- Snapshot of the inbound X-Pelican-Object-Metadata header. Only
    -- populated when the namespace has TrackExtra enabled.
    extra           TEXT     NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_object_history_path  ON object_metadata_history(namespace, object_path, event_ts);
CREATE INDEX idx_object_history_event ON object_metadata_history(event_type, event_ts);
CREATE INDEX idx_object_history_ts    ON object_metadata_history(event_ts);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_object_history_ts;
DROP INDEX IF EXISTS idx_object_history_event;
DROP INDEX IF EXISTS idx_object_history_path;
DROP TABLE IF EXISTS object_metadata_history;
DROP INDEX IF EXISTS idx_object_checksums_object_alg;
DROP TABLE IF EXISTS object_checksums;
DROP INDEX IF EXISTS idx_object_metadata_deleted;
DROP INDEX IF EXISTS idx_object_metadata_ns_modified;
DROP INDEX IF EXISTS idx_object_metadata_live;
DROP TABLE IF EXISTS object_metadata;
-- +goose StatementEnd
