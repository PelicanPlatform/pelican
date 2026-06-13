-- +goose Up
-- +goose StatementBegin
CREATE TABLE lots (
    lot_name             TEXT    PRIMARY KEY,
    owner                TEXT    NOT NULL,
    dedicated_bytes      INTEGER NOT NULL DEFAULT 0,   -- -1 = unbounded
    opportunistic_bytes  INTEGER NOT NULL DEFAULT 0,   -- -1 = unbounded
    max_num_objects      INTEGER NOT NULL DEFAULT -1,  -- -1 = unbounded
    creation_time        INTEGER NOT NULL DEFAULT 0,   -- ms; all-zero triple = non-expiring
    expiration_time      INTEGER NOT NULL DEFAULT 0,
    deletion_time        INTEGER NOT NULL DEFAULT 0,
    created_at           INTEGER NOT NULL DEFAULT 0,
    updated_at           INTEGER NOT NULL DEFAULT 0
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE lot_parents (
    lot_name TEXT NOT NULL,
    parent   TEXT NOT NULL,
    PRIMARY KEY (lot_name, parent),
    FOREIGN KEY (lot_name) REFERENCES lots(lot_name) ON DELETE CASCADE
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE lot_paths (
    lot_name  TEXT    NOT NULL,
    path      TEXT    NOT NULL,
    recursive INTEGER NOT NULL DEFAULT 0,
    exclude   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (lot_name, path),
    FOREIGN KEY (lot_name) REFERENCES lots(lot_name) ON DELETE CASCADE
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_lot_paths_path ON lot_paths(path);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE lot_usage (
    lot_name                       TEXT    PRIMARY KEY,
    self_bytes                     INTEGER NOT NULL DEFAULT 0,
    children_bytes                 INTEGER NOT NULL DEFAULT 0,
    self_objects                   INTEGER NOT NULL DEFAULT 0,
    children_objects               INTEGER NOT NULL DEFAULT 0,
    self_bytes_being_written       INTEGER NOT NULL DEFAULT 0,
    children_bytes_being_written   INTEGER NOT NULL DEFAULT 0,
    self_objects_being_written     INTEGER NOT NULL DEFAULT 0,
    children_objects_being_written INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (lot_name) REFERENCES lots(lot_name) ON DELETE CASCADE
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE lot_parent_attributions (
    child_lot_name   TEXT    NOT NULL,
    parent_lot_name  TEXT    NOT NULL,
    mpa_key          TEXT    NOT NULL,   -- 'dedicated_bytes' | 'opportunistic_bytes' | 'max_num_objects'
    attributed_value INTEGER NOT NULL,   -- absolute attributed amount; -1 = unbounded
    PRIMARY KEY (child_lot_name, parent_lot_name, mpa_key),
    FOREIGN KEY (child_lot_name) REFERENCES lots(lot_name) ON DELETE CASCADE
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE lot_reclamations (
    lot_name         TEXT    PRIMARY KEY,
    reclaimed_at     INTEGER NOT NULL,
    reclaimed_reason TEXT,
    FOREIGN KEY (lot_name) REFERENCES lots(lot_name) ON DELETE CASCADE
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS lot_reclamations;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS lot_parent_attributions;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS lot_usage;
-- +goose StatementEnd
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_lot_paths_path;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS lot_paths;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS lot_parents;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS lots;
-- +goose StatementEnd
