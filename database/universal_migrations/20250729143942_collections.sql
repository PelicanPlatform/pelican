-- +goose Up
-- +goose StatementBegin
CREATE TABLE collections (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    owner_sub TEXT NOT NULL,
    owner_issuer TEXT NOT NULL,
    visibility TEXT NOT NULL DEFAULT 'private',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX idx_owner_issuer_name ON collections (owner_sub, owner_issuer, name);

CREATE TABLE collection_members (
    collection_id TEXT NOT NULL,
    object_url TEXT NOT NULL,
    added_by_sub TEXT NOT NULL,
    added_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (collection_id, object_url)
);

CREATE TABLE collection_acls (
    collection_id TEXT NOT NULL,
    principal_sub TEXT NOT NULL,
    principal_issuer TEXT NOT NULL,
    role TEXT NOT NULL,
    granted_by_sub TEXT NOT NULL,
    granted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    PRIMARY KEY (collection_id, principal_sub, principal_issuer, role)
);

CREATE TABLE collection_metadata (
    collection_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (collection_id, key)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE collection_metadata;
DROP TABLE collection_acls;
DROP TABLE collection_members;
DROP TABLE collections;
DROP INDEX idx_owner_issuer_name;
-- +goose StatementEnd
