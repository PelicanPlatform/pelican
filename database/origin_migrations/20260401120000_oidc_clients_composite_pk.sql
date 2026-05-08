-- +goose Up
-- +goose StatementBegin

-- SQLite does not support ALTER TABLE ... DROP PRIMARY KEY, so we must
-- recreate the table to change the primary key from (id) to (id, namespace).
-- This ensures that GORM's ON CONFLICT clause (which references both columns)
-- works correctly, and prevents cross-namespace client-ID collisions.

CREATE TABLE IF NOT EXISTS oidc_clients_new (
    id TEXT NOT NULL,
    namespace TEXT NOT NULL DEFAULT '',
    client_secret TEXT NOT NULL,
    redirect_uris TEXT NOT NULL DEFAULT '[]',
    grant_types TEXT NOT NULL DEFAULT '[]',
    response_types TEXT NOT NULL DEFAULT '[]',
    scopes TEXT NOT NULL DEFAULT '[]',
    public INTEGER NOT NULL DEFAULT 0,
    dynamically_registered INTEGER NOT NULL DEFAULT 0,
    bound_user TEXT NOT NULL DEFAULT '',
    last_used_at DATETIME,
    registration_ip TEXT NOT NULL DEFAULT '',
    registration_access_token TEXT NOT NULL DEFAULT '',
    client_name TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, namespace)
);

INSERT INTO oidc_clients_new (
    id, namespace, client_secret, redirect_uris, grant_types, response_types,
    scopes, public, dynamically_registered, bound_user, last_used_at,
    registration_ip, registration_access_token, client_name, created_at
)
SELECT
    id, namespace, client_secret, redirect_uris, grant_types, response_types,
    scopes, public, dynamically_registered, bound_user, last_used_at,
    registration_ip, registration_access_token, client_name, created_at
FROM oidc_clients;

DROP TABLE oidc_clients;
ALTER TABLE oidc_clients_new RENAME TO oidc_clients;

-- +goose StatementEnd
