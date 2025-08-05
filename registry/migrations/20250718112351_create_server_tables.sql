-- +goose Up
-- +goose StatementBegin

-- Create servers table
CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    is_origin BOOLEAN NOT NULL DEFAULT FALSE,
    is_cache BOOLEAN NOT NULL DEFAULT FALSE,
    note TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create services table (map the server to its namespace representation) 
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id TEXT NOT NULL,
    namespace_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE,
    FOREIGN KEY (namespace_id) REFERENCES namespace(id) ON DELETE CASCADE
);

-- Create endpoints (network address) table
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
);

-- Create contacts table
CREATE TABLE IF NOT EXISTS contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id TEXT NOT NULL,
    full_name TEXT NOT NULL,
    contact_info TEXT NOT NULL, -- email, phone, etc.
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
);

-- Create indexes for better query performance on server_id lookups
CREATE INDEX IF NOT EXISTS idx_services_server_id ON services(server_id);
CREATE INDEX IF NOT EXISTS idx_services_namespace_id ON services(namespace_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_server_id ON endpoints(server_id);
CREATE INDEX IF NOT EXISTS idx_contacts_server_id ON contacts(server_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Drop indexes
DROP INDEX IF EXISTS idx_contacts_server_id;
DROP INDEX IF EXISTS idx_endpoints_server_id;
DROP INDEX IF EXISTS idx_services_namespace_id;
DROP INDEX IF EXISTS idx_services_server_id;

-- Drop tables in reverse dependency order
DROP TABLE IF EXISTS contacts;
DROP TABLE IF EXISTS endpoints;
DROP TABLE IF EXISTS services;
DROP TABLE IF EXISTS servers;

-- +goose StatementEnd