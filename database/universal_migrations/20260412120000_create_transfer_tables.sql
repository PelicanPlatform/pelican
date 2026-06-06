-- +goose Up
-- +goose StatementBegin

-- Client-agent job execution tables (previously managed separately by
-- client_agent/store; now unified in the server database so the transfer
-- module can use them directly).

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    created_at INTEGER NOT NULL,  -- Unix timestamp in seconds
    started_at INTEGER,
    completed_at INTEGER,
    options TEXT,  -- JSON-encoded transfer options
    error_message TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at DESC);

CREATE TABLE IF NOT EXISTS transfers (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('get', 'put', 'copy', 'delete')),
    source TEXT NOT NULL,
    destination TEXT NOT NULL,
    recursive INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    completed_at INTEGER,
    bytes_transferred INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    error_message TEXT,
    FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_transfers_job_id ON transfers(job_id);
CREATE INDEX IF NOT EXISTS idx_transfers_status ON transfers(status);
CREATE INDEX IF NOT EXISTS idx_transfers_created_at ON transfers(created_at DESC);

CREATE TABLE IF NOT EXISTS job_history (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('completed', 'failed', 'cancelled')),
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    completed_at INTEGER,
    options TEXT,
    error_message TEXT,
    transfers_completed INTEGER DEFAULT 0,
    transfers_failed INTEGER DEFAULT 0,
    transfers_total INTEGER DEFAULT 0,
    bytes_transferred INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    retry_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_job_history_completed_at ON job_history(completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_job_history_status ON job_history(status);
CREATE INDEX IF NOT EXISTS idx_job_history_created_at ON job_history(created_at DESC);

CREATE TABLE IF NOT EXISTS transfer_history (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('get', 'put', 'copy', 'delete')),
    source TEXT NOT NULL,
    destination TEXT NOT NULL,
    recursive INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL CHECK (status IN ('completed', 'failed', 'cancelled')),
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    completed_at INTEGER,
    bytes_transferred INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    error_message TEXT,
    FOREIGN KEY (job_id) REFERENCES job_history(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_transfer_history_job_id ON transfer_history(job_id);
CREATE INDEX IF NOT EXISTS idx_transfer_history_completed_at ON transfer_history(completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_transfer_history_status ON transfer_history(status);

-- Transfer module tables

CREATE TABLE IF NOT EXISTS transfer_credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    credential_type TEXT NOT NULL DEFAULT 'bearer',
    encrypted_access_token TEXT NOT NULL DEFAULT '',
    encrypted_refresh_token TEXT,
    scopes TEXT NOT NULL DEFAULT '',
    token_issuer TEXT NOT NULL DEFAULT '',
    token_expiry DATETIME,
    last_used_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_transfer_credentials_user
    ON transfer_credentials(user_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_transfer_credentials_user_name
    ON transfer_credentials(user_id, name);

CREATE TABLE IF NOT EXISTS transfer_oauth_clients (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    issuer_url TEXT NOT NULL,
    encrypted_client_id TEXT NOT NULL DEFAULT '',
    encrypted_client_secret TEXT NOT NULL DEFAULT '',
    grant_types TEXT NOT NULL DEFAULT '',
    scopes TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_transfer_oauth_clients_user
    ON transfer_oauth_clients(user_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_transfer_oauth_clients_user_name
    ON transfer_oauth_clients(user_id, name);

CREATE TABLE IF NOT EXISTS transfer_jobs (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    agent_job_id TEXT,
    source_credential_id TEXT,
    dest_credential_id TEXT,
    request_body TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (agent_job_id) REFERENCES jobs(id) ON DELETE SET NULL,
    FOREIGN KEY (source_credential_id) REFERENCES transfer_credentials(id) ON DELETE SET NULL,
    FOREIGN KEY (dest_credential_id) REFERENCES transfer_credentials(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_transfer_jobs_user
    ON transfer_jobs(user_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS transfer_jobs;
DROP TABLE IF EXISTS transfer_oauth_clients;
DROP TABLE IF EXISTS transfer_credentials;
DROP TABLE IF EXISTS transfer_history;
DROP TABLE IF EXISTS job_history;
DROP TABLE IF EXISTS transfers;
DROP TABLE IF EXISTS jobs;
-- +goose StatementEnd
