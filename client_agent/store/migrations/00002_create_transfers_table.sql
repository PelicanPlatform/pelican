-- +goose Up
-- Create transfers table for individual transfers within jobs
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

-- +goose Down
DROP INDEX IF EXISTS idx_transfers_created_at;
DROP INDEX IF EXISTS idx_transfers_status;
DROP INDEX IF EXISTS idx_transfers_job_id;
DROP TABLE IF EXISTS transfers;
