-- +goose Up
-- Create transfer_history table for archived transfers
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

-- +goose Down
DROP INDEX IF EXISTS idx_transfer_history_status;
DROP INDEX IF EXISTS idx_transfer_history_completed_at;
DROP INDEX IF EXISTS idx_transfer_history_job_id;
DROP TABLE IF EXISTS transfer_history;
