-- +goose Up
-- Create job_history table for archived completed/failed/cancelled jobs
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
    total_bytes INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_job_history_completed_at ON job_history(completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_job_history_status ON job_history(status);
CREATE INDEX IF NOT EXISTS idx_job_history_created_at ON job_history(created_at DESC);

-- +goose Down
DROP INDEX IF EXISTS idx_job_history_created_at;
DROP INDEX IF EXISTS idx_job_history_status;
DROP INDEX IF EXISTS idx_job_history_completed_at;
DROP TABLE IF EXISTS job_history;
