-- +goose Up
-- Create jobs table for active transfer jobs
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    created_at INTEGER NOT NULL,  -- Unix timestamp in seconds
    started_at INTEGER,
    completed_at INTEGER,
    options TEXT,  -- JSON-encoded transfer options
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at DESC);

-- +goose Down
DROP INDEX IF EXISTS idx_jobs_created_at;
DROP INDEX IF EXISTS idx_jobs_status;
DROP TABLE IF EXISTS jobs;
