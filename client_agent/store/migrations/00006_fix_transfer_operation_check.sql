-- +goose Up
-- The original transfers / transfer_history CHECK constraints permitted
-- ('get','put','copy','delete') but the client agent never emits 'delete' and
-- does emit 'prestage' (see client_agent/transfer_manager.go). Inserting a
-- prestage transfer therefore failed the constraint. SQLite cannot alter a
-- CHECK in place, so rebuild both tables with the correct operation domain.
--
-- No existing row can violate the new constraint: 'prestage' rows were
-- previously rejected (so none exist) and 'delete' was never generated.

CREATE TABLE transfers_new (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('get', 'put', 'copy', 'prestage')),
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
INSERT INTO transfers_new SELECT * FROM transfers;
DROP TABLE transfers;
ALTER TABLE transfers_new RENAME TO transfers;
CREATE INDEX IF NOT EXISTS idx_transfers_job_id ON transfers(job_id);
CREATE INDEX IF NOT EXISTS idx_transfers_status ON transfers(status);
CREATE INDEX IF NOT EXISTS idx_transfers_created_at ON transfers(created_at DESC);

CREATE TABLE transfer_history_new (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('get', 'put', 'copy', 'prestage')),
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
INSERT INTO transfer_history_new SELECT * FROM transfer_history;
DROP TABLE transfer_history;
ALTER TABLE transfer_history_new RENAME TO transfer_history;
CREATE INDEX IF NOT EXISTS idx_transfer_history_job_id ON transfer_history(job_id);
CREATE INDEX IF NOT EXISTS idx_transfer_history_completed_at ON transfer_history(completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_transfer_history_status ON transfer_history(status);

-- +goose Down
-- Restore the original ('get','put','copy','delete') operation domain.

CREATE TABLE transfers_new (
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
INSERT INTO transfers_new SELECT * FROM transfers;
DROP TABLE transfers;
ALTER TABLE transfers_new RENAME TO transfers;
CREATE INDEX IF NOT EXISTS idx_transfers_job_id ON transfers(job_id);
CREATE INDEX IF NOT EXISTS idx_transfers_status ON transfers(status);
CREATE INDEX IF NOT EXISTS idx_transfers_created_at ON transfers(created_at DESC);

CREATE TABLE transfer_history_new (
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
INSERT INTO transfer_history_new SELECT * FROM transfer_history;
DROP TABLE transfer_history;
ALTER TABLE transfer_history_new RENAME TO transfer_history;
CREATE INDEX IF NOT EXISTS idx_transfer_history_job_id ON transfer_history(job_id);
CREATE INDEX IF NOT EXISTS idx_transfer_history_completed_at ON transfer_history(completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_transfer_history_status ON transfer_history(status);
