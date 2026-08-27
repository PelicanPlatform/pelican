-- +goose Up
-- +goose StatementBegin

-- aup_documents stores the operator-edited Acceptable Use Policy.
--
-- Each row is an immutable snapshot: an operator who edits the AUP
-- inserts a new row rather than updating an existing one. The history
-- is permanent so users can always look up the exact text they
-- accepted, identified by the version hash on their User row
-- (users.aup_version).
--
-- Resolution order at runtime (see web_ui/aup.go:resolveAUP):
--   1. The active row in this table (the most recent one with
--      is_active = 1), if any.
--   2. The file at Server.AUPFile, if set.
--   3. The Pelican-shipped default in web_ui/resources/default_aup.md.
--   4. None — when Server.AUPFile is the literal "none" the AUP
--      requirement is disabled entirely.
--
-- The table layout is intentionally append-only. Edits go through
-- handleUpdateAUP, which rolls a new row in and (in the same
-- transaction) flips is_active off on the previous one.
CREATE TABLE aup_documents (
    id TEXT PRIMARY KEY,
    -- Version is the SHA-256 prefix of the content, the same shape
    -- handleGetAUP returns and users.aup_version stores. Unique so
    -- a no-op edit (same content) cannot create duplicate rows.
    version TEXT NOT NULL UNIQUE,
    content TEXT NOT NULL,
    -- Created_by is the user ID of the admin who uploaded this
    -- version, or one of the audit sentinels (CreatorSelfEnrolled /
    -- CreatorUnknown) when no real creator applies (e.g. seed at
    -- migration time).
    created_by TEXT NOT NULL DEFAULT 'unknown',
    auth_method TEXT NOT NULL DEFAULT '',
    auth_method_id TEXT NOT NULL DEFAULT '',
    -- Optional human-readable date the operator wants displayed in
    -- the footer ("This text was last updated on …"). When empty
    -- the footer falls back to the row's created_at.
    last_updated_label TEXT NOT NULL DEFAULT '',
    -- Exactly one row should have is_active = 1 at any time. The
    -- index below is a partial unique that enforces that invariant
    -- without forcing every other row to carry a NULL.
    is_active INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX idx_aup_documents_active ON aup_documents (is_active) WHERE is_active = 1;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_aup_documents_active;
DROP TABLE IF EXISTS aup_documents;
-- +goose StatementEnd
