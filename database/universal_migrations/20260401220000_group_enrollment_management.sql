-- +goose Up
-- +goose StatementBegin

-- Add owner_id and admin fields to groups table.
-- owner_id: the user who owns the group (can change owner, admin, and members).
-- admin_id: a user or group that can manage members but not change owner/admin.
-- admin_type: 'user' or 'group' to indicate what admin_id references.
ALTER TABLE groups ADD COLUMN owner_id TEXT NOT NULL DEFAULT '';
ALTER TABLE groups ADD COLUMN admin_id TEXT NOT NULL DEFAULT '';
ALTER TABLE groups ADD COLUMN admin_type TEXT NOT NULL DEFAULT '';
-- SQLite < 3.35.0 rejects CURRENT_TIMESTAMP as the default for ALTER TABLE
-- ADD COLUMN ("non-constant default"). Use a constant epoch sentinel and
-- backfill below; the GORM model auto-populates UpdatedAt on every write,
-- so the default is only a fallback for raw-SQL inserts.
ALTER TABLE groups ADD COLUMN updated_at DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00';
UPDATE groups SET updated_at = CURRENT_TIMESTAMP WHERE updated_at = '1970-01-01 00:00:00';

-- Backfill owner_id from created_by for existing groups.
UPDATE groups SET owner_id = created_by WHERE owner_id = '';

-- Add user status tracking fields.
ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE users ADD COLUMN last_login_at DATETIME;
ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT '';

-- Add AUP (Acceptable Use Policy) tracking fields.
ALTER TABLE users ADD COLUMN aup_version TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN aup_agreed_at DATETIME;
-- See note above on the constant default.
ALTER TABLE users ADD COLUMN updated_at DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00';
UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE updated_at = '1970-01-01 00:00:00';

-- Create group_invite_links table for invite link management.
-- invite_token stores the bcrypt hash of the token; the plaintext is returned only once at creation.
-- group_id may be empty for user-onboarding invites (no group addition).
CREATE TABLE group_invite_links (
    id TEXT PRIMARY KEY,
    group_id TEXT NOT NULL DEFAULT '',
    invite_token TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    is_single_use INTEGER NOT NULL DEFAULT 0,
    redeemed_by TEXT NOT NULL DEFAULT '',
    redeemed_at DATETIME,
    revoked INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
);

-- Create user_identities table for multiple identities per user.
CREATE TABLE user_identities (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    sub TEXT NOT NULL,
    issuer TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_identity_sub_issuer ON user_identities (sub, issuer);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_identity_sub_issuer;
DROP TABLE IF EXISTS user_identities;
DROP TABLE IF EXISTS group_invite_links;
-- SQLite does not support DROP COLUMN, so we cannot cleanly revert ALTER TABLE changes.
-- The down migration drops the new tables only.
-- +goose StatementEnd
