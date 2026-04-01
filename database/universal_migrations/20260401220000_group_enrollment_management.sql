-- +goose Up
-- +goose StatementBegin

-- Add owner_id and admin fields to groups table.
-- owner_id: the user who owns the group (can change owner, admin, and members).
-- admin_id: a user or group that can manage members but not change owner/admin.
-- admin_type: 'user' or 'group' to indicate what admin_id references.
ALTER TABLE groups ADD COLUMN owner_id TEXT NOT NULL DEFAULT '';
ALTER TABLE groups ADD COLUMN admin_id TEXT NOT NULL DEFAULT '';
ALTER TABLE groups ADD COLUMN admin_type TEXT NOT NULL DEFAULT '';

-- Backfill owner_id from created_by for existing groups.
UPDATE groups SET owner_id = created_by WHERE owner_id = '';

-- Add user status tracking fields.
-- status: 'active' or 'inactive'.
-- last_login_at: timestamp of the last login.
-- display_name: human-readable display name.
ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE users ADD COLUMN last_login_at DATETIME;
ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT '';

-- Add AUP (Acceptable Use Policy) tracking fields.
-- aup_version: version string of the AUP the user agreed to.
-- aup_agreed_at: timestamp when the user agreed to the AUP.
ALTER TABLE users ADD COLUMN aup_version TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN aup_agreed_at DATETIME;

-- Create group_invite_links table for invite link management.
CREATE TABLE group_invite_links (
    id TEXT PRIMARY KEY,
    group_id TEXT NOT NULL,
    invite_token TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    is_single_use INTEGER NOT NULL DEFAULT 0,
    redeemed_by TEXT NOT NULL DEFAULT '',
    redeemed_at DATETIME,
    revoked INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
);

-- Create user_identities table for multiple identities per user.
-- This allows associating multiple OAuth2/OIDC identities with a single user.
CREATE TABLE user_identities (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    sub TEXT NOT NULL,
    issuer TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
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
