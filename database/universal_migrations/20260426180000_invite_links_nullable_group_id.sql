-- +goose Up
-- +goose StatementBegin

-- Password-set invite links have no associated group. The original
-- schema declared `group_id TEXT NOT NULL DEFAULT ''` plus a FOREIGN
-- KEY(group_id) REFERENCES groups(id), which makes inserting a
-- password-kind row fail with SQLITE_CONSTRAINT_FOREIGNKEY: '' is not
-- a valid group ID and the FK refuses it.
--
-- The cleanest fix is to drop the FK. The cascade-on-group-delete
-- behavior is already redundantly implemented in Go: DeleteGroup
-- explicitly removes invite links for the group inside the same
-- transaction. Losing the FK enforcement therefore costs nothing
-- meaningful, and lets group_id remain a plain TEXT column with empty
-- string for the no-group cases (password kind, user-onboarding kind).
--
-- SQLite has no DROP CONSTRAINT, so this is the standard rebuild.

PRAGMA foreign_keys = OFF;

CREATE TABLE group_invite_links_new (
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
    kind TEXT NOT NULL DEFAULT 'group',
    target_user_id TEXT NOT NULL DEFAULT '',
    auth_method TEXT NOT NULL DEFAULT '',
    auth_method_id TEXT NOT NULL DEFAULT ''
    -- Intentionally NO FOREIGN KEY on group_id; the application layer
    -- handles cascading deletes (see database.DeleteGroup).
);

INSERT INTO group_invite_links_new
SELECT id, group_id, invite_token, created_by, created_at, updated_at,
       expires_at, is_single_use, redeemed_by, redeemed_at, revoked,
       kind, target_user_id, auth_method, auth_method_id
FROM group_invite_links;

DROP TABLE group_invite_links;
ALTER TABLE group_invite_links_new RENAME TO group_invite_links;

CREATE INDEX idx_invite_links_kind ON group_invite_links (kind);
CREATE INDEX idx_invite_links_target_user ON group_invite_links (target_user_id);

PRAGMA foreign_keys = ON;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- The down migration would have to re-add the FK; not implemented.
-- +goose StatementEnd
