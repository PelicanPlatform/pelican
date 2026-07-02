-- +goose Up
-- +goose StatementBegin

-- Generalize invite links so the same row layout serves both group-join
-- invites (the original use case) and password-set invites (a new use
-- case that lets an admin onboard a user without ever knowing their
-- password). Existing rows default to kind='group' to preserve behavior.
--
-- Also start tracking the auth context the link was *created* under, so a
-- later audit can answer "who minted this invite, and were they sitting at
-- the web UI or driving it from a script?"
ALTER TABLE group_invite_links ADD COLUMN kind TEXT NOT NULL DEFAULT 'group';
ALTER TABLE group_invite_links ADD COLUMN target_user_id TEXT NOT NULL DEFAULT '';
ALTER TABLE group_invite_links ADD COLUMN auth_method TEXT NOT NULL DEFAULT '';
ALTER TABLE group_invite_links ADD COLUMN auth_method_id TEXT NOT NULL DEFAULT '';

CREATE INDEX idx_invite_links_kind ON group_invite_links (kind);
CREATE INDEX idx_invite_links_target_user ON group_invite_links (target_user_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_invite_links_kind;
DROP INDEX IF EXISTS idx_invite_links_target_user;
-- SQLite cannot DROP COLUMN cleanly; the down migration leaves the new
-- columns in place.
-- +goose StatementEnd
