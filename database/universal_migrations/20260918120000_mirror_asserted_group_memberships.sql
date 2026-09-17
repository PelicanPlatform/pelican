-- +goose Up
-- +goose StatementBegin

-- Mirror the group MEMBERSHIPS a provider asserts, not just the group's
-- existence (20260916120000 did the latter).
--
-- When Issuer.GroupSource names an outside provider, membership lives
-- there and `group_members` has no row. That works for the caller in
-- front of us, whose asserted names are resolved per request, and fails
-- for every decision made about a user who is not: the share-token
-- clamp asking what the share OWNER may do, the guard asking whether a
-- TARGET account is an administrator, the UI listing a group's members.
--
-- A mirrored row is a CACHED authorization fact, and two rules enforced
-- in Go keep it honest: a row may only GRANT while the provider has
-- asserted it within Issuer.AssertedGroupMembershipTTL, but freshness
-- gates granting and NOT existence — a stale row is kept, because a
-- restricting question ("might this account be an admin?") must still
-- see it. Rows go away only when the provider stops asserting them.

-- 'pelican' rows are memberships an administrator created through the
-- group API: authoritative, never expire, and an assertion never
-- overwrites one. Any other value names the provider that asserted it,
-- using the same vocabulary as groups.source.
ALTER TABLE group_members ADD COLUMN source TEXT NOT NULL DEFAULT 'pelican';

-- NULL on 'pelican' rows — they do not expire. Non-NULL only on
-- mirrored rows.
ALTER TABLE group_members ADD COLUMN asserted_at DATETIME;

-- The (group_id, user_id) primary key serves the group-first direction
-- only. Mirroring makes the user-first direction hot too: every login
-- rewrites one user's mirrored rows, and every authorization decision
-- reads them.
CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members (user_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_group_members_user;
-- SQLite cannot DROP COLUMN cleanly; source and asserted_at are left in
-- place. Every pre-existing row is 'pelican', which is what the
-- pre-mirror code assumed of every row anyway.

-- +goose StatementEnd
