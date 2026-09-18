-- +goose Up
-- +goose StatementBegin

-- Mirror the group MEMBERSHIPS a provider asserts, not just the group's
-- existence (20260916120000 did the latter).
--
-- The problem being solved. When Issuer.GroupSource names an outside
-- provider, membership lives there: a user is in "ops" because their
-- token says so, and `group_members` has no row. That works for the
-- caller in front of us — their asserted names are resolved to group IDs
-- on each request — and fails for every decision made about a user who
-- is NOT in front of us:
--
--   * the share-token clamp (oa4mp.GetUserCollectionScopes) asks what
--     the SHARE OWNER can do on the parent collection, at mint time, with
--     no session for that owner. Asserted access is invisible, so the
--     clamp sees "no access" and silently kills the share.
--   * web_ui.IsSystemAdminUserID asks whether a TARGET account is a
--     system admin, to stop a server.user_admin from acting on one. An
--     admin whose authority comes from Server.AdminGroups plus an
--     asserted group reads as a non-admin, and the guard opens.
--   * an asserted group's member list in the UI is simply empty.
--
-- What this is NOT. A mirrored row is a CACHED authorization fact, and a
-- cache that outlives the fact is the same bug as a name that outlives
-- its principal. Two rules keep it honest, enforced in Go:
--
--   * asserted_at records when the provider last said it. A mirrored row
--     may only GRANT while it is fresh (Issuer.AssertedGroupMembershipTTL).
--   * freshness gates granting, NOT existence. A stale row is kept,
--     because a consumer asking a RESTRICTING question — "might this
--     account be an admin?" — must still see it and answer yes. Rows go
--     away only when the provider stops asserting them.
--
-- Only `file` can be refreshed without the user present (it is a local
-- file keyed by username); oidc and github refresh at login, which is
-- what the TTL exists to bound.

-- 'pelican' rows are memberships an administrator created through the
-- group API: authoritative, never expire, and an assertion never
-- overwrites one. Any other value names the provider that asserted it,
-- using the same vocabulary as groups.source.
ALTER TABLE group_members ADD COLUMN source TEXT NOT NULL DEFAULT 'pelican';

-- NULL for 'pelican' rows — they do not expire, so there is nothing to
-- timestamp. Non-NULL only on mirrored rows.
ALTER TABLE group_members ADD COLUMN asserted_at DATETIME;

-- The hot query is "every membership for this user", already served by
-- the (group_id, user_id) primary key only in the group_id direction.
-- Mirroring makes the user-first direction hot too: every login rewrites
-- one user's mirrored rows, and every authorization decision reads them.
CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members (user_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_group_members_user;
-- SQLite cannot DROP COLUMN cleanly; source and asserted_at are left in
-- place. Every pre-existing row is 'pelican', which is what the
-- pre-mirror code assumed of every row anyway.

-- +goose StatementEnd
