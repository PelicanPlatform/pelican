-- +goose Up
-- +goose StatementBegin

-- Mirror the group MEMBERSHIPS a provider asserts, not just the group's
-- existence (20260916120000 did the latter).
--
-- When Issuer.GroupSource names an outside provider, membership lives
-- there and `group_members` has no row. That works for the immediate
-- caller, whose asserted names are resolved via the request, and fails
-- for decisions made about a user who is not the requestor.  For example,
-- the share-token logic is based on what the share OWNER may do, not
-- the current requester.
--
-- A mirrored row is a CACHED membership fact, and two rules enforced
-- in Go keep it honest: a row may only GRANT while the provider has
-- asserted it within Issuer.AssertedGroupMembershipTTL, but the stale
-- row is kept in case if we want to determine possible membership
-- ("might this account be an admin?").  Rows go away only if the
-- provider doesn't assert them in the next login.

-- 'pelican' rows are memberships an administrator created through the
-- group API: authoritative, never expire, and an assertion never
-- overwrites one. Any other value is the provider that asserted it.
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
