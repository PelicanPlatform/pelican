-- +goose Up
-- +goose StatementBegin

-- A latch recording what Pelican has observed about an account's
-- group-derived administrator privileges.
--
-- The problem. web_ui.IsSystemAdminUserID exists to stop a caller
-- holding only server.user_admin from acting on a system administrator's
-- account — renaming it, deleting it, or minting a password-set invite
-- for it. It answers by evaluating the target's privileges, and when
-- those come from Server.AdminGroups plus a group an outside provider
-- asserts, there may be nothing on this server to evaluate: membership
-- lives at the provider. The guard then read the account as an ordinary
-- user and opened.
--
-- Mirroring memberships (20260918120000) narrows that to accounts
-- Pelican has never observed, which is not the same as closing it. This
-- column closes it, by making "we have not established that this
-- account is safe to touch" a state the guard can see rather than a
-- silence it has to interpret:
--
--   'unknown'   — Pelican has never established this account's
--                 group-derived privileges. The guard treats it as a
--                 possible administrator and refuses. This is the
--                 DEFAULT, and every pre-existing row gets it: before
--                 this migration nothing was recorded, so nothing is
--                 known.
--   'possible'  — the account has been observed holding a group that
--                 confers an administrator scope. STICKY: never
--                 downgraded, because a provider retracting the
--                 membership removes the evidence but not the history,
--                 and the whole point is to fail safe on evidence we no
--                 longer have.
--   'ruled-out' — the account's groups have been observed and none of
--                 them confers an administrator scope. The guard allows
--                 a user-administrator to proceed.
--
-- Recourse, deliberately: a full server.admin bypasses this guard
-- entirely (every call site tests `!isAdmin && ...`), so an account
-- latched 'possible' is still manageable — just not by a
-- user-administrator. That is the intended shape. There is no API to
-- clear the latch, because an API to clear it would be an API to defeat
-- the guard.
ALTER TABLE users
    ADD COLUMN group_admin_status TEXT NOT NULL DEFAULT 'unknown';

-- Records when this account's provider-asserted group set was last
-- observed. Distinct from group_admin_status, which says what the
-- observation concluded; this says when it happened, for the operator
-- who wants to know why an account is still 'unknown'.
ALTER TABLE users ADD COLUMN groups_observed_at DATETIME;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- SQLite cannot DROP COLUMN cleanly; both columns are left in place.
-- Reverting the guard to its previous behavior is a code change, not a
-- schema one.
-- +goose StatementEnd
