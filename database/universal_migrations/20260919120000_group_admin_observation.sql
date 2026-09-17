-- +goose Up
-- +goose StatementBegin

-- A latch recording what Pelican has observed about an account's
-- group-derived administrator privileges, so that "we have not
-- established that this account is safe to touch" is a state the
-- user-admin guard can see rather than a silence it has to interpret.
--
--   'unknown'   — never established. Treated as a possible
--                 administrator, so the guard refuses. The default, and
--                 what every pre-existing row gets.
--   'possible'  — observed holding a group that confers an admin scope.
--                 Sticky: a provider retracting the membership removes
--                 the evidence, not the history.
--   'ruled-out' — groups observed, none of them administrative.
--
-- A full server.admin bypasses the guard entirely, so a latched account
-- is still manageable — just not by a user-administrator.
ALTER TABLE users
    ADD COLUMN group_admin_status TEXT NOT NULL DEFAULT 'unknown';

-- When this account's asserted group set was last observed — for the
-- operator wondering why an account is still 'unknown'.
ALTER TABLE users ADD COLUMN groups_observed_at DATETIME;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- SQLite cannot DROP COLUMN cleanly; both columns are left in place.
-- Reverting the guard's behavior is a code change, not a schema one.
-- +goose StatementEnd
