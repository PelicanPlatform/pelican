-- +goose Up
-- +goose StatementBegin

-- New invite-link kind: 'registration_ownership'. The link, when
-- redeemed by an authenticated user, transfers ownership of a registry
-- registration (registrations.admin_metadata user_id) to the redeemer.
-- Single-use is forced at the application layer, mirroring
-- collection-ownership invites.
--
-- RegistrationID parallels the existing GroupID / TargetUserID /
-- CollectionID pattern: per-row, defaulted to 0 so older rows pass the
-- NOT NULL constraint without a backfill. (Registration IDs are the
-- integer primary keys of the registrations table.)
ALTER TABLE group_invite_links
  ADD COLUMN registration_id INTEGER NOT NULL DEFAULT 0;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- SQLite cannot DROP COLUMN cleanly; the down migration is a no-op.
-- +goose StatementEnd
