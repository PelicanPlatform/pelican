-- +goose Up
-- +goose StatementBegin

-- New invite-link kind: 'collection_ownership'. The link, when
-- redeemed by an authenticated user, transfers Collection.OwnerID
-- (and the legacy Collection.Owner username) from the original
-- owner to the redeemer. Single-use is forced at the application
-- layer so a generated link cannot be reused after the first
-- successful transfer.
--
-- Schema-wise we only need a target column. CollectionID parallels
-- the existing GroupID / TargetUserID pattern: per-row, defaulted
-- to '' so older rows pass the NOT NULL constraint without a
-- backfill.
ALTER TABLE group_invite_links
  ADD COLUMN collection_id TEXT NOT NULL DEFAULT '';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- SQLite cannot DROP COLUMN cleanly; the down migration is a no-op.
-- +goose StatementEnd
