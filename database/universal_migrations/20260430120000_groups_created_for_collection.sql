-- +goose Up
-- +goose StatementBegin

-- Per the demo punch list (#2C): "the transfer-owner flow of the
-- collection should also transfer the ownership of any newly created
-- group during the onboarding."
--
-- created_for_collection_id is the breadcrumb we leave at onboarding
-- time so the redemption path can find the groups that came along
-- with a collection and cascade ownership to the new owner. Without
-- this column there's no reliable way to distinguish "iota-readers,
-- minted alongside the iota collection, should follow it on
-- transfer" from "shared-team-readers, attached to iota AND alpha,
-- should NOT follow either of them."
--
-- Empty string (the GORM-friendly default) means "this group is
-- standalone; ownership transfer of any collection it's attached
-- to does NOT cascade to it." That matches the behavior of every
-- group already in the table — backfill is a no-op.

ALTER TABLE groups
    ADD COLUMN created_for_collection_id TEXT NOT NULL DEFAULT '';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- SQLite cannot DROP COLUMN cleanly; the down migration is a no-op.
-- +goose StatementEnd
