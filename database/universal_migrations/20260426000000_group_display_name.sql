-- +goose Up
-- +goose StatementBegin

-- Per the user/group design contract: every group has BOTH a
-- machine-readable Name (admin-controlled, used in policy strings) and a
-- human-readable Display Name (owner-editable, used in the UI). Until
-- now Group only had Name and the Name was playing both roles. This
-- migration adds the column; the population happens lazily — existing
-- rows simply have an empty Display Name and the UI falls back to Name
-- in that case.
ALTER TABLE groups ADD COLUMN display_name TEXT NOT NULL DEFAULT '';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- SQLite cannot DROP COLUMN cleanly; the down migration is a no-op.
-- +goose StatementEnd
