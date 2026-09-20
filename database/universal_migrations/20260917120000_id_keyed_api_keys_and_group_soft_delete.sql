-- +goose NO TRANSACTION
--
-- Required by step 2. Rebuilding `groups` drops the old table, which
-- SQLite treats as deleting every row — firing group_members' ON DELETE
-- CASCADE and taking every membership on the server with it. Only
-- `foreign_keys=OFF` prevents that, and it is a no-op inside a
-- transaction (`defer_foreign_keys` and `legacy_alter_table` were both
-- measured to lose the rows anyway). Running unwrapped is what SQLite's
-- own rebuild-the-table procedure prescribes. The cost is that a
-- failure part-way leaves the schema half-migrated and the operator
-- restores from backup.

-- +goose Up
-- +goose StatementBegin

-- Follow-on to 20260916120000, which re-keyed collection ownership and
-- ACLs onto immutable IDs. Two more places still mixed the two kinds of
-- handle, or let one be reused.

------------------------------------------------------------------
-- 1. api_keys.created_by becomes a User.ID.
------------------------------------------------------------------
--
-- The column has always been READ as a user ID, but the create handler
-- wrote the caller's username, so the lookup fell back to matching on
-- username — which let a released username re-activate a dead key. See
-- the commit message for the full sequence.
--
-- Resolution order matters: try the value as an ID first, because a
-- legacy username could itself be shaped like one. A value that matches
-- neither becomes the empty string, which intersectWithUserScopes
-- treats as "cannot attribute this key to any current authority" and
-- fails closed on every user-grantable scope.
--
-- The `created_at` clause keeps this migration from rebinding the key
-- against an account created *after* the key (which should be
-- impossible).
UPDATE api_keys
SET created_by = COALESCE(
    (SELECT u.id FROM users u WHERE u.id = api_keys.created_by),
    (SELECT u.id FROM users u
      WHERE u.username = api_keys.created_by
        AND u.deleted_at IS NULL
        AND u.created_at <= api_keys.created_at),
    ''
)
WHERE created_by IS NOT NULL AND created_by <> '';

------------------------------------------------------------------
-- 2. Groups become soft-deletable.
------------------------------------------------------------------
--
-- Group.ID was the one authorization primitive that could be reused:
-- DeleteGroup physically removed the row, and generateSlug picks 8 hex
-- characters with no uniqueness check, so a later group could be minted
-- with a dead group's ID and inherit whatever still referenced it.
--
-- Soft delete closes it the way the users table already does: the row
-- stays, so the ID is permanently spent and historical references stay
-- resolvable.
--
-- The NAME, unlike the ID, IS released, matching the users table
-- (20260503120000): nothing keys on a group name any more, and refusing
-- to release it would leave a name permanently unusable after a
-- cleanup. That requires rebuilding the table, because the inline
-- `name TEXT NOT NULL UNIQUE` from 20250729143942 is backed by an
-- implicit sqlite_autoindex that DROP INDEX cannot touch. The column
-- list below is the state after 20260916120000.
--
-- foreign_keys=OFF for the duration: see the NO TRANSACTION note at the
-- top of this file. Without it the DROP TABLE below cascades through
-- group_members.group_id and deletes every membership.
PRAGMA foreign_keys = OFF;

CREATE TABLE groups_new (
    id                        TEXT PRIMARY KEY,
    name                      TEXT NOT NULL,
    description               TEXT,
    created_by                TEXT NOT NULL,
    created_at                DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    owner_id                  TEXT NOT NULL DEFAULT '',
    admin_id                  TEXT NOT NULL DEFAULT '',
    admin_type                TEXT NOT NULL DEFAULT '',
    updated_at                DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00',
    display_name              TEXT NOT NULL DEFAULT '',
    creator_auth_method       TEXT NOT NULL DEFAULT '',
    creator_auth_method_id    TEXT NOT NULL DEFAULT '',
    created_for_collection_id TEXT NOT NULL DEFAULT '',
    auth_template_eligible    INTEGER NOT NULL DEFAULT 1,
    source                    TEXT NOT NULL DEFAULT 'pelican',
    deleted_at                DATETIME
);

INSERT INTO groups_new
    (id, name, description, created_by, created_at, owner_id, admin_id,
     admin_type, updated_at, display_name, creator_auth_method,
     creator_auth_method_id, created_for_collection_id,
     auth_template_eligible, source)
SELECT id, name, description, created_by, created_at, owner_id, admin_id,
       admin_type, updated_at, display_name, creator_auth_method,
       creator_auth_method_id, created_for_collection_id,
       auth_template_eligible, source
FROM groups;

DROP TABLE groups;
ALTER TABLE groups_new RENAME TO groups;

CREATE INDEX idx_groups_deleted_at ON groups (deleted_at);
CREATE UNIQUE INDEX idx_groups_name_live
    ON groups (name)
    WHERE deleted_at IS NULL;

PRAGMA foreign_keys = ON;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- The api_keys.created_by values are not recoverable as usernames.
-- Roll back by restoring a backup instead.

-- +goose StatementEnd
