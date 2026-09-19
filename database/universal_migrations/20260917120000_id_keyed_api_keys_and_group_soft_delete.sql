-- +goose NO TRANSACTION
--
-- Required by step 2. `group_members.group_id` carries
-- `REFERENCES groups(id) ON DELETE CASCADE`, and rebuilding `groups`
-- necessarily drops the old table — which SQLite treats as deleting
-- every row in it, firing that cascade and taking every group
-- membership on the server with it.
--
-- The only pragma that prevents this is `foreign_keys=OFF`, and it is a
-- no-op inside a transaction: `defer_foreign_keys` and
-- `legacy_alter_table` were both measured to lose the rows anyway. So
-- the migration runs unwrapped, which is what SQLite's own
-- rebuild-the-table procedure prescribes. The cost is that a failure
-- part-way leaves the schema half-migrated and the operator restores
-- from backup; the alternative was silently emptying `group_members`.

-- +goose Up
-- +goose StatementBegin

-- Follow-on to 20260916120000, which re-keyed collection ownership and
-- ACLs onto immutable IDs. Two more places still mixed the two kinds of
-- handle, or let one be reused.

------------------------------------------------------------------
-- 1. api_keys.created_by becomes a User.ID.
------------------------------------------------------------------
--
-- The column has always been read as a user ID — every function in
-- api_token/ names the parameter `userID`, and the revocation contract
-- ("a user who loses a management privilege loses it on every API token
-- they minted") intersects the key's persisted scopes against that
-- user's CURRENT effective scopes. But the create handler passed the
-- caller's *username*, so the lookup fell back to matching on username.
--
-- That fallback made a released username re-activate a dead key: alice
-- mints a key carrying server.collection_admin, alice is deleted (the
-- key is not revoked, and its management scopes simply go dormant),
-- someone new is onboarded as "alice" and granted the same scope — and
-- on the next call the old key's scopes intersect against the NEW alice
-- and come back to life for whoever still holds the secret. Renaming a
-- user had the mirror effect, silently bricking every key they minted.
--
-- Resolution order matters: try the value as an ID first, because a
-- legacy username could itself be shaped like one. A value that matches
-- neither becomes the empty string, which intersectWithUserScopes
-- already treats as "cannot attribute this key to any current
-- authority" and fails closed on every user-grantable scope. Data-plane
-- and inter-server scopes are unaffected either way: those are bearer
-- authority, not derived from a creator's role.
UPDATE api_keys
SET created_by = COALESCE(
    (SELECT u.id FROM users u WHERE u.id = api_keys.created_by),
    (SELECT u.id FROM users u WHERE u.username = api_keys.created_by AND u.deleted_at IS NULL),
    ''
)
WHERE created_by IS NOT NULL AND created_by <> '';

------------------------------------------------------------------
-- 2. Groups become soft-deletable.
------------------------------------------------------------------
--
-- Group.ID was the one authorization handle in this schema that could
-- be REUSED: DeleteGroup physically removed the row, and generateSlug
-- picks 8 hex characters with no uniqueness check, so a later group
-- could be minted with a dead group's ID and silently inherit whatever
-- still referenced it — group_scopes rows, a collections.admin_id, a
-- groups.admin_id. That is the same "a released handle carries its
-- authority to the next holder" shape as #3752, one table over.
--
-- Soft delete closes it the way the users table already does: the row
-- stays, so the ID is permanently spent and historical references
-- (groups.created_by, an audit trail naming the group) remain
-- resolvable, while GORM's default scope hides it from every ordinary
-- query so it confers nothing.
--
-- NULL means live; any timestamp means deleted at that moment.
--
-- The name, unlike the ID, IS released — matching the users table
-- (20260503120000). Nothing keys on a group name any more, so a new
-- group taking a dead one's name inherits nothing, and refusing to
-- release it would leave a name permanently unusable after a cleanup.
--
-- That requires rebuilding the table: `name TEXT NOT NULL UNIQUE` in
-- 20250729143942 is an inline column constraint, which SQLite backs
-- with an implicit sqlite_autoindex that DROP INDEX cannot touch. The
-- column list below is the state after 20260916120000.
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

-- Reverting would let a dead group's name be taken while its rows are
-- still soft-deleted, and the api_keys.created_by values are not
-- recoverable as usernames. Roll back by restoring a backup instead.

-- +goose StatementEnd
