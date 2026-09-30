-- +goose Up
-- +goose StatementBegin

-- Re-key every collection authorization decision onto immutable IDs.
--
-- Issues #3752 and #3753: `collections.owner` held a username consulted
-- as an authorization fallback, and `collection_acls.group_id` held a
-- group name with no foreign key. Either could be vacated by a rename
-- or a delete and then reclaimed, carrying its grants to whoever took
-- the name. The commit message has the full sequences.
--
-- After this migration the only authorization handles in these tables
-- are IDs: `collections.owner_id`, and `collection_acls`
-- (subject_type, subject_id) where subject_id is a users.id, a
-- groups.id, or empty for the all-authenticated sentinel. Names live
-- only on the `users` / `groups` rows they belong to, so a rename is a
-- pure display change and a reclaimed name inherits nothing.

------------------------------------------------------------------
-- 1. Group provenance.
------------------------------------------------------------------
--
-- Records WHICH provider a group came from, using the same vocabulary
-- as the Issuer.GroupSource config value:
--
--   'pelican'  — created through Pelican's own group API; membership is
--                authoritative in `group_members`.
--   'oidc' / 'file' / 'github'
--              — asserted by that provider; Pelican records the group
--                only so the name has a stable ID for ACLs to key on.
--   'unknown'  — backfilled in step 2 from a pre-existing name-keyed
--                grant. Some provider asserts the name, but the old
--                schema did not record which; the next assertion stamps
--                the real one.
--
-- Every existing row was created through the API, so 'pelican' is the
-- correct default for the backfill.
ALTER TABLE groups ADD COLUMN source TEXT NOT NULL DEFAULT 'pelican';

------------------------------------------------------------------
-- 2. Mint a group row for every ACL target that has no local row.
------------------------------------------------------------------
--
-- These names were granted to provider-asserted groups this server
-- never had a record for; they need an ID before step 3 can re-key the
-- grants. `auth_template_eligible` is 1 because that is the behavior
-- they already had — FilterAuthTemplateEligibleGroups passes through
-- names with no row, so creating the row with 0 would silently revoke
-- template authority these names hold today.
--
-- `owner_id` is left empty; BootstrapAdminAndBackfillOwners adopts
-- ownerless groups on the next startup. The admin user's ID is not
-- knowable at SQL-migration time (it keys off Server.ExternalWebUrl),
-- which is why that step lives in Go.
--
-- `lower(hex(randomblob(4)))` matches database.generateSlug's format.
INSERT INTO groups (
    id, name, display_name, description, created_by,
    creator_auth_method, creator_auth_method_id,
    owner_id, admin_id, admin_type, auth_template_eligible,
    created_for_collection_id, source, created_at, updated_at
)
SELECT
    lower(hex(randomblob(4))), a.group_id, '', '', 'unknown',
    '', '',
    '', '', '', 1,
    '', 'unknown', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
FROM (SELECT DISTINCT group_id FROM collection_acls) AS a
WHERE a.group_id <> '@authenticated'
  AND a.group_id NOT LIKE 'user-%'
  AND NOT EXISTS (SELECT 1 FROM groups g WHERE g.name = a.group_id);

------------------------------------------------------------------
-- 3. Re-key collection_acls onto (subject_type, subject_id).
------------------------------------------------------------------
--
-- `granted_by` also moves from username to users.id; it is an audit
-- field, never joined, but leaving a username there is exactly the
-- "some columns hold names, some hold IDs" confusion this migration
-- exists to remove. Values that resolve to no user row at all are
-- collapsed to the 'unknown' sentinel already used by Creator.
CREATE TABLE collection_acls_new (
    collection_id TEXT NOT NULL,
    subject_type  TEXT NOT NULL,
    subject_id    TEXT NOT NULL,
    role          TEXT NOT NULL,
    granted_by    TEXT NOT NULL,
    granted_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at    DATETIME,
    PRIMARY KEY (collection_id, subject_type, subject_id, role)
);

-- 3a. The all-authenticated-users sentinel. Kept as its own subject
--     type rather than a magic ID so nothing has to reserve an ID
--     value that can never collide with a real slug.
INSERT OR IGNORE INTO collection_acls_new
    (collection_id, subject_type, subject_id, role, granted_by, granted_at, expires_at)
SELECT a.collection_id, 'authenticated', '', a.role,
       COALESCE((SELECT u.id FROM users u WHERE u.username = a.granted_by AND u.deleted_at IS NULL), 'unknown'),
       a.granted_at, a.expires_at
FROM collection_acls a
WHERE a.group_id = '@authenticated';

-- 3b. Personal grants (`user-<username>`) become subject_type='user'
--     keyed on the LIVE user's ID.
--
--     Rows whose username resolves to no live user are intentionally
--     dropped: that grant is precisely the dangling reference from
--     #3752 — the account was renamed or soft-deleted and whoever
--     claimed the username next would inherit the grant. A deleted
--     user has no authorizations by design, so nothing legitimate is
--     lost; the collection owner can re-issue the grant to the real
--     account if one exists.
INSERT OR IGNORE INTO collection_acls_new
    (collection_id, subject_type, subject_id, role, granted_by, granted_at, expires_at)
SELECT a.collection_id, 'user', u.id, a.role,
       COALESCE((SELECT g.id FROM users g WHERE g.username = a.granted_by AND g.deleted_at IS NULL), 'unknown'),
       a.granted_at, a.expires_at
FROM collection_acls a
JOIN users u ON u.username = substr(a.group_id, 6) AND u.deleted_at IS NULL
WHERE a.group_id LIKE 'user-%';

-- 3c. Group grants. Step 2 guarantees a row exists for every
--     non-sentinel, non-personal name, so this join loses nothing.
INSERT OR IGNORE INTO collection_acls_new
    (collection_id, subject_type, subject_id, role, granted_by, granted_at, expires_at)
SELECT a.collection_id, 'group', g.id, a.role,
       COALESCE((SELECT u.id FROM users u WHERE u.username = a.granted_by AND u.deleted_at IS NULL), 'unknown'),
       a.granted_at, a.expires_at
FROM collection_acls a
JOIN groups g ON g.name = a.group_id
WHERE a.group_id <> '@authenticated'
  AND a.group_id NOT LIKE 'user-%';

DROP TABLE collection_acls;
ALTER TABLE collection_acls_new RENAME TO collection_acls;

-- Supports the caller-side lookup "every ACL row naming one of my
-- subjects", which is how the listing and scope-minting queries run.
CREATE INDEX idx_collection_acls_subject ON collection_acls (subject_type, subject_id);

------------------------------------------------------------------
-- 4. collection_members.added_by moves from username to users.id.
------------------------------------------------------------------
UPDATE collection_members
SET added_by = COALESCE(
    (SELECT u.id FROM users u WHERE u.username = collection_members.added_by AND u.deleted_at IS NULL),
    'unknown'
);

------------------------------------------------------------------
-- 5. Drop collections.owner; owner_id is the only ownership handle.
------------------------------------------------------------------
--
-- Backfill first, and unlike the 20260429000000 backfill accept a
-- soft-deleted user as the match: the point is to preserve the link to
-- the account that actually owned the row. A soft-deleted owner confers
-- no authority (deleted users have no authorizations), so this is a
-- strictly better outcome than dropping the reference — if the account
-- is ever restored it regains its collections, and a *new* account that
-- claims the same username does not.
UPDATE collections
SET owner_id = COALESCE(
    (SELECT u.id FROM users u
      WHERE u.username = collections.owner
      ORDER BY (u.deleted_at IS NULL) DESC, u.created_at DESC
      LIMIT 1),
    ''
)
WHERE owner_id = '';

-- SQLite can't drop a column that participates in an index, and the
-- (owner, name) uniqueness has to become (owner_id, name) anyway, so
-- rebuild the table. The new index is PARTIAL: rows whose owner never
-- resolved to a user keep owner_id = '' and must not collide with each
-- other on name.
CREATE TABLE collections_new (
    id                   TEXT PRIMARY KEY,
    name                 TEXT NOT NULL,
    description          TEXT,
    owner_id             TEXT NOT NULL DEFAULT '',
    admin_id             TEXT NOT NULL DEFAULT '',
    namespace            TEXT NOT NULL,
    visibility           TEXT NOT NULL DEFAULT 'private',
    enable_sharing       INTEGER NOT NULL DEFAULT 0,
    parent_collection_id TEXT NOT NULL DEFAULT '',
    created_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO collections_new
    (id, name, description, owner_id, admin_id, namespace, visibility,
     enable_sharing, parent_collection_id, created_at, updated_at)
SELECT id, name, description, owner_id, admin_id, namespace, visibility,
       enable_sharing, parent_collection_id, created_at, updated_at
FROM collections;

DROP TABLE collections;
ALTER TABLE collections_new RENAME TO collections;

CREATE UNIQUE INDEX idx_owner_name ON collections (owner_id, name) WHERE owner_id <> '';
CREATE INDEX idx_collections_parent ON collections (parent_collection_id) WHERE parent_collection_id <> '';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Restoring the name-keyed schema would reintroduce the vulnerabilities
-- this migration exists to close, and the dropped `collections.owner`
-- usernames are not recoverable for rows whose owner_id never resolved.
-- The down migration is therefore a deliberate no-op: roll back by
-- restoring a backup taken before the upgrade.

-- +goose StatementEnd
