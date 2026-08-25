-- +goose Up
-- +goose StatementBegin

-- Make every identity equal: `user_identities` becomes the single home for
-- (sub, issuer) linkages, and the users table stops carrying a "primary" one.
--
-- Why: the invariants "a (sub, issuer) belongs to at most one user" and "a user
-- has at most one identity per issuer" were split across two tables, and SQLite
-- has no cross-table constraint. Each table's unique index enforced the rules
-- only against its own rows, so the gaps had to be closed by hand-written
-- checks in Go — and both directions were missed:
--
--   * CreateUserIdentity did not check other users' primary rows, so linking an
--     already-claimed identity inserted a row that GetUserByIdentity (which
--     consults users first) then ignored. The caller saw success; nothing
--     changed.
--   * LookupOrBootstrapUser looked only at users, so a *secondary* identity was
--     invisible to web login: an admin could link an identity and the user
--     would still get a brand-new second account on their next sign-in.
--
-- With one table, both invariants become ordinary unique indexes and the whole
-- class of bug goes away. See docs/external-token-exchange-design.md §6.

-- Step 1: quarantine rows that the unified indexes would reject.
--
-- These exist only where the bugs above already produced a split. Rather than
-- abort the upgrade, resolve them the way the running system resolves them
-- today — GetUserByIdentity consults users first, so the primary identity is
-- what callers currently observe, and the shadowed secondary row is the one
-- that loses. The discarded rows are kept so an operator can audit what was
-- reconciled instead of having to infer it.
CREATE TABLE IF NOT EXISTS user_identity_unification_conflicts (
    id TEXT,
    user_id TEXT,
    sub TEXT,
    issuer TEXT,
    created_at DATETIME,
    updated_at DATETIME,
    reason TEXT
);

-- 1a. A secondary row holding a (sub, issuer) that a *different* live user
--     already owns as their primary.
INSERT INTO user_identity_unification_conflicts
    (id, user_id, sub, issuer, created_at, updated_at, reason)
SELECT ui.id, ui.user_id, ui.sub, ui.issuer, ui.created_at, ui.updated_at,
       'shadowed by another user''s primary identity'
FROM user_identities ui
JOIN users u
  ON u.sub = ui.sub AND u.issuer = ui.issuer AND u.deleted_at IS NULL
WHERE ui.user_id <> u.id;

-- 1b. A secondary row at the same issuer as its own user's primary identity,
--     which would violate the one-identity-per-issuer-per-user index.
INSERT INTO user_identity_unification_conflicts
    (id, user_id, sub, issuer, created_at, updated_at, reason)
SELECT ui.id, ui.user_id, ui.sub, ui.issuer, ui.created_at, ui.updated_at,
       'duplicate issuer for the same user'
FROM user_identities ui
JOIN users u
  ON u.id = ui.user_id AND u.issuer = ui.issuer AND u.deleted_at IS NULL
WHERE ui.sub <> u.sub;

DELETE FROM user_identities
WHERE id IN (SELECT id FROM user_identity_unification_conflicts);

-- Step 2: promote every live user's primary identity into user_identities.
--
-- Soft-deleted users are deliberately skipped. Their tombstone exists for audit
-- and foreign-key resolution, not for authentication, and re-inserting their
-- identities would re-reserve (sub, issuer) against re-enrollment — the exact
-- problem 20260503120000 fixed by making the users indexes partial.
INSERT INTO user_identities (id, user_id, sub, issuer, created_at, updated_at)
SELECT lower(hex(randomblob(16))), u.id, u.sub, u.issuer, u.created_at, u.updated_at
FROM users u
WHERE u.deleted_at IS NULL
  AND u.sub <> ''
  AND u.issuer <> ''
  AND NOT EXISTS (
      SELECT 1 FROM user_identities ui
      WHERE ui.sub = u.sub AND ui.issuer = u.issuer
  )
  AND NOT EXISTS (
      SELECT 1 FROM user_identities ui
      WHERE ui.user_id = u.id AND ui.issuer = u.issuer
  );

-- Step 3: drop the now-redundant users-side identity columns and their index.
-- The index must go first; SQLite refuses to drop an indexed column.
DROP INDEX IF EXISTS idx_user_sub_issuer;
ALTER TABLE users DROP COLUMN sub;
ALTER TABLE users DROP COLUMN issuer;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Lossy by nature: a user may now hold several identities and only one can be
-- restored to the row. The oldest is chosen, which for accounts that predate
-- this migration is the identity that used to be the primary one.
ALTER TABLE users ADD COLUMN sub TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN issuer TEXT NOT NULL DEFAULT '';

UPDATE users SET
    sub = COALESCE((
        SELECT ui.sub FROM user_identities ui
        WHERE ui.user_id = users.id
        ORDER BY ui.created_at, ui.id LIMIT 1), ''),
    issuer = COALESCE((
        SELECT ui.issuer FROM user_identities ui
        WHERE ui.user_id = users.id
        ORDER BY ui.created_at, ui.id LIMIT 1), '');

DELETE FROM user_identities
WHERE EXISTS (
    SELECT 1 FROM users u
    WHERE u.id = user_identities.user_id
      AND u.sub = user_identities.sub
      AND u.issuer = user_identities.issuer
);

-- Exclude the empty pair from the restored index. Unification permits an
-- account to have zero identities (its sub/issuer restore to ''), and two such
-- live users would collide on ('','') under a plain partial index and abort the
-- down-migration. The forward direction never produced empty pairs, so this is
-- strictly a down-path accommodation.
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_sub_issuer
    ON users (sub, issuer)
    WHERE deleted_at IS NULL AND sub <> '' AND issuer <> '';

DROP TABLE IF EXISTS user_identity_unification_conflicts;

-- +goose StatementEnd
