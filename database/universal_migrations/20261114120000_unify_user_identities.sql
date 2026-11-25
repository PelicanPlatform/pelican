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
-- class of bug goes away.

-- Step 1: promote every live user's primary identity into user_identities.
--
-- Deliberately unguarded. user_identities already carries UNIQUE(sub, issuer)
-- and UNIQUE(user_id, issuer), so a pair the unified model cannot hold aborts
-- the upgrade here rather than being quietly reconciled into something an
-- operator would have to go looking for.
--
-- Such a pair can only exist where an administrator linked an identity that a
-- different live account already held as its primary, or a second identity at
-- an issuer where that account already had one. Both are reachable only
-- through the admin-only `POST /users/{id}/identities` and `identity add`, so
-- in practice the count is zero. If an upgrade does stop here, the remedy is
-- to decide which account owns the identity and delete the losing row from
-- user_identities; the conflicting pair is named in the error.
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
  AND u.issuer <> '';

-- Step 2: drop the now-redundant users-side identity columns and their index.
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

-- +goose StatementEnd
