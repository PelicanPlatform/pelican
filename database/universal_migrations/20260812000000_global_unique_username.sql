-- +goose Up
-- +goose StatementBegin

-- Reconcile duplicate live usernames BEFORE enforcing global uniqueness.
--
-- The old index was UNIQUE(username, issuer): two live accounts could share a
-- username as long as their issuers differed, and existing databases contain
-- exactly that. Creating a UNIQUE(username) index on such a database fails the
-- migration outright and the server will not start. Rather than abort the
-- upgrade, keep the oldest account's username and rename the rest with a
-- suffix drawn from their (unique) id, recording every rename so an operator
-- can merge the accounts afterward (link the identities with AdoptUserIdentity,
-- then rename back).
--
-- NOTE: this reconciliation logically belongs to the change that makes username
-- globally unique. It lives here because that change (this file) is what fails
-- without it; if that work is revised upstream, fold this block into it.
CREATE TABLE IF NOT EXISTS username_uniqueness_conflicts (
    id                TEXT,
    original_username TEXT,
    new_username      TEXT,
    reconciled_at     DATETIME
);

-- The losers are every live row that is not the oldest for its username.
-- ROW_NUMBER partitions by username; rank 1 (oldest by created_at, id as the
-- tiebreak) keeps the name, ranks > 1 are renamed. The id suffix guarantees the
-- new name is itself unique, since id is the primary key.
INSERT INTO username_uniqueness_conflicts (id, original_username, new_username, reconciled_at)
SELECT id, username, username || '-' || substr(id, 1, 8), CURRENT_TIMESTAMP
FROM users
WHERE deleted_at IS NULL
  AND id IN (
      SELECT id FROM (
          SELECT id,
                 ROW_NUMBER() OVER (PARTITION BY username ORDER BY created_at, id) AS rn
          FROM users
          WHERE deleted_at IS NULL
      ) WHERE rn > 1
  );

UPDATE users
SET username = username || '-' || substr(id, 1, 8)
WHERE id IN (SELECT id FROM username_uniqueness_conflicts);

-- Make username GLOBALLY unique among live rows, replacing the per-issuer
-- UNIQUE(username, issuer).
DROP INDEX IF EXISTS idx_user_issuer;
CREATE UNIQUE INDEX idx_user_username_live
    ON users (username)
    WHERE deleted_at IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Drop the global-unique index FIRST: restoring the reconciled usernames
-- re-creates the duplicates it forbids, so it has to be gone before the UPDATE.
DROP INDEX IF EXISTS idx_user_username_live;

-- Put the reconciled usernames back. Under the (username, issuer) index they
-- are legal again, because the accounts that collided had distinct issuers to
-- begin with.
UPDATE users
SET username = (
    SELECT original_username FROM username_uniqueness_conflicts c WHERE c.id = users.id
)
WHERE id IN (SELECT id FROM username_uniqueness_conflicts);

DROP TABLE IF EXISTS username_uniqueness_conflicts;

-- Restore the per-issuer partial unique index (state after 20260503120000).
CREATE UNIQUE INDEX idx_user_issuer
    ON users (username, issuer)
    WHERE deleted_at IS NULL;

-- +goose StatementEnd
