-- +goose Up
-- +goose StatementBegin

-- Migrate personal group references from "user-<username>" to "user-<user_id>".
-- Personal groups are virtual (never stored in the groups table). The only
-- persisted reference is in collection_acls.group_id, plus collections.owner
-- and collection_acls.granted_by which store the username directly.

-- Migrate collection ACLs that reference personal groups.
UPDATE collection_acls SET group_id = 'user-' || (
    SELECT u.id FROM users u
    WHERE collection_acls.group_id = 'user-' || u.username
    ORDER BY u.created_at ASC
    LIMIT 1
)
WHERE group_id LIKE 'user-%'
  AND EXISTS (
    SELECT 1 FROM users u WHERE collection_acls.group_id = 'user-' || u.username
);

-- Migrate collection_acls.granted_by from username to user ID where applicable.
UPDATE collection_acls SET granted_by = (
    SELECT u.id FROM users u
    WHERE collection_acls.granted_by = u.username
    ORDER BY u.created_at ASC
    LIMIT 1
)
WHERE EXISTS (
    SELECT 1 FROM users u WHERE collection_acls.granted_by = u.username
);

-- Migrate collections.owner from username to user ID.
UPDATE collections SET owner = (
    SELECT u.id FROM users u
    WHERE collections.owner = u.username
    ORDER BY u.created_at ASC
    LIMIT 1
)
WHERE EXISTS (
    SELECT 1 FROM users u WHERE collections.owner = u.username
);

-- Drop the (username, issuer) unique constraint. Username is a mutable display
-- name, not an identity key. The real identity uniqueness is (sub, issuer)
-- which is enforced by idx_user_sub_issuer.
DROP INDEX IF EXISTS idx_user_issuer;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- +goose StatementEnd
