-- +goose Up
-- +goose StatementBegin

-- Follow-on to 20260916120000, which re-keyed collection ownership and
-- ACLs onto immutable IDs.
--
-- Deliberately its own migration, and a transactional one. It used to
-- share a file with the `groups` rebuild, which must run unwrapped so
-- foreign keys can be turned off (see 20260917120000). That put this
-- UPDATE outside a transaction too, for no reason: a failure during the
-- rebuild left these rows already rewritten while goose still recorded
-- the previous version, so the retry re-ran an UPDATE that had already
-- happened. Split, this one either applies or does not.

------------------------------------------------------------------
-- api_keys.created_by becomes a User.ID.
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

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- The original values were usernames, and which account a username
-- referred to at the time is exactly what was not recoverable. Nothing
-- to restore; roll back from a backup taken before the upgrade.
-- +goose StatementEnd
