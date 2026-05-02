-- +goose Up
-- +goose StatementBegin

-- user_scopes / group_scopes hold first-class scope grants for
-- individual users and for groups respectively. The runtime
-- EffectiveScopes(userID, externalGroupNames) helper returns the
-- union of:
--   - rows in user_scopes for that user,
--   - rows in group_scopes for groups the user is a row-member of, AND
--   - rows in group_scopes for groups whose name appears in the
--     caller's wlcg.groups (cookie-asserted) claim.
--
-- These tables intentionally allow only the "user-grantable" subset
-- of scopes from docs/scopes.yaml — data-plane scopes (wlcg.*,
-- scitokens.*) and inter-server scopes are not stored here. The
-- runtime layer enforces the allow-list when granting.
--
-- Each row records who granted the scope and how they were
-- authenticated, so an audit trail is available without a separate
-- log. Granting the same scope twice is a no-op (PRIMARY KEY across
-- target + scope).
CREATE TABLE user_scopes (
    user_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    granted_by TEXT NOT NULL DEFAULT 'unknown',
    auth_method TEXT NOT NULL DEFAULT '',
    auth_method_id TEXT NOT NULL DEFAULT '',
    granted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, scope)
);

CREATE INDEX idx_user_scopes_scope ON user_scopes (scope);

CREATE TABLE group_scopes (
    group_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    granted_by TEXT NOT NULL DEFAULT 'unknown',
    auth_method TEXT NOT NULL DEFAULT '',
    auth_method_id TEXT NOT NULL DEFAULT '',
    granted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (group_id, scope)
);

CREATE INDEX idx_group_scopes_scope ON group_scopes (scope);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_user_scopes_scope;
DROP INDEX IF EXISTS idx_group_scopes_scope;
DROP TABLE IF EXISTS user_scopes;
DROP TABLE IF EXISTS group_scopes;
-- +goose StatementEnd
