-- +goose Up
-- +goose StatementBegin

-- Per the user/group design contract: each user may have at most one
-- linked identity per issuer. The existing UNIQUE(sub, issuer) index
-- already prevents two *users* from sharing the same OIDC identity.
-- This index covers the orthogonal invariant: prevent the same user
-- from accumulating multiple identities at the same issuer (which
-- would let an attacker who compromised any one of those subs
-- impersonate the user).
--
-- Note: the cross-table guarantee (no UserIdentity row may collide with
-- the same user's *primary* identity on User.{sub, issuer}) is enforced
-- in CreateUserIdentity, since SQLite has no native cross-table check.
CREATE UNIQUE INDEX idx_user_identities_user_issuer
    ON user_identities (user_id, issuer);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_user_identities_user_issuer;
-- +goose StatementEnd
