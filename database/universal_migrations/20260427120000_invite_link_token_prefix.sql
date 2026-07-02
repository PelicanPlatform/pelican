-- +goose Up
-- +goose StatementBegin

-- Add a public, non-secret short identifier for invite links so admins
-- can distinguish multiple outstanding links without ever pasting the
-- full token (which is a credential — possession of it lets the
-- holder set a password or join a group).
--
-- token_prefix stores the first 6 characters of the plaintext token,
-- captured at mint time. 6 hex chars is 24 bits — too narrow to brute
-- force into a useful credential against the bcrypt-hashed full token,
-- but more than enough to label, sort, and reason about live invites
-- in CLI output, the admin UI, and audit logs.
--
-- NOT NULL DEFAULT '' so existing rows pre-migration have an empty
-- prefix; new mints fill it in. The column is non-unique because
-- prefix collisions are possible (and harmless).

ALTER TABLE group_invite_links
    ADD COLUMN token_prefix TEXT NOT NULL DEFAULT '';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- SQLite does not support DROP COLUMN cleanly; the down migration is a no-op.
-- +goose StatementEnd
