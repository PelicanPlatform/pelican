-- +goose Up
-- +goose StatementBegin

-- Rename the management scope `server.web_admin` → `server.admin`. The
-- new name better matches what the scope actually grants (full-server
-- admin authority, not "admin of the web UI"); the old name leaked the
-- internal "web admin" framing into the wire vocabulary that operators
-- and audit logs see.
--
-- Both user_scopes and group_scopes carry scope strings keyed by their
-- (target, scope) primary key. Rename in place. Operators with a
-- pre-rename DB will see no behavior change — `Server_Admin` in the
-- regenerated token_scopes package resolves to the new value, and the
-- runtime evaluator (EffectiveScopes / EffectiveScopesForIdentity)
-- only ever compares against `Server_Admin`, so the migrated row is
-- the only one that ever matches.
--
-- The PRIMARY KEY constraint (target, scope) is the only thing that
-- could conflict — a row already at `server.admin` (manually inserted
-- by an operator before the rename, perhaps as an experiment) would
-- collide with the renamed row. Use INSERT OR IGNORE-pattern via a
-- DELETE-of-loser to keep the migration idempotent without merging
-- audit fields (`granted_by`, `auth_method*`, `granted_at`); we keep
-- whichever row was already at the new name and drop the legacy one,
-- since the legacy row would be unreachable after the rename anyway.

DELETE FROM user_scopes
 WHERE scope = 'server.web_admin'
   AND user_id IN (SELECT user_id FROM user_scopes WHERE scope = 'server.admin');

UPDATE user_scopes SET scope = 'server.admin' WHERE scope = 'server.web_admin';

DELETE FROM group_scopes
 WHERE scope = 'server.web_admin'
   AND group_id IN (SELECT group_id FROM group_scopes WHERE scope = 'server.admin');

UPDATE group_scopes SET scope = 'server.admin' WHERE scope = 'server.web_admin';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Inverse of the Up rename. Same collision-handling shape — if a row
-- already carries the legacy name (e.g. produced by a mid-flight
-- operator who picked it up before the migration ran), keep it and
-- drop the new-name copy.

DELETE FROM user_scopes
 WHERE scope = 'server.admin'
   AND user_id IN (SELECT user_id FROM user_scopes WHERE scope = 'server.web_admin');

UPDATE user_scopes SET scope = 'server.web_admin' WHERE scope = 'server.admin';

DELETE FROM group_scopes
 WHERE scope = 'server.admin'
   AND group_id IN (SELECT group_id FROM group_scopes WHERE scope = 'server.web_admin');

UPDATE group_scopes SET scope = 'server.web_admin' WHERE scope = 'server.admin';

-- +goose StatementEnd
