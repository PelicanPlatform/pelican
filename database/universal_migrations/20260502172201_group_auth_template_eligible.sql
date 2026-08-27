-- +goose Up
-- +goose StatementBegin

-- Add an admin-controlled flag to every group that gates whether it
-- can match Issuer.AuthorizationTemplates / Server.*AdminGroups
-- entries (i.e. whether it's "trusted" by the authz pipeline).
--
-- Background. Group creation is being opened to all authenticated
-- users so they can mint groups for their own collection ACLs and
-- shares. But a non-admin who can create a group can also pick its
-- name — which is dangerous when authz templates use the group name
-- as a path component (e.g. `Prefix: /projects/$GROUP`) or when
-- Server.AdminGroups names a group whose row hasn't been created
-- yet. A user creating a group named "alpha" or "sysadmins" must NOT
-- thereby gain access to /projects/alpha or admin authority.
--
-- The fix: every group has an `auth_template_eligible` bit. Only an
-- admin / user-admin can set it (at create or via PATCH). The runtime
-- consumers (oa4mp.CalculateAllowedScopes,
-- web_ui.EffectiveScopesForIdentity's AdminGroups matcher) filter
-- the user's group list against this column before deciding.
--
-- Pre-existing groups predate the user-driven create path, so they
-- were minted by an admin and should keep matching templates as
-- before. The column default is therefore TRUE on the schema and we
-- explicitly UPDATE every existing row to TRUE here for clarity —
-- the SQLite default-on-add behavior is to backfill with the column
-- default, but stating it inline keeps the intent obvious to anyone
-- reading the migration history.

ALTER TABLE groups
  ADD COLUMN auth_template_eligible INTEGER NOT NULL DEFAULT 1;

-- Defensive backfill: should be a no-op given the DEFAULT 1, but
-- runs cleanly under SQLite and removes any ambiguity about what
-- pre-existing rows hold after the migration.
UPDATE groups SET auth_template_eligible = 1;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE groups DROP COLUMN auth_template_eligible;

-- +goose StatementEnd
