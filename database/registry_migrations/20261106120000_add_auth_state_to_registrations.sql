-- +goose Up
-- +goose StatementBegin

-- A namespace registration may carry the auth state (token issuers with base
-- and restricted paths, token-generation hints, capabilities), so the registry
-- can serve them to a Director while no origin for the namespace is online.
-- NULL means the namespace is advertised only while an origin serving it is
-- online: that is what every row created before this column did, and what a
-- row that never sets an auth state still does. The size cap mirrors the
-- registry's own validation; the API rejects larger blobs with 400 before they
-- reach this constraint.
ALTER TABLE registrations ADD COLUMN auth_state TEXT DEFAULT NULL
  CHECK (auth_state IS NULL OR length(auth_state) <= 8192);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE registrations DROP COLUMN auth_state;
-- +goose StatementEnd
