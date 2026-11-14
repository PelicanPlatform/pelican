-- +goose Up
-- +goose StatementBegin

-- A namespace registration may carry the auth state (token issuers with base
-- and restricted paths, token-generation hints, capabilities), so director
-- can send them to Director when the origin is offline. NULL means "not
-- advertised independently of origins", which keeps today's behavior for every
-- existing row. The size cap mirrors the registry's own validation; the API
-- rejects larger blobs with 400 before they reach this constraint.
ALTER TABLE registrations ADD COLUMN auth_state TEXT DEFAULT NULL
  CHECK (auth_state IS NULL OR length(auth_state) <= 8192);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE registrations DROP COLUMN auth_state;
-- +goose StatementEnd
