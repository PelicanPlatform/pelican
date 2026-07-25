-- +goose Up
-- +goose StatementBegin

-- Holds the registry's two-tier PKI material for acting as a certificate
-- authority (WS3, "reduce origin requirements"). A single self-signed
-- federation root anchors trust; a registry intermediate signed by the root is
-- the working key used to sign host certificates for approved services. Exactly
-- one row per role (enforced by the UNIQUE constraint on `role`).
--
-- The CA private keys are encrypted at rest: encrypted_key holds
-- nonce||AES-256-GCM(ciphertext) under a CA-specific sub-key derived from the
-- server master key (HKDF purpose "pelican-registry-ca-key"), the same
-- master-key facility used elsewhere (see universal migration
-- server_master_keys and database/master_key.go). cert_pem is public and stored
-- in the clear.
CREATE TABLE IF NOT EXISTS certificate_authorities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  role TEXT NOT NULL UNIQUE,           -- 'root' | 'intermediate'
  cert_pem TEXT NOT NULL,              -- PEM-encoded certificate (public)
  encrypted_key BLOB NOT NULL,         -- nonce || AES-256-GCM(PKCS#8 private key PEM)
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  not_after DATETIME                   -- certificate expiry, for renewal scheduling
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS certificate_authorities;
-- +goose StatementEnd
