-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS oidc_clients (
    id TEXT PRIMARY KEY,
    client_secret TEXT NOT NULL,
    redirect_uris TEXT NOT NULL DEFAULT '[]',
    grant_types TEXT NOT NULL DEFAULT '[]',
    response_types TEXT NOT NULL DEFAULT '[]',
    scopes TEXT NOT NULL DEFAULT '[]',
    public INTEGER NOT NULL DEFAULT 0,
    dynamically_registered INTEGER NOT NULL DEFAULT 0,
    bound_user TEXT NOT NULL DEFAULT '',
    last_used_at DATETIME,
    registration_ip TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oidc_access_tokens (
    signature TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    requested_at DATETIME NOT NULL,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]',
    granted_scopes TEXT NOT NULL DEFAULT '[]',
    granted_audience TEXT NOT NULL DEFAULT '[]',
    form_data TEXT NOT NULL DEFAULT '{}',
    session_data TEXT NOT NULL DEFAULT '{}',
    subject TEXT NOT NULL DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oidc_refresh_tokens (
    signature TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    requested_at DATETIME NOT NULL,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]',
    granted_scopes TEXT NOT NULL DEFAULT '[]',
    granted_audience TEXT NOT NULL DEFAULT '[]',
    form_data TEXT NOT NULL DEFAULT '{}',
    session_data TEXT NOT NULL DEFAULT '{}',
    subject TEXT NOT NULL DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1,
    first_used_at DATETIME,
    expires_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oidc_authorization_codes (
    signature TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    requested_at DATETIME NOT NULL,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]',
    granted_scopes TEXT NOT NULL DEFAULT '[]',
    granted_audience TEXT NOT NULL DEFAULT '[]',
    form_data TEXT NOT NULL DEFAULT '{}',
    session_data TEXT NOT NULL DEFAULT '{}',
    subject TEXT NOT NULL DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oidc_pkce_requests (
    signature TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    requested_at DATETIME NOT NULL,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]',
    granted_scopes TEXT NOT NULL DEFAULT '[]',
    granted_audience TEXT NOT NULL DEFAULT '[]',
    form_data TEXT NOT NULL DEFAULT '{}',
    session_data TEXT NOT NULL DEFAULT '{}',
    subject TEXT NOT NULL DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oidc_openid_sessions (
    signature TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    requested_at DATETIME NOT NULL,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]',
    granted_scopes TEXT NOT NULL DEFAULT '[]',
    granted_audience TEXT NOT NULL DEFAULT '[]',
    form_data TEXT NOT NULL DEFAULT '{}',
    session_data TEXT NOT NULL DEFAULT '{}',
    subject TEXT NOT NULL DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oidc_device_codes (
    device_code TEXT PRIMARY KEY,
    user_code TEXT NOT NULL UNIQUE,
    request_id TEXT NOT NULL,
    requested_at DATETIME NOT NULL,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]',
    granted_scopes TEXT NOT NULL DEFAULT '[]',
    form_data TEXT NOT NULL DEFAULT '{}',
    session_data TEXT NOT NULL DEFAULT '{}',
    subject TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'used')),
    expires_at DATETIME NOT NULL,
    last_polled_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oidc_jwt_assertions (
    jti TEXT PRIMARY KEY,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_oidc_access_tokens_client ON oidc_access_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_access_tokens_request ON oidc_access_tokens(request_id);
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_client ON oidc_refresh_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_request ON oidc_refresh_tokens(request_id);
CREATE INDEX IF NOT EXISTS idx_oidc_authorization_codes_client ON oidc_authorization_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_openid_sessions_client ON oidc_openid_sessions(client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_device_codes_user_code ON oidc_device_codes(user_code);
CREATE INDEX IF NOT EXISTS idx_oidc_device_codes_status ON oidc_device_codes(status);
CREATE INDEX IF NOT EXISTS idx_oidc_jwt_assertions_expires ON oidc_jwt_assertions(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_access_tokens_expires ON oidc_access_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_expires ON oidc_refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_authorization_codes_expires ON oidc_authorization_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_pkce_requests_expires ON oidc_pkce_requests(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_openid_sessions_expires ON oidc_openid_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_device_codes_expires ON oidc_device_codes(expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS oidc_clients;
DROP TABLE IF EXISTS oidc_access_tokens;
DROP TABLE IF EXISTS oidc_refresh_tokens;
DROP TABLE IF EXISTS oidc_authorization_codes;
DROP TABLE IF EXISTS oidc_pkce_requests;
DROP TABLE IF EXISTS oidc_openid_sessions;
DROP TABLE IF EXISTS oidc_device_codes;
DROP TABLE IF EXISTS oidc_jwt_assertions;
-- +goose StatementEnd
