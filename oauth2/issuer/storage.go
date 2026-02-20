/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

// Package issuer provides an embedded OAuth2/OIDC token issuer using the
// fosite framework.
// It stores all data in the existing Pelican SQLite database via GORM
// and reuses the Pelican authentication framework.
package issuer

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/ory/fosite"
	"gorm.io/gorm"
)

// validTableNames is the whitelist of allowed table names for token session CRUD.
var validTableNames = map[string]bool{
	"oidc_access_tokens":       true,
	"oidc_refresh_tokens":      true,
	"oidc_authorization_codes": true,
	"oidc_openid_sessions":     true,
	"oidc_pkce_requests":       true,
}

// OIDCStorage implements all fosite storage interfaces using the shared Pelican
// SQLite database accessed through GORM.
type OIDCStorage struct {
	db *gorm.DB

	// RefreshTokenGracePeriod controls how long a used refresh token remains
	// valid for reuse after first being exchanged.
	// Default: 5 minutes.
	RefreshTokenGracePeriod time.Duration
}

// NewOIDCStorage creates a new OIDC storage backed by the existing GORM database.
func NewOIDCStorage(db *gorm.DB) *OIDCStorage {
	return &OIDCStorage{
		db:                      db,
		RefreshTokenGracePeriod: 5 * time.Minute,
	}
}

// ---- fosite.ClientManager ----

// GetClient retrieves a client by ID.
func (s *OIDCStorage) GetClient(_ context.Context, clientID string) (fosite.Client, error) {
	var (
		secret        string
		redirectURIs  string
		grantTypes    string
		responseTypes string
		scopes        string
		public        int
	)

	result := s.db.Raw(`
		SELECT client_secret, redirect_uris, grant_types, response_types, scopes, public
		FROM oidc_clients WHERE id = ?
	`, clientID).Row()

	err := result.Scan(&secret, &redirectURIs, &grantTypes, &responseTypes, &scopes, &public)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	client := &fosite.DefaultClient{
		ID:     clientID,
		Secret: []byte(secret),
		Public: public == 1,
		// All clients in this WLCG-compliant issuer accept the wildcard
		// audience so that tokens can be presented to any service.
		Audience: fosite.Arguments{WLCGAudienceAny},
	}

	if err := json.Unmarshal([]byte(redirectURIs), &client.RedirectURIs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal redirect_uris: %w", err)
	}
	if err := json.Unmarshal([]byte(grantTypes), &client.GrantTypes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal grant_types: %w", err)
	}
	if err := json.Unmarshal([]byte(responseTypes), &client.ResponseTypes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response_types: %w", err)
	}
	if err := json.Unmarshal([]byte(scopes), &client.Scopes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal scopes: %w", err)
	}

	return client, nil
}

// CreateClient stores a new OAuth2 client.
func (s *OIDCStorage) CreateClient(ctx context.Context, client *fosite.DefaultClient) error {
	redirectURIs, _ := json.Marshal(client.RedirectURIs)
	grantTypes, _ := json.Marshal(client.GrantTypes)
	responseTypes, _ := json.Marshal(client.ResponseTypes)
	scopes, _ := json.Marshal(client.Scopes)

	public := 0
	if client.Public {
		public = 1
	}

	return s.db.WithContext(ctx).Exec(`
		INSERT OR REPLACE INTO oidc_clients (id, client_secret, redirect_uris, grant_types, response_types, scopes, public)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, client.ID, string(client.Secret), string(redirectURIs), string(grantTypes),
		string(responseTypes), string(scopes), public).Error
}

// CreateDynamicClient stores a new dynamically registered OAuth2 client.
// Unlike CreateClient, it records the registration as dynamic and stores the
// registrant's IP address for audit and rate-limiting purposes.
func (s *OIDCStorage) CreateDynamicClient(ctx context.Context, client *fosite.DefaultClient, registrationIP string) error {
	redirectURIs, _ := json.Marshal(client.RedirectURIs)
	grantTypes, _ := json.Marshal(client.GrantTypes)
	responseTypes, _ := json.Marshal(client.ResponseTypes)
	scopes, _ := json.Marshal(client.Scopes)

	public := 0
	if client.Public {
		public = 1
	}

	return s.db.WithContext(ctx).Exec(`
		INSERT INTO oidc_clients
			(id, client_secret, redirect_uris, grant_types, response_types, scopes, public,
			 dynamically_registered, registration_ip)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
	`, client.ID, string(client.Secret), string(redirectURIs), string(grantTypes),
		string(responseTypes), string(scopes), public, registrationIP).Error
}

// IsDynamicallyRegistered returns whether the given client was created via
// dynamic client registration (RFC 7591).
func (s *OIDCStorage) IsDynamicallyRegistered(_ context.Context, clientID string) (bool, error) {
	var dynReg int
	row := s.db.Raw(`SELECT dynamically_registered FROM oidc_clients WHERE id = ?`, clientID).Row()
	err := row.Scan(&dynReg)
	if errors.Is(err, sql.ErrNoRows) {
		return false, fosite.ErrNotFound
	}
	if err != nil {
		return false, err
	}
	return dynReg == 1, nil
}

// GetBoundUser returns the user bound to a dynamically registered client.
// Returns "" if no user is bound yet.
func (s *OIDCStorage) GetBoundUser(_ context.Context, clientID string) (string, error) {
	var boundUser string
	row := s.db.Raw(`SELECT bound_user FROM oidc_clients WHERE id = ?`, clientID).Row()
	err := row.Scan(&boundUser)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fosite.ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return boundUser, nil
}

// BindClientToUser atomically binds a dynamically registered client to the
// given user.  If the client is already bound to a different user, returns
// an error.  If already bound to the same user, this is a no-op.
func (s *OIDCStorage) BindClientToUser(ctx context.Context, clientID, user string) error {
	// Attempt the bind — only succeeds when bound_user is still empty.
	result := s.db.WithContext(ctx).Exec(`
		UPDATE oidc_clients SET bound_user = ?
		WHERE id = ? AND dynamically_registered = 1 AND bound_user = ''
	`, user, clientID)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 1 {
		return nil // successfully bound
	}

	// 0 rows affected — either already bound (maybe to us) or not dynamic.
	existing, err := s.GetBoundUser(ctx, clientID)
	if err != nil {
		return err
	}
	if existing == user {
		return nil // already bound to this user
	}
	return fmt.Errorf("client %s is already bound to a different user", clientID)
}

// TouchClientLastUsed updates the last_used_at timestamp for a client.
func (s *OIDCStorage) TouchClientLastUsed(ctx context.Context, clientID string) error {
	return s.db.WithContext(ctx).Exec(
		`UPDATE oidc_clients SET last_used_at = ? WHERE id = ?`,
		time.Now().UTC(), clientID,
	).Error
}

// DeleteUnusedDynamicClients removes dynamically registered clients that have
// never been used (last_used_at IS NULL) and were created more than maxAge ago.
func (s *OIDCStorage) DeleteUnusedDynamicClients(ctx context.Context, maxAge time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-maxAge)
	result := s.db.WithContext(ctx).Exec(`
		DELETE FROM oidc_clients
		WHERE dynamically_registered = 1
		  AND last_used_at IS NULL
		  AND created_at < ?
	`, cutoff)
	return result.RowsAffected, result.Error
}

// DeleteStaleDynamicClients removes dynamically registered clients that were
// previously used but have not been used for longer than maxAge.
func (s *OIDCStorage) DeleteStaleDynamicClients(ctx context.Context, maxAge time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-maxAge)
	result := s.db.WithContext(ctx).Exec(`
		DELETE FROM oidc_clients
		WHERE dynamically_registered = 1
		  AND last_used_at IS NOT NULL
		  AND last_used_at < ?
	`, cutoff)
	return result.RowsAffected, result.Error
}

// DeleteExpiredTokenSessions removes expired rows from all token/session tables
// (access tokens, refresh tokens, authorization codes, PKCE requests, OpenID
// sessions). Returns the total number of rows deleted.
func (s *OIDCStorage) DeleteExpiredTokenSessions(ctx context.Context) (int64, error) {
	now := time.Now().UTC()
	tables := []string{
		"oidc_access_tokens",
		"oidc_authorization_codes",
		"oidc_pkce_requests",
		"oidc_openid_sessions",
	}
	var total int64
	for _, table := range tables {
		result := s.db.WithContext(ctx).Exec(
			`DELETE FROM `+table+` WHERE expires_at < ?`, now,
		)
		if result.Error != nil {
			return total, result.Error
		}
		total += result.RowsAffected
	}
	// Refresh tokens: expires_at may be NULL (never-expire), so only delete
	// rows where expires_at is set and in the past, or where the token has
	// been revoked (active=0) and its grace period is long past.
	result := s.db.WithContext(ctx).Exec(
		`DELETE FROM oidc_refresh_tokens WHERE (expires_at IS NOT NULL AND expires_at < ?) OR (active = 0 AND first_used_at IS NOT NULL AND first_used_at < ?)`,
		now, now.Add(-24*time.Hour),
	)
	if result.Error != nil {
		return total, result.Error
	}
	total += result.RowsAffected
	return total, nil
}

// DeleteExpiredDeviceCodes removes device codes that have expired or have been
// consumed (status = 'used'). Returns the number of rows deleted.
func (s *OIDCStorage) DeleteExpiredDeviceCodes(ctx context.Context) (int64, error) {
	now := time.Now().UTC()
	result := s.db.WithContext(ctx).Exec(
		`DELETE FROM oidc_device_codes WHERE expires_at < ? OR status = 'used'`, now,
	)
	return result.RowsAffected, result.Error
}

// DeleteExpiredJWTAssertions removes JWT assertion replay-prevention entries
// whose expiry has passed. Returns the number of rows deleted.
func (s *OIDCStorage) DeleteExpiredJWTAssertions(ctx context.Context) (int64, error) {
	now := time.Now().UTC()
	result := s.db.WithContext(ctx).Exec(
		`DELETE FROM oidc_jwt_assertions WHERE expires_at < ?`, now,
	)
	return result.RowsAffected, result.Error
}

// ---- fosite.AccessTokenStorage ----

func (s *OIDCStorage) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createTokenSession(ctx, "oidc_access_tokens", signature, request)
}

func (s *OIDCStorage) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getTokenSession(ctx, "oidc_access_tokens", signature, session)
}

func (s *OIDCStorage) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.deleteTokenSession(ctx, "oidc_access_tokens", signature)
}

// ---- fosite.RefreshTokenStorage ----

func (s *OIDCStorage) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, request fosite.Requester) error {
	return s.createTokenSession(ctx, "oidc_refresh_tokens", signature, request)
}

func (s *OIDCStorage) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getRefreshTokenSession(ctx, signature, session)
}

func (s *OIDCStorage) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.deleteTokenSession(ctx, "oidc_refresh_tokens", signature)
}

// RotateRefreshToken is called when a refresh token is being rotated.
// It marks the old token with first_used_at for grace period tracking rather
// than immediately revoking it, allowing brief reuse during network issues.
func (s *OIDCStorage) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	return s.db.WithContext(ctx).Exec(
		`UPDATE oidc_refresh_tokens SET first_used_at = COALESCE(first_used_at, ?) WHERE request_id = ? AND active = 1`,
		time.Now().UTC(), requestID,
	).Error
}

// ---- fosite.AuthorizeCodeStorage ----

func (s *OIDCStorage) CreateAuthorizeCodeSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createTokenSession(ctx, "oidc_authorization_codes", signature, request)
}

func (s *OIDCStorage) GetAuthorizeCodeSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getTokenSession(ctx, "oidc_authorization_codes", signature, session)
}

func (s *OIDCStorage) InvalidateAuthorizeCodeSession(ctx context.Context, signature string) error {
	return s.db.WithContext(ctx).Exec(
		`UPDATE oidc_authorization_codes SET active = 0 WHERE signature = ?`, signature,
	).Error
}

// ---- fosite.PKCERequestStorage ----

func (s *OIDCStorage) CreatePKCERequestSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createTokenSession(ctx, "oidc_pkce_requests", signature, request)
}

func (s *OIDCStorage) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getTokenSession(ctx, "oidc_pkce_requests", signature, session)
}

func (s *OIDCStorage) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return s.deleteTokenSession(ctx, "oidc_pkce_requests", signature)
}

// ---- openid.OpenIDConnectRequestStorage ----

func (s *OIDCStorage) CreateOpenIDConnectSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createTokenSession(ctx, "oidc_openid_sessions", signature, request)
}

func (s *OIDCStorage) GetOpenIDConnectSession(ctx context.Context, signature string, session fosite.Requester) (fosite.Requester, error) {
	return s.getTokenSession(ctx, "oidc_openid_sessions", signature, session.GetSession())
}

func (s *OIDCStorage) DeleteOpenIDConnectSession(ctx context.Context, signature string) error {
	return s.deleteTokenSession(ctx, "oidc_openid_sessions", signature)
}

// ---- fosite.TokenRevocationStorage ----

func (s *OIDCStorage) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return s.db.WithContext(ctx).Exec(
		`UPDATE oidc_refresh_tokens SET active = 0 WHERE request_id = ?`, requestID,
	).Error
}

func (s *OIDCStorage) RevokeAccessToken(ctx context.Context, requestID string) error {
	return s.db.WithContext(ctx).Exec(
		`UPDATE oidc_access_tokens SET active = 0 WHERE request_id = ?`, requestID,
	).Error
}

func (s *OIDCStorage) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, requestID string, _ string) error {
	// Mark with first_used_at instead of immediately revoking, enabling re-use
	// within the configured grace period.
	return s.db.WithContext(ctx).Exec(
		`UPDATE oidc_refresh_tokens SET first_used_at = COALESCE(first_used_at, ?) WHERE request_id = ? AND active = 1`,
		time.Now().UTC(), requestID,
	).Error
}

// ---- fosite.ClientAssertionJWTValid / SetClientAssertionJWT ----

func (s *OIDCStorage) ClientAssertionJWTValid(_ context.Context, jti string) error {
	var expiresAt time.Time
	row := s.db.Raw(`SELECT expires_at FROM oidc_jwt_assertions WHERE jti = ?`, jti).Row()
	err := row.Scan(&expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // JTI not seen before → valid
	}
	if err != nil {
		return err
	}
	if time.Now().After(expiresAt) {
		return nil // Expired entry → valid
	}
	return fosite.ErrJTIKnown
}

func (s *OIDCStorage) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return s.db.WithContext(ctx).Exec(
		`INSERT OR REPLACE INTO oidc_jwt_assertions (jti, expires_at) VALUES (?, ?)`,
		jti, exp,
	).Error
}

// ---- Device Code Flow ----

func (s *OIDCStorage) CreateDeviceCodeSession(ctx context.Context, deviceCode, userCode string,
	request fosite.Requester, expiresAt time.Time) error {

	scopes, _ := json.Marshal(request.GetRequestedScopes())
	grantedScopes, _ := json.Marshal(request.GetGrantedScopes())
	formData, _ := json.Marshal(request.GetRequestForm())
	sessionData, _ := json.Marshal(request.GetSession())

	subject := ""
	if request.GetSession() != nil {
		subject = request.GetSession().GetSubject()
	}

	return s.db.WithContext(ctx).Exec(`
		INSERT INTO oidc_device_codes
			(device_code, user_code, request_id, requested_at, client_id, scopes,
			 granted_scopes, form_data, session_data, subject, status, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
	`, deviceCode, userCode, request.GetID(), request.GetRequestedAt(),
		request.GetClient().GetID(), string(scopes), string(grantedScopes),
		string(formData), string(sessionData),
		subject, expiresAt).Error
}

// DeviceCodeSession holds the scanned columns from oidc_device_codes.
type DeviceCodeSession struct {
	RequestID    string
	RequestedAt  time.Time
	ClientID     string
	Scopes       string
	GrantedScope string
	FormData     string
	SessionData  string
	Subject      string
	Status       string
	ExpiresAt    time.Time
}

var (
	// ErrAuthorizationPending is returned when the device code has not yet been approved.
	ErrAuthorizationPending = &fosite.RFC6749Error{
		ErrorField:       "authorization_pending",
		DescriptionField: "The authorization request is still pending",
		CodeField:        http.StatusBadRequest,
	}
	// ErrSlowDown is returned when the client is polling too quickly.
	ErrSlowDown = &fosite.RFC6749Error{
		ErrorField:       "slow_down",
		DescriptionField: "Client is polling too frequently",
		CodeField:        http.StatusBadRequest,
	}
	// ErrExpiredToken is returned when the device code has expired.
	ErrExpiredToken = &fosite.RFC6749Error{
		ErrorField:       "expired_token",
		DescriptionField: "The device code has expired",
		CodeField:        http.StatusBadRequest,
	}
)

func (s *OIDCStorage) GetDeviceCodeSession(ctx context.Context, deviceCode string, session fosite.Session) (fosite.Requester, error) {
	var dc DeviceCodeSession
	var lastPolledAt sql.NullTime
	row := s.db.WithContext(ctx).Raw(`
		SELECT request_id, requested_at, client_id, scopes, granted_scopes,
			   form_data, session_data, subject, status, expires_at, last_polled_at
		FROM oidc_device_codes WHERE device_code = ?
	`, deviceCode).Row()

	err := row.Scan(&dc.RequestID, &dc.RequestedAt, &dc.ClientID,
		&dc.Scopes, &dc.GrantedScope, &dc.FormData, &dc.SessionData,
		&dc.Subject, &dc.Status, &dc.ExpiresAt, &lastPolledAt)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if time.Now().After(dc.ExpiresAt) {
		return nil, ErrExpiredToken
	}

	// RFC 8628 §3.5: enforce minimum polling interval (5 seconds).
	// Check before examining status so slow_down applies even while pending.
	const pollingInterval = 5 * time.Second
	if lastPolledAt.Valid && time.Since(lastPolledAt.Time) < pollingInterval {
		// Update last_polled_at even on slow_down so the next interval
		// is measured from this attempt (RFC 8628 recommends adding 5s).
		_ = s.UpdateDeviceCodePolling(ctx, deviceCode)
		return nil, ErrSlowDown
	}
	_ = s.UpdateDeviceCodePolling(ctx, deviceCode)

	switch dc.Status {
	case "pending":
		return nil, ErrAuthorizationPending
	case "denied":
		return nil, fosite.ErrAccessDenied
	case "used":
		return nil, fosite.ErrInvalidGrant
	case "approved":
		// continue
	default:
		return nil, fmt.Errorf("unknown device code status: %s", dc.Status)
	}

	return s.scanToRequest(ctx, dc.RequestID, dc.RequestedAt, dc.ClientID,
		dc.Scopes, dc.GrantedScope, "", dc.FormData, dc.SessionData, dc.Subject, session)
}

func (s *OIDCStorage) GetDeviceCodeSessionByUserCode(ctx context.Context, userCode string) (*DeviceCodeSession, error) {
	var dc DeviceCodeSession
	row := s.db.WithContext(ctx).Raw(`
		SELECT request_id, requested_at, client_id, scopes, granted_scopes,
			   form_data, session_data, subject, status, expires_at
		FROM oidc_device_codes WHERE user_code = ?
	`, userCode).Row()

	err := row.Scan(&dc.RequestID, &dc.RequestedAt, &dc.ClientID,
		&dc.Scopes, &dc.GrantedScope, &dc.FormData, &dc.SessionData,
		&dc.Subject, &dc.Status, &dc.ExpiresAt)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &dc, nil
}

func (s *OIDCStorage) ApproveDeviceCodeSession(ctx context.Context, userCode, subject string, grantedScopes []string, sessionData []byte) error {
	gs, _ := json.Marshal(grantedScopes)
	return s.db.WithContext(ctx).Exec(`
		UPDATE oidc_device_codes
		SET status = 'approved', subject = ?, granted_scopes = ?, session_data = ?
		WHERE user_code = ? AND status = 'pending'
	`, subject, string(gs), string(sessionData), userCode).Error
}

func (s *OIDCStorage) DenyDeviceCodeSession(ctx context.Context, userCode string) error {
	return s.db.WithContext(ctx).Exec(
		`UPDATE oidc_device_codes SET status = 'denied' WHERE user_code = ? AND status = 'pending'`,
		userCode,
	).Error
}

func (s *OIDCStorage) InvalidateDeviceCodeSession(ctx context.Context, deviceCode string) error {
	return s.db.WithContext(ctx).Exec(
		`UPDATE oidc_device_codes SET status = 'used' WHERE device_code = ?`, deviceCode,
	).Error
}

func (s *OIDCStorage) UpdateDeviceCodePolling(ctx context.Context, deviceCode string) error {
	return s.db.WithContext(ctx).Exec(
		`UPDATE oidc_device_codes SET last_polled_at = ? WHERE device_code = ?`,
		time.Now().UTC(), deviceCode,
	).Error
}

// ---- Internal helpers ----

func buildInsertQuery(table string) (string, error) {
	if !validTableNames[table] {
		return "", fmt.Errorf("invalid table name: %s", table)
	}
	return `INSERT INTO ` + table + ` (signature, request_id, requested_at, client_id,
		scopes, granted_scopes, granted_audience, form_data, session_data, subject, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, nil
}

func buildSelectQuery(table string) (string, error) {
	if !validTableNames[table] {
		return "", fmt.Errorf("invalid table name: %s", table)
	}
	return `SELECT request_id, requested_at, client_id, scopes, granted_scopes,
		granted_audience, form_data, session_data, subject, active
		FROM ` + table + ` WHERE signature = ?`, nil
}

func buildDeleteQuery(table string) (string, error) {
	if !validTableNames[table] {
		return "", fmt.Errorf("invalid table name: %s", table)
	}
	return `DELETE FROM ` + table + ` WHERE signature = ?`, nil
}

func (s *OIDCStorage) createTokenSession(ctx context.Context, table, signature string, request fosite.Requester) error {
	scopes, _ := json.Marshal(request.GetRequestedScopes())
	grantedScopes, _ := json.Marshal(request.GetGrantedScopes())
	grantedAudience, _ := json.Marshal(request.GetGrantedAudience())
	formData, _ := json.Marshal(request.GetRequestForm())
	sessionData, _ := json.Marshal(request.GetSession())

	expiresAt := time.Now().Add(1 * time.Hour) // Default expiration

	query, err := buildInsertQuery(table)
	if err != nil {
		return err
	}

	return s.db.WithContext(ctx).Exec(query,
		signature,
		request.GetID(),
		request.GetRequestedAt(),
		request.GetClient().GetID(),
		string(scopes),
		string(grantedScopes),
		string(grantedAudience),
		string(formData),
		string(sessionData),
		request.GetSession().GetSubject(),
		expiresAt,
	).Error
}

func (s *OIDCStorage) getTokenSession(ctx context.Context, table, signature string, session fosite.Session) (fosite.Requester, error) {
	var (
		requestID       string
		requestedAt     time.Time
		clientID        string
		scopes          string
		grantedScopes   string
		grantedAudience string
		formData        string
		sessionData     string
		subject         string
		active          int
	)

	query, err := buildSelectQuery(table)
	if err != nil {
		return nil, err
	}

	row := s.db.WithContext(ctx).Raw(query, signature).Row()
	err = row.Scan(&requestID, &requestedAt, &clientID, &scopes, &grantedScopes,
		&grantedAudience, &formData, &sessionData, &subject, &active)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if active == 0 {
		return nil, fosite.ErrInactiveToken
	}

	return s.scanToRequest(ctx, requestID, requestedAt, clientID,
		scopes, grantedScopes, grantedAudience, formData, sessionData, subject, session)
}

// getRefreshTokenSession is like getTokenSession but implements the grace period
// for refresh token reuse.
func (s *OIDCStorage) getRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	var (
		requestID       string
		requestedAt     time.Time
		clientID        string
		scopes          string
		grantedScopes   string
		grantedAudience string
		formData        string
		sessionData     string
		subject         string
		active          int
		firstUsedAt     sql.NullTime
	)

	row := s.db.WithContext(ctx).Raw(`
		SELECT request_id, requested_at, client_id, scopes, granted_scopes,
			granted_audience, form_data, session_data, subject, active, first_used_at
		FROM oidc_refresh_tokens WHERE signature = ?
	`, signature).Row()

	err := row.Scan(&requestID, &requestedAt, &clientID, &scopes, &grantedScopes,
		&grantedAudience, &formData, &sessionData, &subject, &active, &firstUsedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	// Build the request first — fosite's handleRefreshTokenReuse expects a
	// non-nil request even when we return ErrInactiveToken, so it can use the
	// request ID to revoke all associated tokens.
	req, err := s.scanToRequest(ctx, requestID, requestedAt, clientID,
		scopes, grantedScopes, grantedAudience, formData, sessionData, subject, session)
	if err != nil {
		return nil, err
	}

	if active == 0 {
		return req, fosite.ErrInactiveToken
	}

	// If the token has been used before, check the grace period
	if firstUsedAt.Valid {
		if time.Since(firstUsedAt.Time) > s.RefreshTokenGracePeriod {
			return req, fosite.ErrInactiveToken
		}
	}

	return req, nil
}

func (s *OIDCStorage) deleteTokenSession(ctx context.Context, table, signature string) error {
	query, err := buildDeleteQuery(table)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Exec(query, signature).Error
}

func (s *OIDCStorage) scanToRequest(ctx context.Context,
	requestID string, requestedAt time.Time, clientID string,
	scopesJSON, grantedScopesJSON, grantedAudienceJSON, formDataJSON, sessionDataJSON, subject string,
	session fosite.Session) (fosite.Requester, error) {

	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	request := fosite.NewRequest()
	request.ID = requestID
	request.RequestedAt = requestedAt
	request.Client = client

	var scopesList []string
	if err := json.Unmarshal([]byte(scopesJSON), &scopesList); err != nil {
		return nil, fmt.Errorf("failed to unmarshal scopes: %w", err)
	}
	request.RequestedScope = scopesList

	var grantedScopesList []string
	if err := json.Unmarshal([]byte(grantedScopesJSON), &grantedScopesList); err != nil {
		return nil, fmt.Errorf("failed to unmarshal granted scopes: %w", err)
	}
	request.GrantedScope = grantedScopesList

	if grantedAudienceJSON != "" {
		var grantedAudienceList []string
		if err := json.Unmarshal([]byte(grantedAudienceJSON), &grantedAudienceList); err != nil {
			return nil, fmt.Errorf("failed to unmarshal granted audience: %w", err)
		}
		request.GrantedAudience = grantedAudienceList
	}

	var form url.Values
	if err := json.Unmarshal([]byte(formDataJSON), &form); err != nil {
		return nil, fmt.Errorf("failed to unmarshal form data: %w", err)
	}
	request.Form = form

	if session != nil {
		if err := json.Unmarshal([]byte(sessionDataJSON), session); err != nil {
			return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
		}
		// Ensure the session carries the canonical subject from the DB row.
		// The session_data JSON may not always contain an up-to-date subject
		// (e.g. device code approval writes subject separately).
		if subject != "" {
			switch s := session.(type) {
			case *WLCGSession:
				s.Subject = subject
				if s.JWTClaims != nil {
					s.JWTClaims.Subject = subject
				}
				if s.IDTokenClaimsField != nil {
					s.IDTokenClaimsField.Subject = subject
				}
			case *fosite.DefaultSession:
				s.Subject = subject
			}
		}
		request.Session = session
	}

	return request, nil
}
