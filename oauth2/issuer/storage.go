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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// validTableNames is the whitelist of allowed table names for token session CRUD
// helpers that accept a table name parameter.
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

	// Namespace is the federation prefix (e.g. "/data/analysis") that this
	// storage instance is scoped to. All client and token operations are
	// filtered to this namespace so that multiple issuers sharing the same
	// database stay isolated.
	Namespace string

	// RefreshTokenGracePeriod controls how long a used refresh token remains
	// valid for reuse after first being exchanged.
	// Default: 5 minutes.
	RefreshTokenGracePeriod time.Duration

	// touchDebounce tracks the last time each client's last_used_at was
	// flushed to disk, keyed by client ID → time.Time.
	// TouchClientLastUsed skips the SQL UPDATE if the previous write was
	// within TouchDebouncePeriod, avoiding write amplification on hot
	// token-exchange paths.
	touchDebounce sync.Map

	// TouchDebouncePeriod is the minimum interval between successive
	// last_used_at writes for the same client.  Default: 5 minutes.
	TouchDebouncePeriod time.Duration
}

// NewOIDCStorage creates a new OIDC storage scoped to the given namespace and
// backed by the existing GORM database.
func NewOIDCStorage(db *gorm.DB, namespace string) *OIDCStorage {
	return &OIDCStorage{
		db:                      db,
		Namespace:               namespace,
		RefreshTokenGracePeriod: 5 * time.Minute,
		TouchDebouncePeriod:     5 * time.Minute,
	}
}

// ---- fosite.ClientManager ----

// GetClient retrieves a client by ID.
func (s *OIDCStorage) GetClient(_ context.Context, clientID string) (fosite.Client, error) {
	var record OIDCClientRecord
	if err := s.db.First(&record, "id = ? AND namespace = ?", clientID, s.Namespace).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	client := &fosite.DefaultClient{
		ID:     record.ID,
		Secret: []byte(record.ClientSecret),
		Public: record.Public,
		// All clients in this WLCG-compliant issuer accept the wildcard
		// audience so that tokens can be presented to any service.
		Audience: fosite.Arguments{WLCGAudienceAny},
	}

	if err := json.Unmarshal([]byte(record.RedirectURIs), &client.RedirectURIs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal redirect_uris: %w", err)
	}
	if err := json.Unmarshal([]byte(record.GrantTypes), &client.GrantTypes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal grant_types: %w", err)
	}
	if err := json.Unmarshal([]byte(record.ResponseTypes), &client.ResponseTypes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response_types: %w", err)
	}
	if err := json.Unmarshal([]byte(record.Scopes), &client.Scopes); err != nil {
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

	record := OIDCClientRecord{
		ID:            client.ID,
		Namespace:     s.Namespace,
		ClientSecret:  string(client.Secret),
		RedirectURIs:  string(redirectURIs),
		GrantTypes:    string(grantTypes),
		ResponseTypes: string(responseTypes),
		Scopes:        string(scopes),
		Public:        client.Public,
	}

	// Client creation should fail on duplicate (id, namespace) so operators
	// must explicitly delete-and-recreate instead of silently overwriting.
	return s.db.WithContext(ctx).Create(&record).Error
}

// CreateDynamicClient stores a new dynamically registered OAuth2 client.
// Unlike CreateClient, it records the registration as dynamic, stores the
// registrant's IP address for audit and rate-limiting purposes, and stores
// a bcrypt-hashed registration access token (RFC 7592) for subsequent
// management requests.
func (s *OIDCStorage) CreateDynamicClient(ctx context.Context, client *fosite.DefaultClient, registrationIP string, hashedRAT []byte, clientName string) error {
	redirectURIs, _ := json.Marshal(client.RedirectURIs)
	grantTypes, _ := json.Marshal(client.GrantTypes)
	responseTypes, _ := json.Marshal(client.ResponseTypes)
	scopes, _ := json.Marshal(client.Scopes)

	record := OIDCClientRecord{
		ID:                      client.ID,
		Namespace:               s.Namespace,
		ClientSecret:            string(client.Secret),
		RedirectURIs:            string(redirectURIs),
		GrantTypes:              string(grantTypes),
		ResponseTypes:           string(responseTypes),
		Scopes:                  string(scopes),
		Public:                  client.Public,
		DynamicallyRegistered:   true,
		RegistrationIP:          registrationIP,
		RegistrationAccessToken: string(hashedRAT),
		ClientName:              clientName,
	}

	return s.db.WithContext(ctx).Create(&record).Error
}

// ValidateRegistrationAccessToken checks the plaintext RAT against the stored
// bcrypt hash for the given client. Returns the OIDCClientRecord on success,
// fosite.ErrNotFound if the client does not exist, or an error if the token
// does not match.
func (s *OIDCStorage) ValidateRegistrationAccessToken(_ context.Context, clientID, plainRAT string) (*OIDCClientRecord, error) {
	var record OIDCClientRecord
	if err := s.db.First(&record, "id = ? AND namespace = ?", clientID, s.Namespace).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}
	if record.RegistrationAccessToken == "" {
		return nil, fmt.Errorf("client has no registration access token")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(record.RegistrationAccessToken), []byte(plainRAT)); err != nil {
		return nil, fmt.Errorf("invalid registration access token")
	}
	return &record, nil
}

// GetClientRecord returns the raw OIDCClientRecord for a client.
func (s *OIDCStorage) GetClientRecord(_ context.Context, clientID string) (*OIDCClientRecord, error) {
	var record OIDCClientRecord
	if err := s.db.First(&record, "id = ? AND namespace = ?", clientID, s.Namespace).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}
	return &record, nil
}

// IsDynamicallyRegistered returns whether the given client was created via
// dynamic client registration (RFC 7591).
func (s *OIDCStorage) IsDynamicallyRegistered(_ context.Context, clientID string) (bool, error) {
	var record OIDCClientRecord
	if err := s.db.Select("dynamically_registered").First(&record, "id = ? AND namespace = ?", clientID, s.Namespace).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, fosite.ErrNotFound
		}
		return false, err
	}
	return record.DynamicallyRegistered, nil
}

// UpdateDynamicClient applies a set of column updates to a dynamically registered client.
func (s *OIDCStorage) UpdateDynamicClient(ctx context.Context, clientID string, updates map[string]interface{}) error {
	return s.db.WithContext(ctx).Model(&OIDCClientRecord{}).Where("id = ? AND namespace = ?", clientID, s.Namespace).Updates(updates).Error
}

// GetBoundUser returns the user bound to a dynamically registered client.
// Returns "" if no user is bound yet.
func (s *OIDCStorage) GetBoundUser(_ context.Context, clientID string) (string, error) {
	var record OIDCClientRecord
	if err := s.db.Select("bound_user").First(&record, "id = ? AND namespace = ?", clientID, s.Namespace).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", fosite.ErrNotFound
		}
		return "", err
	}
	return record.BoundUser, nil
}

// BindClientToUser atomically binds a dynamically registered client to the
// given user.  If the client is already bound to a different user, returns
// an error.  If already bound to the same user, this is a no-op.
// If the client is not dynamically registered, this is also a no-op (returns nil).
func (s *OIDCStorage) BindClientToUser(ctx context.Context, clientID, user string) error {
	// Single transaction: read the client's registration type and current
	// binding, then conditionally update — all under one lock.
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var record OIDCClientRecord
		if err := tx.Select("dynamically_registered", "bound_user").First(&record, "id = ? AND namespace = ?", clientID, s.Namespace).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fosite.ErrNotFound
			}
			return err
		}

		// Not a dynamically registered client — nothing to enforce.
		if !record.DynamicallyRegistered {
			return nil
		}

		// Already bound to this user — no-op.
		if record.BoundUser == user {
			return nil
		}

		// Bound to a different user — reject.
		if record.BoundUser != "" {
			return fmt.Errorf("client %s is already bound to a different user", clientID)
		}

		// Unbound — bind now.
		return tx.Model(&OIDCClientRecord{}).Where("id = ? AND namespace = ?", clientID, s.Namespace).Update("bound_user", user).Error
	})
}

// TouchClientLastUsed updates the last_used_at timestamp for a client.
//
// To avoid write amplification on hot paths (e.g. every token exchange),
// the actual SQL UPDATE is debounced: if the same client was flushed to
// disk within TouchDebouncePeriod the call is a no-op.
func (s *OIDCStorage) TouchClientLastUsed(ctx context.Context, clientID string) error {
	now := time.Now()
	if v, ok := s.touchDebounce.Load(clientID); ok {
		if now.Sub(v.(time.Time)) < s.TouchDebouncePeriod {
			return nil // debounced — skip write
		}
	}
	err := s.db.WithContext(ctx).Model(&OIDCClientRecord{}).Where("id = ? AND namespace = ?", clientID, s.Namespace).
		Update("last_used_at", now.UTC()).Error
	if err == nil {
		s.touchDebounce.Store(clientID, now)
	}
	return err
}

// DeleteUnusedDynamicClients removes dynamically registered clients that have
// never been used (last_used_at IS NULL) and were created more than maxAge ago.
func (s *OIDCStorage) DeleteUnusedDynamicClients(ctx context.Context, maxAge time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-maxAge)
	result := s.db.WithContext(ctx).
		Where("dynamically_registered = ? AND last_used_at IS NULL AND created_at < ? AND namespace = ?", true, cutoff, s.Namespace).
		Delete(&OIDCClientRecord{})
	return result.RowsAffected, result.Error
}

// DeleteStaleDynamicClients removes dynamically registered clients that were
// previously used but have not been used for longer than maxAge.
func (s *OIDCStorage) DeleteStaleDynamicClients(ctx context.Context, maxAge time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-maxAge)
	result := s.db.WithContext(ctx).
		Where("dynamically_registered = ? AND last_used_at IS NOT NULL AND last_used_at < ? AND namespace = ?", true, cutoff, s.Namespace).
		Delete(&OIDCClientRecord{})
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
		result := s.db.WithContext(ctx).Table(table).
			Where("expires_at < ?", now).
			Delete(&OIDCTokenSession{})
		if result.Error != nil {
			return total, result.Error
		}
		total += result.RowsAffected
	}
	// Refresh tokens: expires_at may be NULL (never-expire), so only delete
	// rows where expires_at is set and in the past, or where the token has
	// been revoked (active=0) and its grace period is long past.
	result := s.db.WithContext(ctx).
		Where("(expires_at IS NOT NULL AND expires_at < ?) OR (active = ? AND first_used_at IS NOT NULL AND first_used_at < ?)",
			now, false, now.Add(-24*time.Hour)).
		Delete(&OIDCRefreshToken{})
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
	result := s.db.WithContext(ctx).
		Where("expires_at < ? OR status = ?", now, "used").
		Delete(&OIDCDeviceCode{})
	return result.RowsAffected, result.Error
}

// DeleteExpiredJWTAssertions removes JWT assertion replay-prevention entries
// whose expiry has passed. Returns the number of rows deleted.
func (s *OIDCStorage) DeleteExpiredJWTAssertions(ctx context.Context) (int64, error) {
	now := time.Now().UTC()
	result := s.db.WithContext(ctx).
		Where("expires_at < ?", now).
		Delete(&OIDCJWTAssertion{})
	return result.RowsAffected, result.Error
}

// ---- Admin Client Management ----

// ClientDetail is a read-only view of a stored OIDC client returned by admin APIs.
type ClientDetail struct {
	ClientID              string   `json:"client_id"`
	RedirectURIs          []string `json:"redirect_uris"`
	GrantTypes            []string `json:"grant_types"`
	ResponseTypes         []string `json:"response_types"`
	Scopes                []string `json:"scopes"`
	Public                bool     `json:"public"`
	DynamicallyRegistered bool     `json:"dynamically_registered"`
	CreatedAt             string   `json:"created_at"`
}

// ListClients returns all registered OIDC clients for this namespace.
func (s *OIDCStorage) ListClients(ctx context.Context) ([]ClientDetail, error) {
	var records []OIDCClientRecord
	if err := s.db.WithContext(ctx).Where("namespace = ?", s.Namespace).Order("created_at").Find(&records).Error; err != nil {
		return nil, err
	}

	clients := make([]ClientDetail, 0, len(records))
	for _, r := range records {
		cd := ClientDetail{
			ClientID:              r.ID,
			Public:                r.Public,
			DynamicallyRegistered: r.DynamicallyRegistered,
			CreatedAt:             r.CreatedAt.Format(time.RFC3339),
		}
		_ = json.Unmarshal([]byte(r.RedirectURIs), &cd.RedirectURIs)
		_ = json.Unmarshal([]byte(r.GrantTypes), &cd.GrantTypes)
		_ = json.Unmarshal([]byte(r.ResponseTypes), &cd.ResponseTypes)
		_ = json.Unmarshal([]byte(r.Scopes), &cd.Scopes)

		clients = append(clients, cd)
	}
	if clients == nil {
		clients = []ClientDetail{}
	}
	return clients, nil
}

// GetClientDetail returns a read-only view of a single client.
func (s *OIDCStorage) GetClientDetail(ctx context.Context, clientID string) (*ClientDetail, error) {
	var record OIDCClientRecord
	if err := s.db.WithContext(ctx).First(&record, "id = ? AND namespace = ?", clientID, s.Namespace).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	cd := &ClientDetail{
		ClientID:              record.ID,
		Public:                record.Public,
		DynamicallyRegistered: record.DynamicallyRegistered,
		CreatedAt:             record.CreatedAt.Format(time.RFC3339),
	}
	_ = json.Unmarshal([]byte(record.RedirectURIs), &cd.RedirectURIs)
	_ = json.Unmarshal([]byte(record.GrantTypes), &cd.GrantTypes)
	_ = json.Unmarshal([]byte(record.ResponseTypes), &cd.ResponseTypes)
	_ = json.Unmarshal([]byte(record.Scopes), &cd.Scopes)

	return cd, nil
}

// UpdateClient applies a partial update to an existing client's mutable fields.
// Only non-nil/non-empty fields in the update are written; omitted fields are
// left unchanged.  Returns the updated ClientDetail, or fosite.ErrNotFound if
// the client does not exist.
func (s *OIDCStorage) UpdateClient(ctx context.Context, clientID string, update ClientUpdate) (*ClientDetail, error) {
	// Verify the client exists.
	existing, err := s.GetClientDetail(ctx, clientID)
	if err != nil {
		return nil, err
	}

	// Merge: use updated value when provided, otherwise keep existing.
	redirectURIs := existing.RedirectURIs
	if update.RedirectURIs != nil {
		redirectURIs = *update.RedirectURIs
	}
	grantTypes := existing.GrantTypes
	if update.GrantTypes != nil {
		grantTypes = *update.GrantTypes
	}
	responseTypes := existing.ResponseTypes
	if update.ResponseTypes != nil {
		responseTypes = *update.ResponseTypes
	}
	scopes := existing.Scopes
	if update.Scopes != nil {
		scopes = *update.Scopes
	}

	redirectJSON, _ := json.Marshal(redirectURIs)
	grantJSON, _ := json.Marshal(grantTypes)
	responseJSON, _ := json.Marshal(responseTypes)
	scopesJSON, _ := json.Marshal(scopes)

	err = s.db.WithContext(ctx).Model(&OIDCClientRecord{}).Where("id = ? AND namespace = ?", clientID, s.Namespace).
		Updates(map[string]interface{}{
			"redirect_uris":  string(redirectJSON),
			"grant_types":    string(grantJSON),
			"response_types": string(responseJSON),
			"scopes":         string(scopesJSON),
		}).Error
	if err != nil {
		return nil, err
	}

	// Re-read to return the authoritative state.
	return s.GetClientDetail(ctx, clientID)
}

// ClientUpdate carries the fields that may be changed via the admin update API.
// Pointer-to-slice fields distinguish "omitted" (nil) from "set to empty" (non-nil, len 0).
type ClientUpdate struct {
	RedirectURIs  *[]string
	GrantTypes    *[]string
	ResponseTypes *[]string
	Scopes        *[]string
}

// DeleteClient removes a client by ID. Returns true if a row was deleted.
func (s *OIDCStorage) DeleteClient(ctx context.Context, clientID string) (bool, error) {
	result := s.db.WithContext(ctx).Where("id = ? AND namespace = ?", clientID, s.Namespace).Delete(&OIDCClientRecord{})
	if result.Error != nil {
		return false, result.Error
	}
	return result.RowsAffected > 0, nil
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

// CreateRefreshTokenSession stores a new refresh token session.
// The accessSignature parameter is required by fosite's RefreshTokenStorage
// interface (v0.49+) but is not used by this implementation.
func (s *OIDCStorage) CreateRefreshTokenSession(ctx context.Context, signature string, _ string, request fosite.Requester) error {
	return s.createTokenSession(ctx, "oidc_refresh_tokens", signature, request)
}

func (s *OIDCStorage) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getRefreshTokenSession(ctx, signature, session)
}

func (s *OIDCStorage) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.deleteTokenSession(ctx, "oidc_refresh_tokens", signature)
}

// RotateRefreshToken is called when a refresh token is being rotated.
// It marks the specific token inactive and sets first_used_at for grace-period
// tracking; getRefreshTokenSession may still allow brief reuse while within
// the configured grace window.
func (s *OIDCStorage) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	return s.db.WithContext(ctx).Model(&OIDCRefreshToken{}).
		Where("signature = ? AND namespace = ? AND active = ?", refreshTokenSignature, s.Namespace, true).
		Updates(map[string]interface{}{
			"first_used_at": gorm.Expr("COALESCE(first_used_at, ?)", time.Now().UTC()),
			"active":        false,
		}).Error
}

// ---- fosite.AuthorizeCodeStorage ----

func (s *OIDCStorage) CreateAuthorizeCodeSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createTokenSession(ctx, "oidc_authorization_codes", signature, request)
}

func (s *OIDCStorage) GetAuthorizeCodeSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getTokenSession(ctx, "oidc_authorization_codes", signature, session)
}

func (s *OIDCStorage) InvalidateAuthorizeCodeSession(ctx context.Context, signature string) error {
	return s.db.WithContext(ctx).Table("oidc_authorization_codes").
		Where("signature = ? AND namespace = ?", signature, s.Namespace).
		Update("active", false).Error
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
	return s.db.WithContext(ctx).Model(&OIDCRefreshToken{}).
		Where("request_id = ? AND namespace = ?", requestID, s.Namespace).
		Update("active", false).Error
}

func (s *OIDCStorage) RevokeAccessToken(ctx context.Context, requestID string) error {
	return s.db.WithContext(ctx).Table("oidc_access_tokens").
		Where("request_id = ? AND namespace = ?", requestID, s.Namespace).
		Update("active", false).Error
}

func (s *OIDCStorage) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, requestID string, refreshTokenSignature string) error {
	// Mark only the specific token being rotated (by signature) rather than
	// all tokens for the request_id, preventing chain poisoning.
	return s.RotateRefreshToken(ctx, requestID, refreshTokenSignature)
}

// ---- fosite.ClientAssertionJWTValid / SetClientAssertionJWT ----

func (s *OIDCStorage) ClientAssertionJWTValid(_ context.Context, jti string) error {
	var assertion OIDCJWTAssertion
	err := s.db.First(&assertion, "jti = ?", jti).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil // JTI not seen before → valid
	}
	if err != nil {
		return err
	}
	if time.Now().After(assertion.ExpiresAt) {
		return nil // Expired entry → valid
	}
	return fosite.ErrJTIKnown
}

func (s *OIDCStorage) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	record := OIDCJWTAssertion{JTI: jti, ExpiresAt: exp}
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{
		UpdateAll: true,
	}).Create(&record).Error
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

	record := OIDCDeviceCode{
		DeviceCode:    deviceCode,
		UserCode:      userCode,
		RequestID:     request.GetID(),
		RequestedAt:   request.GetRequestedAt(),
		ClientID:      request.GetClient().GetID(),
		Scopes:        string(scopes),
		GrantedScopes: string(grantedScopes),
		FormData:      string(formData),
		SessionData:   string(sessionData),
		Subject:       subject,
		Status:        "pending",
		ExpiresAt:     expiresAt,
		Namespace:     s.Namespace,
	}

	return s.db.WithContext(ctx).Create(&record).Error
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
	var dc OIDCDeviceCode
	if err := s.db.WithContext(ctx).First(&dc, "device_code = ? AND namespace = ?", deviceCode, s.Namespace).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	if time.Now().After(dc.ExpiresAt) {
		return nil, ErrExpiredToken
	}

	// RFC 8628 §3.5: enforce minimum polling interval (5 seconds).
	// A single conditional UPDATE atomically checks and advances
	// last_polled_at, eliminating the TOCTOU race of a separate
	// SELECT-then-UPDATE.  If RowsAffected == 0 the previous poll
	// was too recent → slow_down.
	const pollingInterval = 5 * time.Second
	now := time.Now().UTC()
	cutoff := now.Add(-pollingInterval)
	pollResult := s.db.WithContext(ctx).Model(&OIDCDeviceCode{}).
		Where("device_code = ? AND namespace = ? AND (last_polled_at IS NULL OR last_polled_at <= ?)", deviceCode, s.Namespace, cutoff).
		Update("last_polled_at", now)
	if pollResult.Error != nil {
		return nil, pollResult.Error
	}
	if pollResult.RowsAffected == 0 {
		return nil, ErrSlowDown
	}

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
		dc.Scopes, dc.GrantedScopes, "", dc.FormData, dc.SessionData, dc.Subject, session)
}

func (s *OIDCStorage) GetDeviceCodeSessionByUserCode(ctx context.Context, userCode string) (*OIDCDeviceCode, error) {
	var dc OIDCDeviceCode
	if err := s.db.WithContext(ctx).First(&dc, "user_code = ? AND namespace = ?", userCode, s.Namespace).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}
	return &dc, nil
}

func (s *OIDCStorage) ApproveDeviceCodeSession(ctx context.Context, userCode, subject string, grantedScopes []string, sessionData []byte) error {
	gs, _ := json.Marshal(grantedScopes)
	return s.db.WithContext(ctx).Model(&OIDCDeviceCode{}).
		Where("user_code = ? AND namespace = ? AND status = ?", userCode, s.Namespace, "pending").
		Updates(map[string]interface{}{
			"status":         "approved",
			"subject":        subject,
			"granted_scopes": string(gs),
			"session_data":   string(sessionData),
		}).Error
}

func (s *OIDCStorage) DenyDeviceCodeSession(ctx context.Context, userCode string) error {
	return s.db.WithContext(ctx).Model(&OIDCDeviceCode{}).
		Where("user_code = ? AND namespace = ? AND status = ?", userCode, s.Namespace, "pending").
		Update("status", "denied").Error
}

func (s *OIDCStorage) InvalidateDeviceCodeSession(ctx context.Context, deviceCode string) error {
	return s.db.WithContext(ctx).Model(&OIDCDeviceCode{}).
		Where("device_code = ? AND namespace = ?", deviceCode, s.Namespace).
		Update("status", "used").Error
}

func (s *OIDCStorage) UpdateDeviceCodePolling(ctx context.Context, deviceCode string) error {
	return s.db.WithContext(ctx).Model(&OIDCDeviceCode{}).
		Where("device_code = ? AND namespace = ?", deviceCode, s.Namespace).
		Update("last_polled_at", time.Now().UTC()).Error
}

// ---- Internal helpers ----

func (s *OIDCStorage) createTokenSession(ctx context.Context, table, signature string, request fosite.Requester) error {
	if !validTableNames[table] {
		return fmt.Errorf("invalid table name: %s", table)
	}

	scopes, _ := json.Marshal(request.GetRequestedScopes())
	grantedScopes, _ := json.Marshal(request.GetGrantedScopes())
	grantedAudience, _ := json.Marshal(request.GetGrantedAudience())
	formData, _ := json.Marshal(request.GetRequestForm())
	sessionData, _ := json.Marshal(request.GetSession())

	// Derive expiration from the session's token-type-specific expiry when
	// available, so that refresh tokens honour RefreshTokenLifespan (7d)
	// instead of always using a 1h default.
	var expiresAt time.Time
	switch table {
	case "oidc_refresh_tokens":
		expiresAt = request.GetSession().GetExpiresAt(fosite.RefreshToken)
	case "oidc_access_tokens":
		expiresAt = request.GetSession().GetExpiresAt(fosite.AccessToken)
	case "oidc_authorization_codes":
		expiresAt = request.GetSession().GetExpiresAt(fosite.AuthorizeCode)
	}
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(1 * time.Hour)
	}

	record := OIDCTokenSession{
		Signature:       signature,
		RequestID:       request.GetID(),
		RequestedAt:     request.GetRequestedAt(),
		ClientID:        request.GetClient().GetID(),
		Scopes:          string(scopes),
		GrantedScopes:   string(grantedScopes),
		GrantedAudience: string(grantedAudience),
		FormData:        string(formData),
		SessionData:     string(sessionData),
		Subject:         request.GetSession().GetSubject(),
		Active:          true,
		ExpiresAt:       &expiresAt,
		Namespace:       s.Namespace,
	}

	return s.db.WithContext(ctx).Table(table).Create(&record).Error
}

func (s *OIDCStorage) getTokenSession(ctx context.Context, table, signature string, session fosite.Session) (fosite.Requester, error) {
	if !validTableNames[table] {
		return nil, fmt.Errorf("invalid table name: %s", table)
	}

	var record OIDCTokenSession
	if err := s.db.WithContext(ctx).Table(table).First(&record, "signature = ? AND namespace = ?", signature, s.Namespace).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	if !record.Active {
		return nil, fosite.ErrInactiveToken
	}

	return s.scanToRequest(ctx, record.RequestID, record.RequestedAt, record.ClientID,
		record.Scopes, record.GrantedScopes, record.GrantedAudience,
		record.FormData, record.SessionData, record.Subject, session)
}

// getRefreshTokenSession is like getTokenSession but implements the grace period
// for refresh token reuse.
func (s *OIDCStorage) getRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	var record OIDCRefreshToken
	if err := s.db.WithContext(ctx).First(&record, "signature = ? AND namespace = ?", signature, s.Namespace).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	// Build the request first — fosite's handleRefreshTokenReuse expects a
	// non-nil request even when we return ErrInactiveToken, so it can use the
	// request ID to revoke all associated tokens.
	req, err := s.scanToRequest(ctx, record.RequestID, record.RequestedAt, record.ClientID,
		record.Scopes, record.GrantedScopes, record.GrantedAudience,
		record.FormData, record.SessionData, record.Subject, session)
	if err != nil {
		return nil, err
	}

	// Grace period logic: when a token has been rotated (active=false),
	// allow reuse within the grace period so that a client can retry after
	// a transient failure (e.g. the response carrying the new token was
	// lost). Outside the grace period, the token is definitively inactive.
	if !record.Active {
		if record.FirstUsedAt != nil && time.Since(*record.FirstUsedAt) <= s.RefreshTokenGracePeriod {
			// Within grace period — allow reuse.
			return req, nil
		}
		return req, fosite.ErrInactiveToken
	}

	// Active token that has never been used — fully valid.
	return req, nil
}

func (s *OIDCStorage) deleteTokenSession(ctx context.Context, table, signature string) error {
	if !validTableNames[table] {
		return fmt.Errorf("invalid table name: %s", table)
	}
	return s.db.WithContext(ctx).Table(table).Where("signature = ? AND namespace = ?", signature, s.Namespace).Delete(&OIDCTokenSession{}).Error
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
