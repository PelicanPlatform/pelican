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

package issuer

import (
	"context"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/database"
	dbutils "github.com/pelicanplatform/pelican/database/utils"
)

// createTestDB creates a temporary SQLite database with the OIDC tables
// by running the real Goose migration files (universal + origin).
func createTestDB(t *testing.T) *OIDCStorage {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "test-oidc.sqlite")
	db, err := dbutils.InitSQLiteDB(dbPath)
	require.NoError(t, err)

	sqlDB, err := db.DB()
	require.NoError(t, err)

	// Close the database when the test finishes so the file handle is
	// released before t.TempDir cleanup.  Without this, Windows CI fails
	// because open SQLite files cannot be deleted.
	t.Cleanup(func() { sqlDB.Close() })

	require.NoError(t, dbutils.MigrateDB(sqlDB, database.EmbedUniversalMigrations, "universal_migrations"))
	require.NoError(t, dbutils.MigrateServerSpecificDB(sqlDB, database.EmbedOriginMigrations, "origin_migrations", "origin"))

	storage := NewOIDCStorage(db)
	return storage
}

// newTestClient creates a test OAuth2 client in the storage.
func newTestClient(t *testing.T, storage *OIDCStorage, clientID string) *fosite.DefaultClient {
	t.Helper()
	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        []byte("$2a$10$fakehashfakehashfakehashfakehashfakehashfakehashfake"), // bcrypt placeholder
		RedirectURIs:  []string{"https://localhost/callback"},
		GrantTypes:    fosite.Arguments{"authorization_code", "refresh_token"},
		ResponseTypes: fosite.Arguments{"code"},
		Scopes:        fosite.Arguments{"openid", "offline_access", "storage.read:/"},
		Public:        false,
	}
	require.NoError(t, storage.CreateClient(context.Background(), client))
	return client
}

// newTestRequest builds a fosite.Request with a proper session.
func newTestRequest(client fosite.Client, subject string) *fosite.Request {
	now := time.Now()
	session := &WLCGSession{
		JWTClaims: &jwt.JWTClaims{
			Subject:   subject,
			Issuer:    "https://test-issuer.example.com",
			IssuedAt:  now,
			ExpiresAt: now.Add(1 * time.Hour),
			Extra:     map[string]any{},
		},
		IDTokenClaimsField: &jwt.IDTokenClaims{
			Subject:   subject,
			Issuer:    "https://test-issuer.example.com",
			IssuedAt:  now,
			ExpiresAt: now.Add(1 * time.Hour),
			Extra:     map[string]any{},
		},
		JWTHeaders: &jwt.Headers{},
		Subject:    subject,
	}

	req := fosite.NewRequest()
	req.ID = "req-" + subject
	req.Client = client
	req.RequestedAt = now
	req.RequestedScope = fosite.Arguments{"openid", "offline_access", "storage.read:/"}
	req.GrantedScope = fosite.Arguments{"openid", "offline_access", "storage.read:/"}
	req.Form = url.Values{"grant_type": {"authorization_code"}}
	req.Session = session
	return req
}

func TestRefreshTokenStorage(t *testing.T) {
	t.Run("CreateAndRetrieve", func(t *testing.T) {
		storage := createTestDB(t)
		client := newTestClient(t, storage, "test-client-1")
		req := newTestRequest(client, "alice")
		ctx := context.Background()

		// Store
		err := storage.CreateRefreshTokenSession(ctx, "sig-1", "", req)
		require.NoError(t, err)

		// Retrieve
		session := &WLCGSession{
			IDTokenClaimsField: &jwt.IDTokenClaims{Extra: map[string]any{}},
			JWTHeaders:         &jwt.Headers{},
		}
		got, err := storage.GetRefreshTokenSession(ctx, "sig-1", session)
		require.NoError(t, err)
		assert.Equal(t, "req-alice", got.GetID())
		assert.Equal(t, "alice", got.GetSession().GetSubject())
	})

	t.Run("NotFound", func(t *testing.T) {
		storage := createTestDB(t)
		ctx := context.Background()

		session := &WLCGSession{
			IDTokenClaimsField: &jwt.IDTokenClaims{Extra: map[string]any{}},
			JWTHeaders:         &jwt.Headers{},
		}
		_, err := storage.GetRefreshTokenSession(ctx, "nonexistent", session)
		assert.ErrorIs(t, err, fosite.ErrNotFound)
	})
}

func TestRefreshTokenGracePeriod(t *testing.T) {
	t.Run("ReusableWithinGracePeriod", func(t *testing.T) {
		storage := createTestDB(t)
		storage.RefreshTokenGracePeriod = 5 * time.Minute

		client := newTestClient(t, storage, "client-grace")
		req := newTestRequest(client, "alice")
		ctx := context.Background()

		// Create a refresh token session.
		require.NoError(t, storage.CreateRefreshTokenSession(ctx, "rt-grace", "", req))

		// Simulate first use: mark the token as used via the grace period mechanism.
		require.NoError(t, storage.RevokeRefreshTokenMaybeGracePeriod(ctx, req.GetID(), "rt-grace"))

		// The token should still be retrievable because we are within the grace period.
		session := &WLCGSession{
			IDTokenClaimsField: &jwt.IDTokenClaims{Extra: map[string]interface{}{}},
			JWTHeaders:         &jwt.Headers{},
		}
		got, err := storage.GetRefreshTokenSession(ctx, "rt-grace", session)
		require.NoError(t, err, "refresh token should be reusable within the grace period")
		assert.Equal(t, "req-alice", got.GetID())
	})

	t.Run("RejectedAfterGracePeriod", func(t *testing.T) {
		storage := createTestDB(t)
		// Use a very short grace period so we can test expiry.
		storage.RefreshTokenGracePeriod = 1 * time.Millisecond

		client := newTestClient(t, storage, "client-expired")
		req := newTestRequest(client, "bob")
		ctx := context.Background()

		require.NoError(t, storage.CreateRefreshTokenSession(ctx, "rt-expired", "", req))

		// Mark as used
		require.NoError(t, storage.RevokeRefreshTokenMaybeGracePeriod(ctx, req.GetID(), "rt-expired"))

		// Wait for the grace period to elapse
		time.Sleep(5 * time.Millisecond)

		session := &WLCGSession{
			IDTokenClaimsField: &jwt.IDTokenClaims{Extra: map[string]interface{}{}},
			JWTHeaders:         &jwt.Headers{},
		}
		_, err := storage.GetRefreshTokenSession(ctx, "rt-expired", session)
		assert.ErrorIs(t, err, fosite.ErrInactiveToken,
			"refresh token should be rejected after the grace period expires")
	})

	t.Run("SecondUseWithinGracePeriodSucceeds", func(t *testing.T) {
		storage := createTestDB(t)
		storage.RefreshTokenGracePeriod = 5 * time.Minute

		client := newTestClient(t, storage, "client-reuse")
		req := newTestRequest(client, "carol")
		ctx := context.Background()

		require.NoError(t, storage.CreateRefreshTokenSession(ctx, "rt-reuse", "", req))

		// First use: mark the token
		require.NoError(t, storage.RevokeRefreshTokenMaybeGracePeriod(ctx, req.GetID(), "rt-reuse"))

		// First retrieval within grace period → succeeds
		session1 := &WLCGSession{
			IDTokenClaimsField: &jwt.IDTokenClaims{Extra: map[string]interface{}{}},
			JWTHeaders:         &jwt.Headers{},
		}
		got1, err := storage.GetRefreshTokenSession(ctx, "rt-reuse", session1)
		require.NoError(t, err, "first reuse within grace period should succeed")
		assert.Equal(t, "req-carol", got1.GetID())

		// Second use within the same grace period still works
		// (RevokeRefreshTokenMaybeGracePeriod uses COALESCE to preserve
		// the original first_used_at timestamp)
		require.NoError(t, storage.RevokeRefreshTokenMaybeGracePeriod(ctx, req.GetID(), "rt-reuse"))

		session2 := &WLCGSession{
			IDTokenClaimsField: &jwt.IDTokenClaims{Extra: map[string]interface{}{}},
			JWTHeaders:         &jwt.Headers{},
		}
		got2, err := storage.GetRefreshTokenSession(ctx, "rt-reuse", session2)
		require.NoError(t, err, "second reuse within grace period should still succeed")
		assert.Equal(t, "req-carol", got2.GetID())
	})

	t.Run("RevokedTokenRejected", func(t *testing.T) {
		storage := createTestDB(t)
		client := newTestClient(t, storage, "client-revoke")
		req := newTestRequest(client, "dave")
		ctx := context.Background()

		require.NoError(t, storage.CreateRefreshTokenSession(ctx, "rt-revoke", "", req))

		// Hard revoke (sets active=0) - simulates explicit revocation
		require.NoError(t, storage.RevokeRefreshToken(ctx, req.GetID()))

		session := &WLCGSession{
			IDTokenClaimsField: &jwt.IDTokenClaims{Extra: map[string]interface{}{}},
			JWTHeaders:         &jwt.Headers{},
		}
		_, err := storage.GetRefreshTokenSession(ctx, "rt-revoke", session)
		assert.ErrorIs(t, err, fosite.ErrInactiveToken,
			"explicitly revoked token should be rejected regardless of grace period")
	})
}

func TestDeviceCodeStorage(t *testing.T) {
	t.Run("CreateAndApprove", func(t *testing.T) {
		storage := createTestDB(t)
		client := newTestClient(t, storage, "device-client")
		req := newTestRequest(client, "")
		ctx := context.Background()

		expiresAt := time.Now().Add(10 * time.Minute)
		require.NoError(t, storage.CreateDeviceCodeSession(ctx, "dc-1", "ABCD-1234", req, expiresAt))

		// Before approval: should return authorization_pending
		session := &WLCGSession{
			IDTokenClaimsField: &jwt.IDTokenClaims{Extra: map[string]any{}},
			JWTHeaders:         &jwt.Headers{},
		}
		_, err := storage.GetDeviceCodeSession(ctx, "dc-1", session)
		assert.Equal(t, ErrAuthorizationPending, err)

		// Approve the device code
		require.NoError(t, storage.ApproveDeviceCodeSession(ctx, "ABCD-1234", "alice", []string{"openid"}, []byte("{}")))

		// Reset last_polled_at so the next GetDeviceCodeSession doesn't hit the
		// RFC 8628 §3.5 slow_down rate limit from the poll above.
		require.NoError(t, storage.db.Exec(
			`UPDATE oidc_device_codes SET last_polled_at = ? WHERE device_code = ?`,
			time.Now().Add(-10*time.Second), "dc-1",
		).Error)

		// After approval: should succeed
		session2 := &WLCGSession{
			IDTokenClaimsField: &jwt.IDTokenClaims{Extra: map[string]interface{}{}},
			JWTHeaders:         &jwt.Headers{},
		}
		got, err := storage.GetDeviceCodeSession(ctx, "dc-1", session2)
		require.NoError(t, err)
		assert.Equal(t, "alice", got.GetSession().GetSubject())
	})

	t.Run("ExpiredDeviceCode", func(t *testing.T) {
		storage := createTestDB(t)
		client := newTestClient(t, storage, "device-client-exp")
		req := newTestRequest(client, "")
		ctx := context.Background()

		// Create with past expiry
		expiresAt := time.Now().Add(-1 * time.Minute)
		require.NoError(t, storage.CreateDeviceCodeSession(ctx, "dc-exp", "WXYZ-5678", req, expiresAt))

		session := &WLCGSession{
			IDTokenClaimsField: &jwt.IDTokenClaims{Extra: map[string]interface{}{}},
			JWTHeaders:         &jwt.Headers{},
		}
		_, err := storage.GetDeviceCodeSession(ctx, "dc-exp", session)
		assert.Equal(t, ErrExpiredToken, err)
	})

	t.Run("DeniedDeviceCode", func(t *testing.T) {
		storage := createTestDB(t)
		client := newTestClient(t, storage, "device-client-deny")
		req := newTestRequest(client, "")
		ctx := context.Background()

		expiresAt := time.Now().Add(10 * time.Minute)
		require.NoError(t, storage.CreateDeviceCodeSession(ctx, "dc-deny", "DENY-CODE", req, expiresAt))

		require.NoError(t, storage.DenyDeviceCodeSession(ctx, "DENY-CODE"))

		session := &WLCGSession{
			IDTokenClaimsField: &jwt.IDTokenClaims{Extra: map[string]interface{}{}},
			JWTHeaders:         &jwt.Headers{},
		}
		_, err := storage.GetDeviceCodeSession(ctx, "dc-deny", session)
		assert.ErrorIs(t, err, fosite.ErrAccessDenied)
	})
}

// T1: Verify that granted_audience is preserved through storage round-trip
func TestGrantedAudiencePreserved(t *testing.T) {
	storage := createTestDB(t)
	client := newTestClient(t, storage, "aud-client")
	req := newTestRequest(client, "alice")
	req.GrantedAudience = fosite.Arguments{"https://origin.example.com", "https://cache.example.com"}
	ctx := context.Background()

	// Store an access token with a granted audience
	require.NoError(t, storage.CreateAccessTokenSession(ctx, "aud-sig", req))

	// Retrieve and verify the audience survived the round-trip
	session := &WLCGSession{
		IDTokenClaimsField: &jwt.IDTokenClaims{Extra: map[string]any{}},
		JWTHeaders:         &jwt.Headers{},
	}
	got, err := storage.GetAccessTokenSession(ctx, "aud-sig", session)
	require.NoError(t, err)
	assert.ElementsMatch(t, fosite.Arguments{"https://origin.example.com", "https://cache.example.com"},
		got.GetGrantedAudience(), "granted_audience should be preserved in storage")

	// Also test refresh tokens
	require.NoError(t, storage.CreateRefreshTokenSession(ctx, "aud-rt-sig", "", req))
	session2 := &WLCGSession{
		IDTokenClaimsField: &jwt.IDTokenClaims{Extra: map[string]any{}},
		JWTHeaders:         &jwt.Headers{},
	}
	got2, err := storage.GetRefreshTokenSession(ctx, "aud-rt-sig", session2)
	require.NoError(t, err)
	assert.ElementsMatch(t, fosite.Arguments{"https://origin.example.com", "https://cache.example.com"},
		got2.GetGrantedAudience(), "granted_audience should be preserved in refresh token storage")
}

// T2: Verify the device code polling rate limit (RFC 8628 §3.5)
func TestDeviceCodePollingRateLimit(t *testing.T) {
	storage := createTestDB(t)
	client := newTestClient(t, storage, "poll-client")
	req := newTestRequest(client, "")
	ctx := context.Background()

	expiresAt := time.Now().Add(10 * time.Minute)
	require.NoError(t, storage.CreateDeviceCodeSession(ctx, "dc-poll", "POLL-CODE", req, expiresAt))

	// First poll: should return authorization_pending (not slow_down)
	session := &WLCGSession{
		IDTokenClaimsField: &jwt.IDTokenClaims{Extra: map[string]interface{}{}},
		JWTHeaders:         &jwt.Headers{},
	}
	_, err := storage.GetDeviceCodeSession(ctx, "dc-poll", session)
	assert.Equal(t, ErrAuthorizationPending, err, "first poll should be authorization_pending")

	// Immediate second poll: should return slow_down
	session2 := &WLCGSession{
		IDTokenClaimsField: &jwt.IDTokenClaims{Extra: map[string]interface{}{}},
		JWTHeaders:         &jwt.Headers{},
	}
	_, err = storage.GetDeviceCodeSession(ctx, "dc-poll", session2)
	assert.Equal(t, ErrSlowDown, err, "rapid second poll should return slow_down")

	// After resetting last_polled_at to simulate waiting, should work again
	require.NoError(t, storage.db.Exec(
		`UPDATE oidc_device_codes SET last_polled_at = ? WHERE device_code = ?`,
		time.Now().Add(-10*time.Second), "dc-poll",
	).Error)

	session3 := &WLCGSession{
		IDTokenClaimsField: &jwt.IDTokenClaims{Extra: map[string]interface{}{}},
		JWTHeaders:         &jwt.Headers{},
	}
	_, err = storage.GetDeviceCodeSession(ctx, "dc-poll", session3)
	assert.Equal(t, ErrAuthorizationPending, err, "after waiting, should be authorization_pending again")
}

// T4: Verify expired token garbage collection
func TestExpiredTokenGarbageCollection(t *testing.T) {
	storage := createTestDB(t)
	client := newTestClient(t, storage, "gc-client")
	ctx := context.Background()

	// Create an access token then manually expire it in the DB
	expiredReq := newTestRequest(client, "expired-user")
	expiredReq.ID = "req-expired"
	require.NoError(t, storage.CreateAccessTokenSession(ctx, "gc-at-expired", expiredReq))
	require.NoError(t, storage.db.Exec(
		`UPDATE oidc_access_tokens SET expires_at = ? WHERE signature = ?`,
		time.Now().Add(-1*time.Hour), "gc-at-expired",
	).Error)

	// Create a valid access token
	validReq := newTestRequest(client, "valid-user")
	validReq.ID = "req-valid"
	require.NoError(t, storage.CreateAccessTokenSession(ctx, "gc-at-valid", validReq))

	// Create an expired authorization code
	expiredCodeReq := newTestRequest(client, "code-user")
	expiredCodeReq.ID = "req-code-expired"
	require.NoError(t, storage.CreateAuthorizeCodeSession(ctx, "gc-code-expired", expiredCodeReq))
	require.NoError(t, storage.db.Exec(
		`UPDATE oidc_authorization_codes SET expires_at = ? WHERE signature = ?`,
		time.Now().Add(-1*time.Hour), "gc-code-expired",
	).Error)

	// Run GC
	n, err := storage.DeleteExpiredTokenSessions(ctx)
	require.NoError(t, err)
	assert.True(t, n >= 2, "should delete at least 2 expired sessions, got %d", n)

	// Expired access token should be gone
	session := &WLCGSession{
		IDTokenClaimsField: &jwt.IDTokenClaims{Extra: map[string]interface{}{}},
		JWTHeaders:         &jwt.Headers{},
	}
	_, err = storage.GetAccessTokenSession(ctx, "gc-at-expired", session)
	assert.ErrorIs(t, err, fosite.ErrNotFound, "expired access token should be deleted")

	// Valid access token should still exist
	session2 := &WLCGSession{
		IDTokenClaimsField: &jwt.IDTokenClaims{Extra: map[string]interface{}{}},
		JWTHeaders:         &jwt.Headers{},
	}
	got, err := storage.GetAccessTokenSession(ctx, "gc-at-valid", session2)
	require.NoError(t, err, "valid access token should survive GC")
	assert.Equal(t, "valid-user", got.GetSession().GetSubject())
}

// T5: Verify expired device code garbage collection
func TestExpiredDeviceCodeGarbageCollection(t *testing.T) {
	storage := createTestDB(t)
	client := newTestClient(t, storage, "gc-dc-client")
	req := newTestRequest(client, "")
	ctx := context.Background()

	// Create an expired device code
	require.NoError(t, storage.CreateDeviceCodeSession(
		ctx, "dc-gc-expired", "EXP-CODE", req, time.Now().Add(-1*time.Minute)))

	// Create a valid device code
	require.NoError(t, storage.CreateDeviceCodeSession(
		ctx, "dc-gc-valid", "VAL-CODE", req, time.Now().Add(10*time.Minute)))

	// Create a "used" device code (approved and already consumed)
	require.NoError(t, storage.CreateDeviceCodeSession(
		ctx, "dc-gc-used", "USED-CODE", req, time.Now().Add(10*time.Minute)))
	require.NoError(t, storage.ApproveDeviceCodeSession(
		ctx, "USED-CODE", "alice", []string{"openid"}, []byte("{}")))
	require.NoError(t, storage.db.Exec(
		`UPDATE oidc_device_codes SET status = 'used' WHERE device_code = ?`, "dc-gc-used",
	).Error)

	// Run GC
	n, err := storage.DeleteExpiredDeviceCodes(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n, "should delete expired + used device codes")

	// Valid device code should still exist
	dc, err := storage.GetDeviceCodeSessionByUserCode(ctx, "VAL-CODE")
	require.NoError(t, err)
	assert.Equal(t, "pending", dc.Status)

	// Expired and used should be gone
	_, err = storage.GetDeviceCodeSessionByUserCode(ctx, "EXP-CODE")
	assert.ErrorIs(t, err, fosite.ErrNotFound, "expired device code should be deleted")
	_, err = storage.GetDeviceCodeSessionByUserCode(ctx, "USED-CODE")
	assert.ErrorIs(t, err, fosite.ErrNotFound, "used device code should be deleted")
}

// T14: Verify expired JWT assertion garbage collection
func TestExpiredJWTAssertionGC(t *testing.T) {
	storage := createTestDB(t)
	ctx := context.Background()

	// Insert an expired JWT assertion directly
	require.NoError(t, storage.db.Exec(
		`INSERT INTO oidc_jwt_assertions (jti, expires_at) VALUES (?, ?)`,
		"expired-jti", time.Now().Add(-1*time.Hour),
	).Error)

	// Insert a valid JWT assertion
	require.NoError(t, storage.db.Exec(
		`INSERT INTO oidc_jwt_assertions (jti, expires_at) VALUES (?, ?)`,
		"valid-jti", time.Now().Add(1*time.Hour),
	).Error)

	// Run GC
	n, err := storage.DeleteExpiredJWTAssertions(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n, "should delete 1 expired JWT assertion")

	// Expired should be gone
	var count int64
	storage.db.Raw(`SELECT COUNT(*) FROM oidc_jwt_assertions WHERE jti = ?`, "expired-jti").Scan(&count)
	assert.Equal(t, int64(0), count, "expired JTI should be deleted")

	// Valid should remain
	storage.db.Raw(`SELECT COUNT(*) FROM oidc_jwt_assertions WHERE jti = ?`, "valid-jti").Scan(&count)
	assert.Equal(t, int64(1), count, "valid JTI should survive GC")
}
