//go:build !windows

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

package web_ui

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/test_utils"
)

// withMyPasswordTestDB stands up an in-memory DB with the user table
// and password_hash column wired up, restoring the previous DB on
// cleanup. The /me/password handlers only touch the user record and
// the credential view of the same table, so the migration set is
// minimal.
func withMyPasswordTestDB(t *testing.T) {
	t.Helper()
	prev := database.ServerDatabase
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&database.User{}))
	require.NoError(t, database.AutoMigrateCredentialsForTests(db))
	database.ServerDatabase = db
	t.Cleanup(func() { database.ServerDatabase = prev })
}

// seedUser creates an active user with the supplied password (empty
// password = no local-password set) and returns the row's ID.
func seedUser(t *testing.T, id, username, password string) string {
	t.Helper()
	require.NoError(t, database.ServerDatabase.Create(&database.User{
		ID:       id,
		Username: username,
		Sub:      username,
		Issuer:   "https://example.com",
		Status:   database.UserStatusActive,
	}).Error)
	if password != "" {
		require.NoError(t, database.SetUserPassword(database.ServerDatabase, id, password))
	}
	return id
}

// invokeWithCaller runs a handler with UserId pre-set on the gin
// context (the production AuthHandler is what normally sets it; we
// short-circuit that here to test the handler in isolation).
func invokeWithCaller(handler gin.HandlerFunc, userID, method, path string, body []byte) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Handle(method, path, func(ctx *gin.Context) {
		if userID != "" {
			ctx.Set("UserId", userID)
		}
	}, handler)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	return w
}

// TestHandleUpdateMyPassword pins the contract for self-service
// password rotation:
//
//   - Refused with 403 when the row has no password set (the design
//     contract: only an admin-issued invite can CREATE a password,
//     so an OIDC-only user can't quietly grow one).
//   - Refused with 403 when the supplied current password is wrong.
//   - Refused with 400 when either field is empty.
//   - Refused with 500 when no caller can be identified (callerID
//     guards against ctx misconfiguration upstream).
//   - Succeeds with 204 and updates the stored hash on a correct
//     current password — verified by trying to log in via
//     VerifyUserPassword with the new password afterwards.
func TestHandleUpdateMyPassword(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	t.Run("refused when caller has no password set", func(t *testing.T) {
		withMyPasswordTestDB(t)
		seedUser(t, "u-noPW", "alice", "")
		body := []byte(`{"currentPassword":"x","newPassword":"newSecret123"}`)
		w := invokeWithCaller(handleUpdateMyPassword, "u-noPW", http.MethodPut, "/me/password", body)
		assert.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
		assert.Contains(t, w.Body.String(), "no local password is set",
			"users without a password must be told to use the admin-invite path, not have a quiet path to create one here")
	})

	t.Run("refused when current password is wrong", func(t *testing.T) {
		withMyPasswordTestDB(t)
		seedUser(t, "u-bob", "bob", "correct-pw")
		body := []byte(`{"currentPassword":"wrong","newPassword":"newSecret123"}`)
		w := invokeWithCaller(handleUpdateMyPassword, "u-bob", http.MethodPut, "/me/password", body)
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "current password is incorrect")
	})

	t.Run("rejects missing fields with 400", func(t *testing.T) {
		withMyPasswordTestDB(t)
		seedUser(t, "u-carol", "carol", "old-pw-123")
		// Missing newPassword.
		body := []byte(`{"currentPassword":"old-pw-123"}`)
		w := invokeWithCaller(handleUpdateMyPassword, "u-carol", http.MethodPut, "/me/password", body)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "currentPassword and newPassword are required")
	})

	t.Run("aborts with 500 when caller has no UserId", func(t *testing.T) {
		withMyPasswordTestDB(t)
		body := []byte(`{"currentPassword":"x","newPassword":"y"}`)
		// userID = "" → callerID() short-circuits before reaching
		// any password code.
		w := invokeWithCaller(handleUpdateMyPassword, "", http.MethodPut, "/me/password", body)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("rotates an existing password", func(t *testing.T) {
		withMyPasswordTestDB(t)
		seedUser(t, "u-dan", "dan", "old-pw-123")
		body := []byte(`{"currentPassword":"old-pw-123","newPassword":"newSecret123"}`)
		w := invokeWithCaller(handleUpdateMyPassword, "u-dan", http.MethodPut, "/me/password", body)
		assert.Equal(t, http.StatusNoContent, w.Code, "body: %s", w.Body.String())

		// The new password must verify; the old one must not. (Both
		// halves matter — a buggy implementation that wrote a tombstone
		// hash would pass "new doesn't verify" but break "old fails too".)
		_, err := database.VerifyUserPassword(database.ServerDatabase, "dan", "newSecret123", "https://example.com")
		assert.NoError(t, err, "the new password must authenticate after rotation")
		_, err = database.VerifyUserPassword(database.ServerDatabase, "dan", "old-pw-123", "https://example.com")
		assert.Error(t, err, "the previous password must stop working as soon as the rotation succeeds")
	})
}

// TestHandleClearMyPassword pins the self-service clear-password
// contract:
//
//   - Refused with 403 when the row has no password (no observable
//     side effect on a credential-less account).
//   - Succeeds with 204 when a password is set, AFTER which the
//     stored credential no longer authenticates.
//   - Refused with 500 on missing UserId.
//
// The test deliberately doesn't assert that linked OIDC identities
// keep working — that's a property of the IdP relationship, not of
// SetUserPassword(""), and is covered by the login-flow tests.
func TestHandleClearMyPassword(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	t.Run("refused when caller has no password", func(t *testing.T) {
		withMyPasswordTestDB(t)
		seedUser(t, "u-eve", "eve", "")
		w := invokeWithCaller(handleClearMyPassword, "u-eve", http.MethodDelete, "/me/password", nil)
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "no local password is set")
	})

	t.Run("clears an existing password", func(t *testing.T) {
		withMyPasswordTestDB(t)
		seedUser(t, "u-frank", "frank", "old-pw-123")
		w := invokeWithCaller(handleClearMyPassword, "u-frank", http.MethodDelete, "/me/password", nil)
		assert.Equal(t, http.StatusNoContent, w.Code, "body: %s", w.Body.String())

		// After clear, login with the OLD password must fail. There's
		// no "new" password to test — that's the point.
		_, err := database.VerifyUserPassword(database.ServerDatabase, "frank", "old-pw-123", "https://example.com")
		assert.Error(t, err, "the cleared password must stop authenticating")
	})

	t.Run("aborts with 500 when caller has no UserId", func(t *testing.T) {
		withMyPasswordTestDB(t)
		w := invokeWithCaller(handleClearMyPassword, "", http.MethodDelete, "/me/password", nil)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}
