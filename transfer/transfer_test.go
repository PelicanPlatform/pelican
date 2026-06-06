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

package transfer

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/client_agent"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

func setupTestEnvironment(t *testing.T) (*gin.Engine, *gorm.DB) {
	t.Helper()
	server_utils.ResetTestState()
	t.Cleanup(config.ResetConfig)
	gin.SetMode(gin.TestMode)

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	t.Cleanup(func() {
		cancel()
		if err := egrp.Wait(); err != nil && err != context.Canceled {
			t.Log("Error waiting for errgroup:", err)
		}
	})

	tmpDir := t.TempDir()
	require.NoError(t, param.Set(param.ConfigDir, tmpDir))
	require.NoError(t, param.Set(param.IssuerKeysDirectory, filepath.Join(tmpDir, "issuer-keys")))
	require.NoError(t, param.Set(param.Server_UILoginRateLimit, 100))

	exportDir := filepath.Join(tmpDir, "export")
	require.NoError(t, os.MkdirAll(exportDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(exportDir, "sentinel"), []byte("test"), 0644))
	require.NoError(t, param.Set(param.Origin_StorageType, "posix"))
	require.NoError(t, param.Set(param.Origin_Exports, []map[string]interface{}{
		{
			"StoragePrefix":    exportDir,
			"FederationPrefix": "/test",
			"SentinelLocation": "sentinel",
		},
	}))

	test_utils.MockFederationRoot(t, nil, nil)
	require.NoError(t, config.InitServer(ctx, server_structs.OriginType))

	mockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	database.ServerDatabase = mockDB
	require.NoError(t, mockDB.Exec("PRAGMA foreign_keys = ON").Error)
	require.NoError(t, mockDB.AutoMigrate(&database.User{}))
	require.NoError(t, mockDB.AutoMigrate(&TransferCredential{}))
	require.NoError(t, mockDB.AutoMigrate(&TransferOAuthClient{}))
	require.NoError(t, mockDB.AutoMigrate(&TransferJob{}))
	require.NoError(t, mockDB.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_transfer_credentials_owner_name ON transfer_credentials(user_id, name)").Error)
	require.NoError(t, mockDB.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_transfer_oauth_clients_owner_name ON transfer_oauth_clients(user_id, name)").Error)

	tm := client_agent.NewTransferManager(ctx, 5, nil)
	engine := gin.New()
	engine.Use(gin.Recovery())
	require.NoError(t, registerTransferRoutes(ctx, engine, egrp, mockDB, tm))
	return engine, mockDB
}

func generateTransferToken(t *testing.T, subject string, groups ...string) string {
	t.Helper()
	tk := token.NewWLCGToken()
	issuer := param.Server_ExternalWebUrl.GetString()
	require.NotEmpty(t, issuer, "Server External Web URL must be set")
	tk.Issuer = issuer
	tk.Subject = subject
	tk.Lifetime = 5 * time.Minute
	tk.AddAudienceAny()
	tk.AddScopes(token_scopes.Pelican_Transfer)
	if len(groups) > 0 {
		tk.AddGroups(groups...)
	}
	tok, err := tk.CreateToken()
	require.NoError(t, err)
	return tok
}

func doRequest(t *testing.T, engine *gin.Engine, method, path string, body interface{}, tok string) *httptest.ResponseRecorder {
	t.Helper()
	var reqBody *bytes.Buffer
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		reqBody = bytes.NewBuffer(data)
	} else {
		reqBody = bytes.NewBuffer(nil)
	}
	req, err := http.NewRequest(method, path, reqBody)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

// doRequestCookie is like doRequest but presents the token via the "login"
// cookie (a web-UI session) instead of the Authorization header.  Group
// membership (Transfer.EnabledGroups) is only enforced for cookie-based auth.
func doRequestCookie(t *testing.T, engine *gin.Engine, method, path string, body interface{}, tok string) *httptest.ResponseRecorder {
	t.Helper()
	var reqBody *bytes.Buffer
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		reqBody = bytes.NewBuffer(data)
	} else {
		reqBody = bytes.NewBuffer(nil)
	}
	req, err := http.NewRequest(method, path, reqBody)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if tok != "" {
		req.AddCookie(&http.Cookie{Name: "login", Value: tok})
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

func TestCredentialCRUD(t *testing.T) {
	engine, _ := setupTestEnvironment(t)
	tok := generateTransferToken(t, "test-user")
	var credID string

	t.Run("CreateCredential", func(t *testing.T) {
		creq := CredentialCreateRequest{
			Name:        "my-cred",
			AccessToken: "secret-access-token-123",
			TokenIssuer: "https://example.com",
		}
		w := doRequest(t, engine, "POST", "/api/v1.0/transfer/credentials", creq, tok)
		assert.Equal(t, http.StatusCreated, w.Code, "Body: %s", w.Body.String())
		var resp CredentialResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.NotEmpty(t, resp.ID)
		assert.Equal(t, "my-cred", resp.Name)
		assert.Equal(t, "bearer", resp.CredentialType)
		assert.Equal(t, "https://example.com", resp.TokenIssuer)
		credID = resp.ID
	})

	t.Run("ListCredentials", func(t *testing.T) {
		w := doRequest(t, engine, "GET", "/api/v1.0/transfer/credentials", nil, tok)
		assert.Equal(t, http.StatusOK, w.Code)
		var resp []CredentialResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Len(t, resp, 1)
		assert.Equal(t, credID, resp[0].ID)
	})

	t.Run("GetCredential", func(t *testing.T) {
		w := doRequest(t, engine, "GET", "/api/v1.0/transfer/credentials/"+credID, nil, tok)
		assert.Equal(t, http.StatusOK, w.Code)
		var resp CredentialResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, credID, resp.ID)
		assert.Equal(t, "my-cred", resp.Name)
	})

	t.Run("DuplicateNameRejected", func(t *testing.T) {
		creq := CredentialCreateRequest{
			Name:        "my-cred",
			AccessToken: "another-token",
		}
		w := doRequest(t, engine, "POST", "/api/v1.0/transfer/credentials", creq, tok)
		assert.Equal(t, http.StatusConflict, w.Code)
	})

	t.Run("DeleteCredential", func(t *testing.T) {
		w := doRequest(t, engine, "DELETE", "/api/v1.0/transfer/credentials/"+credID, nil, tok)
		assert.Equal(t, http.StatusOK, w.Code)
		w = doRequest(t, engine, "GET", "/api/v1.0/transfer/credentials/"+credID, nil, tok)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("DeleteNonExistent", func(t *testing.T) {
		w := doRequest(t, engine, "DELETE", "/api/v1.0/transfer/credentials/nonexistent-id", nil, tok)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestCredentialOwnershipIsolation(t *testing.T) {
	engine, _ := setupTestEnvironment(t)
	tokAlice := generateTransferToken(t, "alice")
	tokBob := generateTransferToken(t, "bob")

	creq := CredentialCreateRequest{
		Name:        "alice-cred",
		AccessToken: "alice-secret",
	}
	w := doRequest(t, engine, "POST", "/api/v1.0/transfer/credentials", creq, tokAlice)
	require.Equal(t, http.StatusCreated, w.Code)
	var resp CredentialResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	aliceCredID := resp.ID

	t.Run("BobCannotSeeAliceCredentials", func(t *testing.T) {
		w := doRequest(t, engine, "GET", "/api/v1.0/transfer/credentials", nil, tokBob)
		assert.Equal(t, http.StatusOK, w.Code)
		var creds []CredentialResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &creds))
		assert.Empty(t, creds)
	})

	t.Run("BobCannotGetAliceCredential", func(t *testing.T) {
		w := doRequest(t, engine, "GET", "/api/v1.0/transfer/credentials/"+aliceCredID, nil, tokBob)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("BobCannotDeleteAliceCredential", func(t *testing.T) {
		w := doRequest(t, engine, "DELETE", "/api/v1.0/transfer/credentials/"+aliceCredID, nil, tokBob)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("AliceCanStillAccessOwn", func(t *testing.T) {
		w := doRequest(t, engine, "GET", "/api/v1.0/transfer/credentials/"+aliceCredID, nil, tokAlice)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("BobCanUseSameName", func(t *testing.T) {
		creq := CredentialCreateRequest{
			Name:        "alice-cred",
			AccessToken: "bob-secret",
		}
		w := doRequest(t, engine, "POST", "/api/v1.0/transfer/credentials", creq, tokBob)
		assert.Equal(t, http.StatusCreated, w.Code)
	})
}

func TestAuthMiddleware(t *testing.T) {
	engine, _ := setupTestEnvironment(t)

	t.Run("NoTokenReturns403", func(t *testing.T) {
		w := doRequest(t, engine, "GET", "/api/v1.0/transfer/credentials", nil, "")
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("InvalidTokenReturns403", func(t *testing.T) {
		w := doRequest(t, engine, "GET", "/api/v1.0/transfer/credentials", nil, "not-a-valid-jwt")
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("ValidTokenSucceeds", func(t *testing.T) {
		tok := generateTransferToken(t, "valid-user")
		w := doRequest(t, engine, "GET", "/api/v1.0/transfer/credentials", nil, tok)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestGroupRestriction(t *testing.T) {
	engine, _ := setupTestEnvironment(t)

	require.NoError(t, param.Set(param.Transfer_EnabledGroups, []string{"/transfer-users"}))
	t.Cleanup(func() {
		require.NoError(t, param.Set(param.Transfer_EnabledGroups, []string{}))
	})

	// Group membership is enforced only for cookie-based (web-UI) sessions.
	t.Run("CookieUserWithoutGroupRejected", func(t *testing.T) {
		tok := generateTransferToken(t, "no-group-user")
		w := doRequestCookie(t, engine, "GET", "/api/v1.0/transfer/credentials", nil, tok)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("CookieUserWithMatchingGroupAllowed", func(t *testing.T) {
		tok := generateTransferToken(t, "group-user", "/transfer-users")
		w := doRequestCookie(t, engine, "GET", "/api/v1.0/transfer/credentials", nil, tok)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("CookieUserWithWrongGroupRejected", func(t *testing.T) {
		tok := generateTransferToken(t, "wrong-group-user", "/other-group")
		w := doRequestCookie(t, engine, "GET", "/api/v1.0/transfer/credentials", nil, tok)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	// Bearer tokens (Authorization header) carry an explicit transfer scope and
	// are intentionally not subject to the group check.
	t.Run("BearerTokenBypassesGroupCheck", func(t *testing.T) {
		tok := generateTransferToken(t, "wrong-group-bearer", "/other-group")
		w := doRequest(t, engine, "GET", "/api/v1.0/transfer/credentials", nil, tok)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestOAuthClientCRUD(t *testing.T) {
	engine, _ := setupTestEnvironment(t)
	tok := generateTransferToken(t, "test-user")

	require.NoError(t, param.Set(param.Transfer_EnableOAuth2Clients, true))
	t.Cleanup(func() {
		require.NoError(t, param.Set(param.Transfer_EnableOAuth2Clients, false))
	})

	var clientID string

	t.Run("CreateOAuthClient", func(t *testing.T) {
		creq := OAuthClientCreateRequest{
			Name:         "my-oauth-client",
			IssuerURL:    "https://accounts.example.com",
			ClientID:     "client-id-123",
			ClientSecret: "super-secret",
		}
		w := doRequest(t, engine, "POST", "/api/v1.0/transfer/oauth-clients", creq, tok)
		assert.Equal(t, http.StatusCreated, w.Code, "Body: %s", w.Body.String())
		var resp OAuthClientResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.NotEmpty(t, resp.ID)
		assert.Equal(t, "my-oauth-client", resp.Name)
		assert.Equal(t, "https://accounts.example.com", resp.IssuerURL)
		clientID = resp.ID
	})

	t.Run("ListOAuthClients", func(t *testing.T) {
		w := doRequest(t, engine, "GET", "/api/v1.0/transfer/oauth-clients", nil, tok)
		assert.Equal(t, http.StatusOK, w.Code)
		var resp []OAuthClientResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Len(t, resp, 1)
		assert.Equal(t, clientID, resp[0].ID)
	})

	t.Run("DeleteOAuthClient", func(t *testing.T) {
		w := doRequest(t, engine, "DELETE", "/api/v1.0/transfer/oauth-clients/"+clientID, nil, tok)
		assert.Equal(t, http.StatusOK, w.Code)
		w = doRequest(t, engine, "GET", "/api/v1.0/transfer/oauth-clients", nil, tok)
		assert.Equal(t, http.StatusOK, w.Code)
		var resp []OAuthClientResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Empty(t, resp)
	})
}

func TestOAuthClientDisabledByDefault(t *testing.T) {
	engine, _ := setupTestEnvironment(t)
	tok := generateTransferToken(t, "test-user")

	require.NoError(t, param.Set(param.Transfer_EnableOAuth2Clients, false))

	t.Run("CreateRejectedWhenDisabled", func(t *testing.T) {
		creq := OAuthClientCreateRequest{
			Name:         "test-client",
			IssuerURL:    "https://example.com",
			ClientID:     "id",
			ClientSecret: "secret",
		}
		w := doRequest(t, engine, "POST", "/api/v1.0/transfer/oauth-clients", creq, tok)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("ListRejectedWhenDisabled", func(t *testing.T) {
		w := doRequest(t, engine, "GET", "/api/v1.0/transfer/oauth-clients", nil, tok)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

func TestTransferJobSubmission(t *testing.T) {
	engine, _ := setupTestEnvironment(t)
	tok := generateTransferToken(t, "test-user")

	t.Run("CreateJobWithoutCredential", func(t *testing.T) {
		jreq := TransferJobCreateRequest{
			Transfers: []TransferItem{
				{
					Operation:   "get",
					Source:      "pelican:///test/hello.txt",
					Destination: "/tmp/hello.txt",
				},
			},
		}
		w := doRequest(t, engine, "POST", "/api/v1.0/transfer/jobs", jreq, tok)
		assert.Equal(t, http.StatusCreated, w.Code, "Body: %s", w.Body.String())
		var resp TransferJobResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.NotEmpty(t, resp.JobID)
		assert.Contains(t, []string{"pending", "running"}, resp.Status)
		assert.Len(t, resp.Transfers, 1)
	})

	t.Run("CreateJobWithInvalidBody", func(t *testing.T) {
		w := doRequest(t, engine, "POST", "/api/v1.0/transfer/jobs", map[string]string{}, tok)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("CreateJobWithSourceCredential", func(t *testing.T) {
		creq := CredentialCreateRequest{
			Name:        "src-cred",
			AccessToken: "source-token-value",
		}
		w := doRequest(t, engine, "POST", "/api/v1.0/transfer/credentials", creq, tok)
		require.Equal(t, http.StatusCreated, w.Code)
		var credResp CredentialResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &credResp))

		jreq := TransferJobCreateRequest{
			Transfers: []TransferItem{
				{
					Operation:   "get",
					Source:      "pelican:///test/file.txt",
					Destination: "/tmp/file.txt",
				},
			},
			SourceCredentialID: credResp.ID,
		}
		w = doRequest(t, engine, "POST", "/api/v1.0/transfer/jobs", jreq, tok)
		assert.Equal(t, http.StatusCreated, w.Code, "Body: %s", w.Body.String())
	})

	t.Run("CreateJobWithNonExistentCredential", func(t *testing.T) {
		jreq := TransferJobCreateRequest{
			Transfers: []TransferItem{
				{
					Operation:   "get",
					Source:      "pelican:///test/file.txt",
					Destination: "/tmp/file.txt",
				},
			},
			SourceCredentialID: "non-existent-credential-id",
		}
		w := doRequest(t, engine, "POST", "/api/v1.0/transfer/jobs", jreq, tok)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestTransferJobOwnershipIsolation(t *testing.T) {
	engine, _ := setupTestEnvironment(t)
	tokAlice := generateTransferToken(t, "alice")
	tokBob := generateTransferToken(t, "bob")

	jreq := TransferJobCreateRequest{
		Transfers: []TransferItem{
			{
				Operation:   "get",
				Source:      "pelican:///test/file.txt",
				Destination: "/tmp/file.txt",
			},
		},
	}
	w := doRequest(t, engine, "POST", "/api/v1.0/transfer/jobs", jreq, tokAlice)
	require.Equal(t, http.StatusCreated, w.Code)
	var resp TransferJobResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	aliceJobID := resp.JobID

	t.Run("BobCannotSeeAliceJobs", func(t *testing.T) {
		w := doRequest(t, engine, "GET", "/api/v1.0/transfer/jobs", nil, tokBob)
		assert.Equal(t, http.StatusOK, w.Code)
		var listResp TransferJobListResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listResp))
		assert.Equal(t, 0, listResp.Total)
	})

	t.Run("BobCannotGetAliceJob", func(t *testing.T) {
		w := doRequest(t, engine, "GET", "/api/v1.0/transfer/jobs/"+aliceJobID, nil, tokBob)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("BobCannotCancelAliceJob", func(t *testing.T) {
		w := doRequest(t, engine, "DELETE", "/api/v1.0/transfer/jobs/"+aliceJobID, nil, tokBob)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("AliceCanSeeOwnJob", func(t *testing.T) {
		w := doRequest(t, engine, "GET", "/api/v1.0/transfer/jobs/"+aliceJobID, nil, tokAlice)
		assert.Equal(t, http.StatusOK, w.Code)
		var status TransferJobStatus
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &status))
		assert.Equal(t, aliceJobID, status.JobID)
	})
}

func TestCredentialEncryptionRoundTrip(t *testing.T) {
	engine, db := setupTestEnvironment(t)
	tok := generateTransferToken(t, "encrypt-test-user")
	secretToken := "my-super-secret-access-token-value"

	creq := CredentialCreateRequest{
		Name:        "encrypted-cred",
		AccessToken: secretToken,
	}
	w := doRequest(t, engine, "POST", "/api/v1.0/transfer/credentials", creq, tok)
	require.Equal(t, http.StatusCreated, w.Code)

	var resp CredentialResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	var storedCred TransferCredential
	require.NoError(t, db.First(&storedCred, "id = ?", resp.ID).Error)
	assert.NotEqual(t, secretToken, storedCred.EncryptedAccessToken, "Access token should be encrypted in database")
	assert.NotEmpty(t, storedCred.EncryptedAccessToken)

	bodyStr := w.Body.String()
	assert.NotContains(t, bodyStr, secretToken, "Secret token should not appear in API response")

	// Use the user_id from the stored credential to construct the owner identity
	owner := ownerIdentity{UserID: storedCred.UserID}
	decrypted, err := getDecryptedAccessToken(db, resp.ID, owner)
	require.NoError(t, err)
	assert.Equal(t, secretToken, decrypted)
}

func TestCredentialCleanup(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(config.ResetConfig)

	tmpDir := t.TempDir()
	require.NoError(t, param.Set(param.ConfigDir, tmpDir))
	require.NoError(t, param.Set(param.IssuerKeysDirectory, filepath.Join(tmpDir, "issuer-keys")))

	ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
	defer cancel()

	test_utils.MockFederationRoot(t, nil, nil)
	require.NoError(t, config.InitServer(ctx, server_structs.OriginType))

	mockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, mockDB.AutoMigrate(&TransferCredential{}))

	encToken, err := config.EncryptString("test-token")
	require.NoError(t, err)

	oldTime := time.Now().Add(-2 * time.Hour)
	recentTime := time.Now().Add(-5 * time.Minute)

	// Create credentials with varying ages and usage
	creds := []TransferCredential{
		{
			ID: "old-never-used", UserID: "test-user",
			Name: "old-never-used", EncryptedAccessToken: encToken,
			CreatedAt: oldTime, UpdatedAt: oldTime,
		},
		{
			ID: "old-used-recently", UserID: "test-user",
			Name: "old-used-recently", EncryptedAccessToken: encToken,
			CreatedAt: oldTime, UpdatedAt: oldTime, LastUsedAt: &recentTime,
		},
		{
			ID: "old-used-long-ago", UserID: "test-user",
			Name: "old-used-long-ago", EncryptedAccessToken: encToken,
			CreatedAt: oldTime, UpdatedAt: oldTime, LastUsedAt: &oldTime,
		},
		{
			ID: "new-never-used", UserID: "test-user",
			Name: "new-never-used", EncryptedAccessToken: encToken,
			CreatedAt: recentTime, UpdatedAt: recentTime,
		},
	}
	for _, c := range creds {
		require.NoError(t, mockDB.Create(&c).Error)
	}

	// Run one cleanup cycle with a 1 hour timeout
	timeout := 1 * time.Hour
	cutoff := time.Now().Add(-timeout)
	result := mockDB.Where(
		"(last_used_at IS NOT NULL AND last_used_at < ?) OR (last_used_at IS NULL AND created_at < ?)",
		cutoff, cutoff,
	).Delete(&TransferCredential{})
	require.NoError(t, result.Error)
	assert.Equal(t, int64(2), result.RowsAffected)

	// Verify which credentials remain
	var remaining []TransferCredential
	require.NoError(t, mockDB.Find(&remaining).Error)
	assert.Equal(t, 2, len(remaining))

	remainingIDs := make(map[string]bool)
	for _, c := range remaining {
		remainingIDs[c.ID] = true
	}
	assert.True(t, remainingIDs["old-used-recently"], "recently-used credential should survive")
	assert.True(t, remainingIDs["new-never-used"], "new credential should survive")
	assert.False(t, remainingIDs["old-never-used"], "old never-used credential should be cleaned up")
	assert.False(t, remainingIDs["old-used-long-ago"], "old stale credential should be cleaned up")
}

func TestCredentialTokenProvider(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(config.ResetConfig)

	tmpDir := t.TempDir()
	require.NoError(t, param.Set(param.ConfigDir, tmpDir))
	require.NoError(t, param.Set(param.IssuerKeysDirectory, filepath.Join(tmpDir, "issuer-keys")))

	ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
	defer cancel()

	test_utils.MockFederationRoot(t, nil, nil)
	require.NoError(t, config.InitServer(ctx, server_structs.OriginType))

	mockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, mockDB.AutoMigrate(&TransferCredential{}))
	mockDB.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_transfer_credentials_owner_name ON transfer_credentials(user_id, name)")

	secretToken := "my-secret-access-token"
	encToken, err := config.EncryptString(secretToken)
	require.NoError(t, err)

	cred := TransferCredential{
		ID: "test-cred", UserID: "test-user",
		Name: "test-cred", EncryptedAccessToken: encToken,
	}
	require.NoError(t, mockDB.Create(&cred).Error)

	owner := ownerIdentity{UserID: "test-user"}

	t.Run("GetReturnsDecryptedToken", func(t *testing.T) {
		provider := newCredentialTokenProvider(mockDB, "test-cred", owner)
		tok, err := provider.Get()
		require.NoError(t, err)
		assert.Equal(t, secretToken, tok)

		// last_used_at should be set after Get()
		var updated TransferCredential
		require.NoError(t, mockDB.First(&updated, "id = ?", "test-cred").Error)
		assert.NotNil(t, updated.LastUsedAt)
	})

	t.Run("GetFailsForWrongOwner", func(t *testing.T) {
		wrongOwner := ownerIdentity{UserID: "nonexistent-user-id"}
		provider := newCredentialTokenProvider(mockDB, "test-cred", wrongOwner)
		_, err := provider.Get()
		assert.Error(t, err)
	})

	t.Run("DebouncePreventsDuplicateUpdates", func(t *testing.T) {
		provider := newCredentialTokenProvider(mockDB, "test-cred", owner)

		// First call sets last_used_at
		_, err := provider.Get()
		require.NoError(t, err)

		var first TransferCredential
		require.NoError(t, mockDB.First(&first, "id = ?", "test-cred").Error)
		firstTime := *first.LastUsedAt

		// Second call should be debounced (within the 5-minute window)
		_, err = provider.Get()
		require.NoError(t, err)

		var second TransferCredential
		require.NoError(t, mockDB.First(&second, "id = ?", "test-cred").Error)
		assert.Equal(t, firstTime, *second.LastUsedAt, "last_used_at should not change within debounce window")
	})
}

func TestTransferPrefixValidation(t *testing.T) {
	engine, _ := setupTestEnvironment(t)
	tok := generateTransferToken(t, "test-user")

	// Set allowed prefixes to simulate origin mode
	origPrefixes := allowedPrefixes
	allowedPrefixes = []string{"/origin/data", "/origin/public"}
	t.Cleanup(func() { allowedPrefixes = origPrefixes })

	t.Run("AllowedSourcePrefix", func(t *testing.T) {
		jreq := TransferJobCreateRequest{
			Transfers: []TransferItem{
				{
					Operation:   "get",
					Source:      "pelican:///origin/data/file.txt",
					Destination: "/tmp/file.txt",
				},
			},
		}
		w := doRequest(t, engine, "POST", "/api/v1.0/transfer/jobs", jreq, tok)
		assert.Equal(t, http.StatusCreated, w.Code, "Body: %s", w.Body.String())
	})

	t.Run("AllowedDestPrefix", func(t *testing.T) {
		jreq := TransferJobCreateRequest{
			Transfers: []TransferItem{
				{
					Operation:   "put",
					Source:      "/tmp/file.txt",
					Destination: "pelican:///origin/public/file.txt",
				},
			},
		}
		w := doRequest(t, engine, "POST", "/api/v1.0/transfer/jobs", jreq, tok)
		assert.Equal(t, http.StatusCreated, w.Code, "Body: %s", w.Body.String())
	})

	t.Run("RejectedPrefix", func(t *testing.T) {
		jreq := TransferJobCreateRequest{
			Transfers: []TransferItem{
				{
					Operation:   "get",
					Source:      "pelican:///other/namespace/file.txt",
					Destination: "/tmp/file.txt",
				},
			},
		}
		w := doRequest(t, engine, "POST", "/api/v1.0/transfer/jobs", jreq, tok)
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "PATH_NOT_ALLOWED")
	})

	t.Run("ExactPrefixMatch", func(t *testing.T) {
		jreq := TransferJobCreateRequest{
			Transfers: []TransferItem{
				{
					Operation:   "get",
					Source:      "pelican:///origin/data",
					Destination: "/tmp/data",
				},
			},
		}
		w := doRequest(t, engine, "POST", "/api/v1.0/transfer/jobs", jreq, tok)
		assert.Equal(t, http.StatusCreated, w.Code, "Body: %s", w.Body.String())
	})

	t.Run("PartialPrefixNotAllowed", func(t *testing.T) {
		// /origin/database should NOT match /origin/data
		jreq := TransferJobCreateRequest{
			Transfers: []TransferItem{
				{
					Operation:   "get",
					Source:      "pelican:///origin/database/file.txt",
					Destination: "/tmp/file.txt",
				},
			},
		}
		w := doRequest(t, engine, "POST", "/api/v1.0/transfer/jobs", jreq, tok)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

func TestExtractPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"PelicanURL", "pelican:///foo/bar/file.txt", "/foo/bar/file.txt"},
		{"OsdfURL", "osdf:///namespace/data", "/namespace/data"},
		{"HttpURL", "https://example.com/data/file.txt", "/data/file.txt"},
		{"BarePath", "/local/path/to/file", "/local/path/to/file"},
		{"Empty", "", ""},
		{"TrailingSlash", "pelican:///foo/bar/", "/foo/bar"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractPath(tt.input))
		})
	}
}

func TestPathUnderPrefix(t *testing.T) {
	tests := []struct {
		name     string
		p        string
		prefix   string
		expected bool
	}{
		{"ExactMatch", "/origin/data", "/origin/data", true},
		{"Nested", "/origin/data/subdir/file.txt", "/origin/data", true},
		{"TrailingSlash", "/origin/data/", "/origin/data", true},
		{"NoMatch", "/other/data/file.txt", "/origin/data", false},
		{"PartialComponent", "/origin/database", "/origin/data", false},
		{"PrefixTrailingSlash", "/origin/data/file.txt", "/origin/data/", true},
		{"Root", "/anything", "/", true},
		{"EmptyPath", "", "/origin/data", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, pathUnderPrefix(tt.p, tt.prefix))
		})
	}
}

func TestTransferMatchesPrefixes(t *testing.T) {
	prefixes := []string{"/origin/data", "/origin/public"}

	t.Run("SourceMatches", func(t *testing.T) {
		item := TransferItem{Source: "pelican:///origin/data/file.txt", Destination: "/tmp/file.txt"}
		assert.True(t, transferMatchesPrefixes(item, prefixes))
	})

	t.Run("DestMatches", func(t *testing.T) {
		item := TransferItem{Source: "/tmp/file.txt", Destination: "pelican:///origin/public/out.txt"}
		assert.True(t, transferMatchesPrefixes(item, prefixes))
	})

	t.Run("NeitherMatches", func(t *testing.T) {
		item := TransferItem{Source: "/tmp/file.txt", Destination: "/other/out.txt"}
		assert.False(t, transferMatchesPrefixes(item, prefixes))
	})

	t.Run("BothMatch", func(t *testing.T) {
		item := TransferItem{Source: "pelican:///origin/data/a", Destination: "pelican:///origin/public/b"}
		assert.True(t, transferMatchesPrefixes(item, prefixes))
	})

	t.Run("EmptyPrefixes", func(t *testing.T) {
		item := TransferItem{Source: "pelican:///origin/data/file.txt", Destination: "/tmp/file.txt"}
		assert.False(t, transferMatchesPrefixes(item, nil))
		assert.False(t, transferMatchesPrefixes(item, []string{}))
	})
}
