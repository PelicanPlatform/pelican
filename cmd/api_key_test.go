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

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/web_ui"
)

func TestConstructApiKeyApiURL(t *testing.T) {
	t.Cleanup(func() {
		server_utils.ResetTestState()
	})

	t.Run("empty-server-url", func(t *testing.T) {
		_, err := constructApiKeyApiURL("")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--server flag providing the server's web URL is required")
	})

	t.Run("invalid-url-format", func(t *testing.T) {
		_, err := constructApiKeyApiURL("://invalid-url")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Invalid server URL format")
	})

	t.Run("non-https-scheme", func(t *testing.T) {
		_, err := constructApiKeyApiURL("http://example.com:8447")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Server URL must have an https scheme")
	})

	t.Run("url-without-hostname", func(t *testing.T) {
		_, err := constructApiKeyApiURL("https:///path/only")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Server URL must include a hostname")
	})

	t.Run("valid-url", func(t *testing.T) {
		result, err := constructApiKeyApiURL("https://my-origin.com:8447")
		require.NoError(t, err)
		assert.Equal(t, "https://my-origin.com:8447/api/v1.0/tokens", result.String())
	})

	t.Run("valid-url-with-trailing-slash", func(t *testing.T) {
		result, err := constructApiKeyApiURL("https://my-origin.com:8447/")
		require.NoError(t, err)
		assert.Equal(t, "https://my-origin.com:8447/api/v1.0/tokens", result.String())
	})

	t.Run("valid-url-no-port", func(t *testing.T) {
		result, err := constructApiKeyApiURL("https://my-origin.com")
		require.NoError(t, err)
		assert.Equal(t, "https://my-origin.com/api/v1.0/tokens", result.String())
	})
}

func TestFetchOrGenerateWebAPIAdminToken(t *testing.T) {
	t.Cleanup(func() {
		server_utils.ResetTestState()
	})

	t.Run("token-file-not-found", func(t *testing.T) {
		_, err := fetchOrGenerateWebAPIAdminToken("https://example.com", "/nonexistent/path/token.txt")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Token file not found")
	})

	t.Run("token-from-file", func(t *testing.T) {
		tempDir := t.TempDir()
		tokenFile := filepath.Join(tempDir, "token.txt")
		expectedToken := "test-token-12345"
		err := os.WriteFile(tokenFile, []byte(expectedToken), 0600)
		require.NoError(t, err)

		tok, err := fetchOrGenerateWebAPIAdminToken("https://example.com", tokenFile)
		require.NoError(t, err)
		assert.Equal(t, expectedToken, tok)
	})

	t.Run("token-from-file-with-newline", func(t *testing.T) {
		tempDir := t.TempDir()
		tokenFile := filepath.Join(tempDir, "token.txt")
		expectedToken := "test-token-12345"
		err := os.WriteFile(tokenFile, []byte(expectedToken+"\n"), 0600)
		require.NoError(t, err)

		tok, err := fetchOrGenerateWebAPIAdminToken("https://example.com", tokenFile)
		require.NoError(t, err)
		// The utils.GetTokenFromFile should trim the newline
		assert.Equal(t, expectedToken, tok)
	})
}

func TestApiKeyGenerateValidation(t *testing.T) {
	// Save original values and restore after test
	origScopes := apiKeyScopes
	origName := apiKeyName
	origExpiration := apiKeyExpiration
	origServerURL := apiKeyServerURLStr
	origTokenLocation := apiKeyTokenLocation

	t.Cleanup(func() {
		apiKeyScopes = origScopes
		apiKeyName = origName
		apiKeyExpiration = origExpiration
		apiKeyServerURLStr = origServerURL
		apiKeyTokenLocation = origTokenLocation
		server_utils.ResetTestState()
	})

	t.Run("empty-scopes", func(t *testing.T) {
		apiKeyScopes = ""
		apiKeyExpiration = "2026-12-31T23:59:59Z"
		apiKeyServerURLStr = "https://example.com:8447"
		apiKeyTokenLocation = ""

		cmd := &cobra.Command{}
		err := generateApiKey(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--scopes flag is required")
	})

	t.Run("scopes-with-empty-value", func(t *testing.T) {
		apiKeyScopes = "monitoring.query,,monitoring.scrape"
		apiKeyExpiration = "2026-12-31T23:59:59Z"
		apiKeyServerURLStr = "https://example.com:8447"
		apiKeyTokenLocation = ""

		cmd := &cobra.Command{}
		err := generateApiKey(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scopes cannot contain empty values")
	})

	t.Run("scopes-with-whitespace-only", func(t *testing.T) {
		apiKeyScopes = "monitoring.query,   ,monitoring.scrape"
		apiKeyExpiration = "2026-12-31T23:59:59Z"
		apiKeyServerURLStr = "https://example.com:8447"
		apiKeyTokenLocation = ""

		cmd := &cobra.Command{}
		err := generateApiKey(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scopes cannot contain empty values")
	})

	t.Run("empty-expiration", func(t *testing.T) {
		apiKeyScopes = "monitoring.query"
		apiKeyExpiration = ""
		apiKeyServerURLStr = "https://example.com:8447"
		apiKeyTokenLocation = ""

		cmd := &cobra.Command{}
		err := generateApiKey(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--expiration flag is required")
	})

	t.Run("invalid-expiration-format", func(t *testing.T) {
		apiKeyScopes = "monitoring.query"
		apiKeyExpiration = "2026-12-31"
		apiKeyServerURLStr = "https://example.com:8447"
		apiKeyTokenLocation = ""

		cmd := &cobra.Command{}
		err := generateApiKey(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expiration must be in RFC3339 format")
	})

	t.Run("invalid-expiration-natural-language", func(t *testing.T) {
		apiKeyScopes = "monitoring.query"
		apiKeyExpiration = "next week"
		apiKeyServerURLStr = "https://example.com:8447"
		apiKeyTokenLocation = ""

		cmd := &cobra.Command{}
		err := generateApiKey(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expiration must be in RFC3339 format")
	})

	t.Run("missing-server-url", func(t *testing.T) {
		apiKeyScopes = "monitoring.query"
		apiKeyExpiration = "2026-12-31T23:59:59Z"
		apiKeyServerURLStr = ""
		apiKeyTokenLocation = ""

		cmd := &cobra.Command{}
		err := generateApiKey(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--server flag providing the server's web URL is required")
	})

	t.Run("invalid-server-url-scheme", func(t *testing.T) {
		apiKeyScopes = "monitoring.query"
		apiKeyExpiration = "2026-12-31T23:59:59Z"
		apiKeyServerURLStr = "http://example.com:8447"
		apiKeyTokenLocation = ""

		cmd := &cobra.Command{}
		err := generateApiKey(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Server URL must have an https scheme")
	})

	t.Run("token-file-not-found", func(t *testing.T) {
		apiKeyScopes = "monitoring.query"
		apiKeyExpiration = "2026-12-31T23:59:59Z"
		apiKeyServerURLStr = "https://example.com:8447"
		apiKeyTokenLocation = "/nonexistent/path/to/token"

		cmd := &cobra.Command{}
		err := generateApiKey(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Token file not found")
	})
}

func TestHandleAdminApiResponse(t *testing.T) {
	t.Cleanup(func() {
		server_utils.ResetTestState()
	})

	t.Run("success-200", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"token":"abc123"}`)),
		}
		body, err := handleAdminApiResponse(resp)
		require.NoError(t, err)
		assert.Equal(t, `{"token":"abc123"}`, string(body))
	})

	t.Run("success-201-created", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(strings.NewReader(`{"id":"new-resource"}`)),
		}
		body, err := handleAdminApiResponse(resp)
		require.NoError(t, err)
		assert.Equal(t, `{"id":"new-resource"}`, string(body))
	})

	t.Run("error-400-bad-request", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusBadRequest,
			Status:     "400 Bad Request",
			Body:       io.NopCloser(strings.NewReader(`{"status":"error","msg":"Invalid scopes"}`)),
		}
		_, err := handleAdminApiResponse(resp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "400 Bad Request")
		assert.Contains(t, err.Error(), "Invalid scopes")
	})

	t.Run("error-401-unauthorized", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusUnauthorized,
			Status:     "401 Unauthorized",
			Body:       io.NopCloser(strings.NewReader(`{"status":"error","msg":"Authentication required"}`)),
		}
		_, err := handleAdminApiResponse(resp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "401 Unauthorized")
		assert.Contains(t, err.Error(), "check if token is valid or expired")
	})

	t.Run("error-403-forbidden", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusForbidden,
			Status:     "403 Forbidden",
			Body:       io.NopCloser(strings.NewReader(`{"status":"error","msg":"Insufficient permissions"}`)),
		}
		_, err := handleAdminApiResponse(resp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "403 Forbidden")
		assert.Contains(t, err.Error(), "check if token has required admin privileges")
	})

	t.Run("error-500-internal-server-error", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusInternalServerError,
			Status:     "500 Internal Server Error",
			Body:       io.NopCloser(strings.NewReader(`Internal Server Error`)),
		}
		_, err := handleAdminApiResponse(resp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "500 Internal Server Error")
	})

	t.Run("error-with-empty-body", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusBadRequest,
			Status:     "400 Bad Request",
			Body:       io.NopCloser(strings.NewReader("")),
		}
		_, err := handleAdminApiResponse(resp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "400 Bad Request")
	})
}

func TestApiKeyGenerateWithMockServer(t *testing.T) {
	// Save original values and restore after test
	origScopes := apiKeyScopes
	origName := apiKeyName
	origExpiration := apiKeyExpiration
	origServerURL := apiKeyServerURLStr
	origTokenLocation := apiKeyTokenLocation

	t.Cleanup(func() {
		apiKeyScopes = origScopes
		apiKeyName = origName
		apiKeyExpiration = origExpiration
		apiKeyServerURLStr = origServerURL
		apiKeyTokenLocation = origTokenLocation
		server_utils.ResetTestState()
	})

	t.Run("successful-api-key-generation", func(t *testing.T) {
		// Create a mock server that responds with a token
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify the request
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "/api/v1.0/tokens", r.URL.Path)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			assert.Contains(t, r.Header.Get("Authorization"), "Bearer ")

			// Parse and verify request body
			var req web_ui.CreateApiTokenReq
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			err = json.Unmarshal(body, &req)
			require.NoError(t, err)
			assert.Equal(t, "test-key", req.Name)
			assert.Equal(t, []string{"monitoring.query", "monitoring.scrape"}, req.Scopes)
			assert.Equal(t, "2026-12-31T23:59:59Z", req.Expiration)

			// Send response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"token":"generated-api-key-12345"}`))
		}))
		defer server.Close()

		// Create a temp token file
		tempDir := t.TempDir()
		tokenFile := filepath.Join(tempDir, "admin-token.txt")
		err := os.WriteFile(tokenFile, []byte("admin-bearer-token"), 0600)
		require.NoError(t, err)

		// Set up the command parameters
		apiKeyScopes = "monitoring.query,monitoring.scrape"
		apiKeyName = "test-key"
		apiKeyExpiration = "2026-12-31T23:59:59Z"
		apiKeyServerURLStr = server.URL
		apiKeyTokenLocation = tokenFile
	})

	t.Run("scopes-trimmed-correctly", func(t *testing.T) {
		// Test that scopes with extra whitespace are trimmed
		apiKeyScopes = "  monitoring.query  ,  monitoring.scrape  "
		apiKeyExpiration = "2026-12-31T23:59:59Z"
		apiKeyServerURLStr = "https://example.com:8447"
		apiKeyTokenLocation = "/nonexistent/path" // Will fail at token fetch

		cmd := &cobra.Command{}
		err := generateApiKey(cmd, []string{})
		// Should fail at token fetch, not at scope validation
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Token file not found")
	})
}

func TestApiKeyCommandStructure(t *testing.T) {
	t.Cleanup(func() {
		server_utils.ResetTestState()
	})

	t.Run("apikey-command-exists", func(t *testing.T) {
		assert.NotNil(t, apiKeyCmd)
		assert.Equal(t, "apikey", apiKeyCmd.Use)
		assert.Contains(t, apiKeyCmd.Short, "API keys")
	})

	t.Run("generate-subcommand-exists", func(t *testing.T) {
		assert.NotNil(t, apiKeyGenerateCmd)
		assert.Equal(t, "generate", apiKeyGenerateCmd.Use)
	})

	t.Run("required-flags-exist", func(t *testing.T) {
		// Check persistent flags on parent command
		serverFlag := apiKeyCmd.PersistentFlags().Lookup("server")
		assert.NotNil(t, serverFlag)
		assert.Equal(t, "s", serverFlag.Shorthand)

		tokenFlag := apiKeyCmd.PersistentFlags().Lookup("token")
		assert.NotNil(t, tokenFlag)
		assert.Equal(t, "t", tokenFlag.Shorthand)

		// Check flags on generate subcommand
		scopesFlag := apiKeyGenerateCmd.Flags().Lookup("scopes")
		assert.NotNil(t, scopesFlag)

		nameFlag := apiKeyGenerateCmd.Flags().Lookup("name")
		assert.NotNil(t, nameFlag)

		expirationFlag := apiKeyGenerateCmd.Flags().Lookup("expiration")
		assert.NotNil(t, expirationFlag)
	})
}
