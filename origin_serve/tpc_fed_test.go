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

package origin_serve_test

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

var (
	//go:embed resources/posixv2-auth.yml
	posixv2AuthCfg string
)

// getTestToken generates a short-lived WLCG token with read, create, and modify
// scopes rooted at "/".  It writes the token to a temp file and returns both
// the file handle and the raw token string.
func getTestToken(t *testing.T) (tokenFile *os.File, tkn string) {
	t.Helper()
	require.NoError(t, param.IssuerKeysDirectory.Set(t.TempDir()))

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "origin"
	tokenConfig.AddAudienceAny()

	readScope, err := token_scopes.Wlcg_Storage_Read.Path("/")
	require.NoError(t, err)
	createScope, err := token_scopes.Wlcg_Storage_Create.Path("/")
	require.NoError(t, err)
	modScope, err := token_scopes.Wlcg_Storage_Modify.Path("/")
	require.NoError(t, err)
	tokenConfig.AddScopes(readScope, createScope, modScope)

	tkn, err = tokenConfig.CreateToken()
	require.NoError(t, err)

	tokenFile, err = os.CreateTemp(t.TempDir(), "token")
	require.NoError(t, err)
	_, err = tokenFile.WriteString(tkn)
	require.NoError(t, err)
	tokenFile.Close()
	return
}

// getReadOnlyToken generates a short-lived WLCG token with only storage.read
// scope. This is insufficient for COPY which requires storage.create.
func getReadOnlyToken(t *testing.T) string {
	t.Helper()

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "origin"
	tokenConfig.AddAudienceAny()

	readScope, err := token_scopes.Wlcg_Storage_Read.Path("/")
	require.NoError(t, err)
	tokenConfig.AddScopes(readScope)

	tkn, err := tokenConfig.CreateToken()
	require.NoError(t, err)
	return tkn
}

// TestTPCWithPOSIXv2 verifies that DoCopy (third-party copy) works end-to-end
// against a POSIXv2 origin, exercising the TPC COPY handler.
func TestTPCWithPOSIXv2(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	fed := fed_test_utils.NewFedTest(t, posixv2AuthCfg)

	// Disable SSRF protection for federation tests where the origin
	// connects to itself via a local hostname that resolves to a
	// private/link-local address.  The SSRF dialer is thoroughly
	// tested in config/ssrf_transport_test.go.
	require.NoError(t, param.Server_SSRFProtection_Disabled.Set(true))
	config.ResetSSRFTransportForTest()

	tokenFile, tkn := getTestToken(t)
	defer os.Remove(tokenFile.Name())

	require.NoError(t, param.Logging_DisableProgressBars.Set(true))

	host := param.Server_Hostname.GetString()
	port := strconv.Itoa(param.Server_WebPort.GetInt())

	for _, export := range fed.Exports {
		t.Run("CopyWithinExport_"+export.FederationPrefix, func(t *testing.T) {
			testContent := "hello from the POSIXv2 TPC E2E test"

			// Seed a source file in the origin's storage directory
			srcDir := filepath.Join(export.StoragePrefix, "tpc_e2e")
			require.NoError(t, os.MkdirAll(srcDir, 0755))
			srcFile := filepath.Join(srcDir, "source.txt")
			require.NoError(t, os.WriteFile(srcFile, []byte(testContent), 0644))
			test_utils.ChownToDaemon(t, srcDir, srcFile)

			sourceURL := fmt.Sprintf("pelican://%s:%s%s/tpc_e2e/source.txt", host, port, export.FederationPrefix)
			destURL := fmt.Sprintf("pelican://%s:%s%s/tpc_e2e/dest.txt", host, port, export.FederationPrefix)

			// Execute the third-party copy
			transferResults, err := client.DoCopy(fed.Ctx, sourceURL, destURL, false,
				client.WithToken(tkn), client.WithSourceToken(tkn))
			require.NoError(t, err)
			require.Len(t, transferResults, 1)
			assert.Equal(t, int64(len(testContent)), transferResults[0].TransferredBytes)

			// Verify the destination file by downloading it
			localDir := t.TempDir()
			downloadResults, err := client.DoGet(fed.Ctx, destURL, localDir, false, client.WithToken(tkn))
			require.NoError(t, err)
			require.Len(t, downloadResults, 1)
			assert.Equal(t, int64(len(testContent)), downloadResults[0].TransferredBytes)

			downloaded, err := os.ReadFile(filepath.Join(localDir, "dest.txt"))
			require.NoError(t, err)
			assert.Equal(t, testContent, string(downloaded))
		})

		t.Run("CopyFailsWithNoToken_"+export.FederationPrefix, func(t *testing.T) {
			// Seed a source file so the copy has something to read
			noTokDir := filepath.Join(export.StoragePrefix, "tpc_notoken")
			require.NoError(t, os.MkdirAll(noTokDir, 0755))
			noTokFile := filepath.Join(noTokDir, "source.txt")
			require.NoError(t, os.WriteFile(noTokFile, []byte("secret"), 0644))
			test_utils.ChownToDaemon(t, noTokDir, noTokFile)

			sourceURL := fmt.Sprintf("pelican://%s:%s%s/tpc_notoken/source.txt", host, port, export.FederationPrefix)
			destURL := fmt.Sprintf("pelican://%s:%s%s/tpc_notoken/dest.txt", host, port, export.FederationPrefix)

			// DoCopy with no token (and auto-acquire disabled) should fail because the namespace requires auth
			_, err := client.DoCopy(fed.Ctx, sourceURL, destURL, false, client.WithAcquireToken(false))
			require.Error(t, err)
		})

		t.Run("CopyFailsWithReadOnlyToken_"+export.FederationPrefix, func(t *testing.T) {
			// Seed a source file so the copy has something to read
			roDir := filepath.Join(export.StoragePrefix, "tpc_readonly")
			require.NoError(t, os.MkdirAll(roDir, 0755))
			roFile := filepath.Join(roDir, "source.txt")
			require.NoError(t, os.WriteFile(roFile, []byte("readonly-content"), 0644))
			test_utils.ChownToDaemon(t, roDir, roFile)

			readTkn := getReadOnlyToken(t)
			sourceURL := fmt.Sprintf("pelican://%s:%s%s/tpc_readonly/source.txt", host, port, export.FederationPrefix)
			destURL := fmt.Sprintf("pelican://%s:%s%s/tpc_readonly/dest.txt", host, port, export.FederationPrefix)

			// A storage.read-only token should be rejected for COPY (requires storage.create)
			_, err := client.DoCopy(fed.Ctx, sourceURL, destURL, false,
				client.WithToken(readTkn), client.WithSourceToken(readTkn), client.WithAcquireToken(false))
			require.Error(t, err)

			// Verify the destination was NOT created
			_, statErr := os.Stat(filepath.Join(roDir, "dest.txt"))
			assert.True(t, os.IsNotExist(statErr), "destination file should not exist after rejected COPY")
		})

		t.Run("CopyFromPut_"+export.FederationPrefix, func(t *testing.T) {
			testContent := "uploaded then copied via TPC"

			// Upload a file via DoPut first
			tmpFile, err := os.CreateTemp(t.TempDir(), "upload")
			require.NoError(t, err)
			_, err = tmpFile.WriteString(testContent)
			require.NoError(t, err)
			tmpFile.Close()

			uploadURL := fmt.Sprintf("pelican://%s:%s%s/put_then_copy/source.txt", host, port, export.FederationPrefix)
			_, err = client.DoPut(fed.Ctx, tmpFile.Name(), uploadURL, false, client.WithToken(tkn))
			require.NoError(t, err)

			destURL := fmt.Sprintf("pelican://%s:%s%s/put_then_copy/dest.txt", host, port, export.FederationPrefix)

			// Now TPC from the uploaded file to a new destination
			copyResults, err := client.DoCopy(fed.Ctx, uploadURL, destURL, false,
				client.WithToken(tkn), client.WithSourceToken(tkn))
			require.NoError(t, err)
			require.Len(t, copyResults, 1)
			assert.Equal(t, int64(len(testContent)), copyResults[0].TransferredBytes)

			// Download the copied file and verify contents
			localDir := t.TempDir()
			_, err = client.DoGet(fed.Ctx, destURL, localDir, false, client.WithToken(tkn))
			require.NoError(t, err)

			downloaded, err := os.ReadFile(filepath.Join(localDir, "dest.txt"))
			require.NoError(t, err)
			assert.Equal(t, testContent, string(downloaded))
		})
	}
}
