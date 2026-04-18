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
	tokenConfig.AddScopes(readScope)

	tkn, err := tokenConfig.CreateToken()
	require.NoError(t, err)
	return tkn
}

// TestTPCWithPOSIXv2 verifies that DoCopy (third-party copy) works end-to-end
// against a POSIXv2 origin, exercising the TPC COPY handler.
func TestTPCWithPOSIXv2(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

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

	type tpcTestCase struct {
		name string
		// content is the data written to the source file.
		content string
		// copyOpts are passed to client.DoCopy.
		copyOpts func(t *testing.T) []client.TransferOption
		// seedVia controls how the source file is created:
		// "file" writes directly to disk, "put" uploads via DoPut.
		seedVia string
		// expectErr, if true, means DoCopy should return an error.
		expectErr bool
		// verifyDest, if true, downloads the destination and compares content.
		verifyDest bool
		// verifyAbsent, if true, asserts the destination file was NOT created.
		verifyAbsent bool
	}

	tests := []tpcTestCase{
		{
			name:    "CopyWithinExport",
			content: "hello from the POSIXv2 TPC E2E test",
			copyOpts: func(_ *testing.T) []client.TransferOption {
				return []client.TransferOption{client.WithToken(tkn), client.WithSourceToken(tkn)}
			},
			seedVia:    "file",
			verifyDest: true,
		},
		{
			name:    "CopyFailsWithNoToken",
			content: "secret",
			copyOpts: func(_ *testing.T) []client.TransferOption {
				return []client.TransferOption{client.WithAcquireToken(false)}
			},
			seedVia:   "file",
			expectErr: true,
		},
		{
			name:    "CopyFailsWithReadOnlyToken",
			content: "readonly-content",
			copyOpts: func(t *testing.T) []client.TransferOption {
				readTkn := getReadOnlyToken(t)
				return []client.TransferOption{
					client.WithToken(readTkn), client.WithSourceToken(readTkn),
					client.WithAcquireToken(false),
				}
			},
			seedVia:      "file",
			expectErr:    true,
			verifyAbsent: true,
		},
		{
			name:    "CopyFromPut",
			content: "uploaded then copied via TPC",
			copyOpts: func(_ *testing.T) []client.TransferOption {
				return []client.TransferOption{client.WithToken(tkn), client.WithSourceToken(tkn)}
			},
			seedVia:    "put",
			verifyDest: true,
		},
	}

	for _, export := range fed.Exports {
		for _, tc := range tests {
			tc := tc
			t.Run(tc.name+"_"+export.FederationPrefix, func(t *testing.T) {
				subdir := fmt.Sprintf("tpc_%s", tc.name)
				sourceURL := fmt.Sprintf("pelican://%s:%s%s/%s/source.txt", host, port, export.FederationPrefix, subdir)
				destURL := fmt.Sprintf("pelican://%s:%s%s/%s/dest.txt", host, port, export.FederationPrefix, subdir)

				// Seed the source file.
				switch tc.seedVia {
				case "file":
					srcDir := filepath.Join(export.StoragePrefix, subdir)
					require.NoError(t, os.MkdirAll(srcDir, 0755))
					srcFile := filepath.Join(srcDir, "source.txt")
					require.NoError(t, os.WriteFile(srcFile, []byte(tc.content), 0644))
					test_utils.ChownToDaemon(t, srcDir, srcFile)
				case "put":
					tmpFile, err := os.CreateTemp(t.TempDir(), "upload")
					require.NoError(t, err)
					_, err = tmpFile.WriteString(tc.content)
					require.NoError(t, err)
					tmpFile.Close()
					_, err = client.DoPut(fed.Ctx, tmpFile.Name(), sourceURL, false, client.WithToken(tkn))
					require.NoError(t, err)
				default:
					t.Fatalf("unknown seedVia %q", tc.seedVia)
				}

				// Execute the third-party copy.
				opts := tc.copyOpts(t)
				transferResults, err := client.DoCopy(fed.Ctx, sourceURL, destURL, false, opts...)
				if tc.expectErr {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					require.Len(t, transferResults, 1)
					assert.Equal(t, int64(len(tc.content)), transferResults[0].TransferredBytes)
				}

				// Verify the destination file contents via download.
				if tc.verifyDest {
					localDir := t.TempDir()
					downloadResults, err := client.DoGet(fed.Ctx, destURL, localDir, false, client.WithToken(tkn))
					require.NoError(t, err)
					require.Len(t, downloadResults, 1)
					assert.Equal(t, int64(len(tc.content)), downloadResults[0].TransferredBytes)

					downloaded, err := os.ReadFile(filepath.Join(localDir, "dest.txt"))
					require.NoError(t, err)
					assert.Equal(t, tc.content, string(downloaded))
				}

				// Verify the destination was NOT created (e.g. auth failure).
				if tc.verifyAbsent {
					destDir := filepath.Join(export.StoragePrefix, subdir)
					_, statErr := os.Stat(filepath.Join(destDir, "dest.txt"))
					assert.True(t, os.IsNotExist(statErr), "destination file should not exist after rejected COPY")
				}
			})
		}
	}
}
