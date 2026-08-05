//go:build server

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
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// setupIntrospectTest isolates the package-level flag variables and viper
// state that `pelican-server origin introspect` reads, so each subtest starts clean
// and leaves nothing behind for the rest of the cmd package.
func setupIntrospectTest(t *testing.T) {
	t.Helper()

	origServer, origToken, origJSON := originIntrospectServer, originIntrospectToken, originIntrospectJSON
	t.Cleanup(func() {
		originIntrospectServer, originIntrospectToken, originIntrospectJSON = origServer, origToken, origJSON
		server_utils.ResetTestState()
	})

	server_utils.ResetTestState()
	originIntrospectServer, originIntrospectToken, originIntrospectJSON = "", "", false
	require.NoError(t, param.ConfigBase.Set(t.TempDir()))
}

// introspectTestCmd is a stand-in for the real cobra command; introspectGet
// only ever uses its Context.
func introspectTestCmd() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	return cmd
}

// captureAuthOrigin stands up a fake origin that records the Authorization
// header it was handed and answers every request with a valid usage payload.
func captureAuthOrigin(t *testing.T, authHeader *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*authHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"backend":"pstore","usedBytes":42,"capacityBytes":100}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestIntrospectUsesTokenFile confirms that --token is treated as a path to a
// file holding a token (the convention shared with `pelican cache introspect`
// and `pelican downtime`), and that the file's contents are what reaches the
// origin.
func TestIntrospectUsesTokenFile(t *testing.T) {
	setupIntrospectTest(t)

	var seen string
	srv := captureAuthOrigin(t, &seen)

	tokenFile := filepath.Join(t.TempDir(), "admin-token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("a-token-from-a-file\n"), 0600))

	originIntrospectServer = srv.URL
	originIntrospectToken = tokenFile

	var result storageUsageResult
	require.NoError(t, introspectGet(introspectTestCmd(), "/usage", nil, &result))

	// The trailing newline must be trimmed, and the file's contents used
	// verbatim -- not interpreted as a literal token, and not replaced by a
	// freshly minted one.
	assert.Equal(t, "Bearer a-token-from-a-file", seen)
	assert.Equal(t, int64(42), result.UsedBytes)
}

// TestIntrospectMissingTokenFileErrors confirms that a --token pointing at
// nothing is reported as an error, rather than being treated as a literal
// token or quietly falling back to minting one.
func TestIntrospectMissingTokenFileErrors(t *testing.T) {
	setupIntrospectTest(t)

	var seen string
	srv := captureAuthOrigin(t, &seen)

	originIntrospectServer = srv.URL
	originIntrospectToken = filepath.Join(t.TempDir(), "does-not-exist")

	var result storageUsageResult
	err := introspectGet(introspectTestCmd(), "/usage", nil, &result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to obtain an administrator token")
	assert.Contains(t, err.Error(), "Token file not found")
	// The request must never have been made.
	assert.Empty(t, seen)
}

// TestIntrospectMintsAdminTokenWithoutFile is the point of the change: with no
// --token at all, the command mints its own short-lived admin token from the
// local issuer key. The minted token is checked against the same conditions
// web_ui.AuthHandler and web_ui.AdminAuthHandler impose on the origin side --
// signed by the issuer key, issuer pinned to the local issuer URL, and a
// subject that maps to an administrator.
func TestIntrospectMintsAdminTokenWithoutFile(t *testing.T) {
	setupIntrospectTest(t)

	var seen string
	srv := captureAuthOrigin(t, &seen)

	// A key directory with no key in it: the issuer key is generated on
	// first use, which is what an origin host has.
	require.NoError(t, param.IssuerKeysDirectory.Set(filepath.Join(t.TempDir(), "issuer-keys")))
	require.NoError(t, param.Server_ExternalWebUrl.Set(srv.URL))

	originIntrospectServer = srv.URL
	originIntrospectToken = ""

	var result storageUsageResult
	require.NoError(t, introspectGet(introspectTestCmd(), "/usage", nil, &result))

	raw, found := strings.CutPrefix(seen, "Bearer ")
	require.True(t, found, "no bearer token was sent; got %q", seen)

	// Signature must verify against this server's public JWKS -- the
	// "private key is available" half of the fallback.
	jwks, err := config.GetIssuerPublicJWKS()
	require.NoError(t, err)
	tok, err := token.VerifyWithKeysetStrict(raw, jwks)
	require.NoError(t, err)

	// web_ui.extractUserFromBearerToken pins the issuer to
	// config.GetLocalIssuerUrl() before trusting the subject.
	assert.Equal(t, config.GetLocalIssuerUrl(), tok.Issuer())

	// web_ui.CheckAdmin grants server.admin to the built-in "admin"
	// username, which is where this token's admin authority comes from.
	assert.Equal(t, "admin", tok.Subject())

	scope, ok := tok.Get("scope")
	require.True(t, ok, "minted token carries no scope claim")
	assert.Contains(t, scope, token_scopes.WebUi_Access.String())

	assert.Equal(t, int64(42), result.UsedBytes)
}

// TestIntrospectTokenFlagIsAFileLocation guards the documented contract: the
// flag is a path, it has the same `-t` shorthand as the sibling admin
// commands, and no environment variable is advertised as a source of tokens.
func TestIntrospectTokenFlagIsAFileLocation(t *testing.T) {
	flag := originIntrospectCmd.PersistentFlags().Lookup("token")
	require.NotNil(t, flag)
	assert.Equal(t, "t", flag.Shorthand)
	assert.Contains(t, flag.Usage, "file")
	assert.NotContains(t, flag.Usage, "PELICAN_ADMIN_TOKEN")
	assert.NotContains(t, originIntrospectCmd.Long, "PELICAN_ADMIN_TOKEN")
}
