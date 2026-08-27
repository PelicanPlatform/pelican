//go:build client || server

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
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
)

func TestResolveTokenOptions(t *testing.T) {
	newCmd := func(flags map[string]string) *cobra.Command {
		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().StringP("token", "t", "", "")
		cmd.Flags().String("source-token", "", "")
		cmd.Flags().String("dest-token", "", "")
		for k, v := range flags {
			_ = cmd.Flags().Set(k, v)
		}
		return cmd
	}

	t.Run("NoFlags", func(t *testing.T) {
		opts := resolveTokenOptions(newCmd(nil))
		assert.Empty(t, opts)
	})

	t.Run("TokenOnly", func(t *testing.T) {
		opts := resolveTokenOptions(newCmd(map[string]string{"token": "/tmp/tok"}))
		assert.Len(t, opts, 1)
	})

	t.Run("SourceTokenOnly", func(t *testing.T) {
		opts := resolveTokenOptions(newCmd(map[string]string{"source-token": "/tmp/src"}))
		assert.Len(t, opts, 1)
	})

	t.Run("DestTokenOnly", func(t *testing.T) {
		opts := resolveTokenOptions(newCmd(map[string]string{"dest-token": "/tmp/dst"}))
		assert.Len(t, opts, 1)
	})

	t.Run("AllThreeFlags", func(t *testing.T) {
		opts := resolveTokenOptions(newCmd(map[string]string{
			"token":        "/tmp/tok",
			"source-token": "/tmp/src",
			"dest-token":   "/tmp/dst",
		}))
		// All three produce options; the specific overrides are resolved by the client library
		assert.Len(t, opts, 3)
	})

	t.Run("TokenAndSourceToken", func(t *testing.T) {
		opts := resolveTokenOptions(newCmd(map[string]string{
			"token":        "/tmp/tok",
			"source-token": "/tmp/src",
		}))
		assert.Len(t, opts, 2)
	})
}

// resetIssuerTestState gives a subtest a clean config with a usable issuer-key
// directory, and puts the global config back the way it found it.
func resetIssuerTestState(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		mintedAdminTokenIssuer = ""
		server_utils.ResetTestState()
	})
	mintedAdminTokenIssuer = ""
	server_utils.ResetTestState()
	require.NoError(t, param.ConfigBase.Set(t.TempDir()))
	// An empty key directory: the issuer key is generated on first use, which
	// is the state of a server host that has not minted anything yet.
	require.NoError(t, param.IssuerKeysDirectory.Set(filepath.Join(t.TempDir(), "issuer-keys")))
}

// mintedIssuer returns the `iss` of a freshly auto-generated admin token.
func mintedIssuer(t *testing.T, serverURL string) string {
	t.Helper()
	raw, err := fetchOrGenerateWebAPIAdminToken(serverURL, "")
	require.NoError(t, err)
	tok, err := token.UnsafeParseClaims(raw)
	require.NoError(t, err)
	return tok.Issuer()
}

// TestWebAPIAdminTokenIssuerMatchesVerifier pins the minting side of the
// auto-generated web-API admin token to the verifying side.
//
// web_ui.extractUserFromBearerToken (reached from web_ui.AuthHandler) accepts a
// bearer token only when its issuer is exactly config.GetLocalIssuerUrl().  The
// assertions below therefore compare against GetLocalIssuerUrl() rather than
// any literal URL, so that if either side changes its notion of the local
// issuer the test fails instead of quietly re-introducing the 401.
func TestWebAPIAdminTokenIssuerMatchesVerifier(t *testing.T) {
	t.Run("StandaloneServer", func(t *testing.T) {
		resetIssuerTestState(t)
		require.NoError(t, param.Server_ExternalWebUrl.Set("https://standalone.example.com:8444"))

		assert.Equal(t, config.GetLocalIssuerUrl(), webAPIAdminTokenIssuer("https://dialed.example.com:8444"))
		assert.Equal(t, config.GetLocalIssuerUrl(), mintedIssuer(t, "https://dialed.example.com:8444"))
	})

	t.Run("IgnoresServerIssuerUrl", func(t *testing.T) {
		// The original bug: the token was minted from
		// config.GetServerIssuerURL(), which honors Server.IssuerUrl, while the
		// verifier pins config.GetLocalIssuerUrl(), which does not.
		resetIssuerTestState(t)
		require.NoError(t, param.Server_ExternalWebUrl.Set("https://server.example.com:8444"))
		require.NoError(t, param.Server_IssuerUrl.Set("https://issuer.example.com"))

		serverIssuer, err := config.GetServerIssuerURL()
		require.NoError(t, err)
		require.NotEqual(t, config.GetLocalIssuerUrl(), serverIssuer,
			"test is vacuous unless the two issuer notions actually differ")

		minted := mintedIssuer(t, "https://server.example.com:8444")
		assert.Equal(t, config.GetLocalIssuerUrl(), minted)
		assert.NotEqual(t, serverIssuer, minted)
	})

	t.Run("NoWebUrlFallsBackToDialedServer", func(t *testing.T) {
		// A client-only configuration has no Server.ExternalWebUrl; the URL the
		// operator pointed us at is the best available stand-in, and is what
		// the remote server's own ExternalWebUrl normally is.
		resetIssuerTestState(t)
		require.Empty(t, param.Server_ExternalWebUrl.GetString())

		assert.Equal(t, "https://remote.example.com:8444", webAPIAdminTokenIssuer("https://remote.example.com:8444"))
	})

	t.Run("NoIssuerAtAllIsAnError", func(t *testing.T) {
		resetIssuerTestState(t)
		_, err := fetchOrGenerateWebAPIAdminToken("", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Cannot determine the issuer")
	})
}

// TestWebAPIAdminTokenIssuerColocatedOriginAndDirector covers the topology the
// bug was actually reported on: an origin and a director in one process, where
// the server's local issuer URL is a sub-path of the web URL.
//
// The expected value is not written out here.  It is captured from
// config.GetLocalIssuerUrl() in a process that has registered both modules --
// i.e. exactly what the serving process computes -- and the CLI-side derivation
// is then required to reproduce it from configuration alone.
func TestWebAPIAdminTokenIssuerColocatedOriginAndDirector(t *testing.T) {
	const webUrl = "https://colocated.example.com:8444"

	// Step 1: what the *server* will require.  InitServer is what registers the
	// enabled modules, which is the input config.GetLocalIssuerUrl() keys off.
	resetIssuerTestState(t)
	require.NoError(t, param.Server_ExternalWebUrl.Set(webUrl))
	require.NoError(t, config.InitServer(context.Background(),
		server_structs.OriginType|server_structs.DirectorType))
	expected := config.GetLocalIssuerUrl()
	require.NotEqual(t, webUrl, expected,
		"a co-located origin+director must use a local issuer distinct from the web URL")

	// Step 2: what a CLI process on that host can work out.  No module is
	// registered here -- config.InitServer was never called with them -- which
	// is precisely why config.GetLocalIssuerUrl() cannot be used directly.
	resetIssuerTestState(t)
	require.NoError(t, param.Server_ExternalWebUrl.Set(webUrl))
	require.NoError(t, param.Server_Modules.Set([]string{"origin", "director"}))

	require.False(t, config.IsServerEnabled(server_structs.OriginType),
		"a CLI process must not appear to have the origin module registered")
	assert.NotEqual(t, expected, config.GetLocalIssuerUrl(),
		"config.GetLocalIssuerUrl() alone cannot see the co-located topology from a CLI")

	assert.Equal(t, expected, webAPIAdminTokenIssuer(webUrl))
	assert.Equal(t, expected, mintedIssuer(t, webUrl))
}

// TestAdminTokenIssuerHintNamesBothIssuers checks that an authorization failure
// is diagnosable: when the CLI cannot tell that the server is a co-located
// origin+director, the 401 must at least report the issuer it used and the one
// such a server would have wanted.
func TestAdminTokenIssuerHintNamesBothIssuers(t *testing.T) {
	t.Run("NoHintWhenOperatorSuppliedTheToken", func(t *testing.T) {
		resetIssuerTestState(t)
		assert.Empty(t, adminTokenIssuerHint())
	})

	t.Run("NamesTheMintedAndColocatedIssuers", func(t *testing.T) {
		resetIssuerTestState(t)
		require.NoError(t, param.Server_ExternalWebUrl.Set("https://server.example.com:8444"))
		minted := mintedIssuer(t, "https://server.example.com:8444")

		hint := adminTokenIssuerHint()
		assert.Contains(t, hint, minted)
		assert.Contains(t, hint, minted+"/api/v1.0/origin")
		assert.Contains(t, hint, param.Server_Modules.GetName())
	})

	t.Run("NoColocatedAdviceWhenAlreadyColocated", func(t *testing.T) {
		resetIssuerTestState(t)
		require.NoError(t, param.Server_ExternalWebUrl.Set("https://server.example.com:8444"))
		require.NoError(t, param.Server_Modules.Set([]string{"origin", "director"}))
		minted := mintedIssuer(t, "https://server.example.com:8444")

		hint := adminTokenIssuerHint()
		assert.Contains(t, hint, minted)
		assert.NotContains(t, hint, param.Server_Modules.GetName())
	})
}

// TestEvictTokenIssuerIsNotTheWebAPIIssuer pins that the two admin-token
// paths stay distinct.
//
// They look interchangeable and are not. The web API pins a token's issuer to
// the server's local issuer URL; eviction is authorized against the namespace
// ACL, which requires an issuer the namespace trusts and whose JWKS the cache
// can fetch. Unifying them would produce a token that one verifier accepts and
// the other rejects, and the symptom would be a 403 from a command that had
// been working.
func TestEvictTokenIssuerIsNotTheWebAPIIssuer(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	// A co-located origin+director is the case where the web API's issuer grows
	// the /api/v1.0/origin sub-path and the two answers visibly diverge.
	viper.Set("Server.ExternalWebUrl", "https://cache.example.com:8444")
	viper.Set("Server.Modules", []string{"origin", "director"})

	webAPI := webAPIAdminTokenIssuer("https://cache.example.com:8444")
	evict, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	require.NotEmpty(t, webAPI)
	require.NotEmpty(t, evict)
	assert.NotEqual(t, webAPI, evict,
		"the web API and namespace-ACL paths require different issuers; if these have become "+
			"equal, one of the two verifiers has changed and cache evict or the web API is about to break")
}
