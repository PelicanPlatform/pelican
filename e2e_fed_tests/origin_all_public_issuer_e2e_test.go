//go:build server && !windows

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

package fed_tests

import (
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// allPublicEmbeddedIssuerConfig is an origin with the embedded issuer enabled
// but ONLY a public-read export: no export requires authentication, so the
// embedded issuer registers no OIDC providers.
const allPublicEmbeddedIssuerConfig = `
Origin:
  StorageType: posixv2
  EnableIssuer: true
  IssuerMode: embedded
  Exports:
    - FederationPrefix: /public-data
      StoragePrefix: %s
      Capabilities: ["PublicReads"]
`

// TestAllPublicOriginStartsWithEmbeddedIssuer verifies that an origin with the
// embedded issuer enabled but only public-read exports starts cleanly
// (issue #3719).
//
// The embedded issuer creates a provider per auth-requiring export, so an
// all-public origin registers none and serves no issuer discovery endpoint.
// The launcher's issuer startup health check used to fall back to the
// namespace-less OA4MP discovery path in that case, which the embedded issuer
// never serves; the probe 404'd until Server.StartupTimeout and the whole
// launch failed, crash-looping the origin. The launcher now skips the issuer
// health check when no export requires authentication.
//
// Note: on main the same configuration instead health-checks the server's
// local issuer, which is registered whenever the embedded issuer is enabled
// (commit 4ac260c2e). That feature is not on v7.27.x, so this test also pins
// that no issuer provider exists on an all-public origin — if the local
// issuer is ever backported, the second assertion flips and the launcher
// skip should be replaced with the health check from 4ac260c2e.
func TestAllPublicOriginStartsWithEmbeddedIssuer(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(func() { server_utils.ResetTestState() })

	// Without the launcher fix the fed never finishes starting: the issuer
	// health check probes a URL nothing serves and LaunchModules errors out.
	originConfig := fmt.Sprintf(allPublicEmbeddedIssuerConfig, t.TempDir())
	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft, "an all-public embedded-issuer origin must start cleanly")

	serverURL := param.Server_ExternalWebUrl.GetString()
	httpClient := &http.Client{Transport: config.GetTransport()}

	// The server is up and healthy — the same endpoint the launcher gates on.
	resp, err := httpClient.Get(serverURL + "/api/v1.0/health")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "the origin's health endpoint must respond after startup")

	// No issuer provider is registered for the public export: its discovery
	// document is not served. This is why the launcher must skip the issuer
	// health check rather than probe anything.
	discResp, err := httpClient.Get(serverURL + "/api/v1.0/issuer/ns/public-data/.well-known/openid-configuration")
	require.NoError(t, err)
	defer discResp.Body.Close()
	body, _ := io.ReadAll(discResp.Body)
	require.Equal(t, http.StatusNotFound, discResp.StatusCode,
		"an all-public origin must register no issuer provider (body: %s)", string(body))
}
