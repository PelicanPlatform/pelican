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

package fed_tests

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/oauth2/issuer"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// allPublicEmbeddedIssuerConfig is an origin with the embedded issuer enabled
// but ONLY a public-read export: no export requires authentication and the
// transfer API is off.
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

// TestAllPublicOriginRegistersLocalIssuer verifies that an origin with the
// embedded issuer enabled but only public-read exports still stands up its
// local issuer.
//
// The local issuer used to be registered only when at least one data export
// required authentication (or the transfer API was on); an all-public origin
// hit an early return ("no exports require authentication; no issuers
// registered") and served no issuer routes at all. The local issuer is now
// registered whenever the embedded issuer is enabled -- it is the generic
// local-identity issuer the transfer and collections features depend on -- so
// this pins that an all-public embedded origin (a) starts cleanly and (b)
// exposes the local issuer's discovery document.
func TestAllPublicOriginRegistersLocalIssuer(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(func() { server_utils.ResetTestState() })

	originConfig := fmt.Sprintf(allPublicEmbeddedIssuerConfig, t.TempDir())
	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft, "an all-public embedded-issuer origin must start cleanly")

	serverURL := param.Server_ExternalWebUrl.GetString()
	discoveryURL := serverURL + "/api/v1.0/issuer/ns" + issuer.LocalIssuerNamespace +
		"/.well-known/openid-configuration"

	httpClient := &http.Client{Transport: config.GetTransport()}
	resp, err := httpClient.Get(discoveryURL)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"the local issuer's discovery document must be served on an all-public embedded origin (body: %s)", string(body))

	var disc struct {
		Issuer        string `json:"issuer"`
		TokenEndpoint string `json:"token_endpoint"`
	}
	require.NoError(t, json.Unmarshal(body, &disc))
	// The local issuer identifies itself with GetLocalIssuerUrl() -- what the
	// web-UI/transfer LocalIssuer checks trust -- and exposes real OAuth
	// endpoints (proving the provider, not just a stub route, is registered).
	assert.Equal(t, config.GetLocalIssuerUrl(), disc.Issuer,
		"the local issuer discovery document must carry the local issuer URL")
	assert.NotEmpty(t, disc.TokenEndpoint, "the local issuer must advertise a token endpoint")
}
