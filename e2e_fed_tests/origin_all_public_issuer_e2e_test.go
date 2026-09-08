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
	"fmt"
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
func TestAllPublicOriginStartsWithEmbeddedIssuer(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(func() { server_utils.ResetTestState() })

	originConfig := fmt.Sprintf(allPublicEmbeddedIssuerConfig, t.TempDir())
	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft, "an all-public embedded-issuer origin must start cleanly")

	serverURL := param.Server_ExternalWebUrl.GetString()
	httpClient := &http.Client{Transport: config.GetTransport()}

	resp, err := httpClient.Get(serverURL + "/api/v1.0/health")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "the origin's health endpoint must respond after startup")
}
