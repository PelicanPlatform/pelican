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
	"crypto/tls"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
)

// wellFormedApiToken is a syntactically valid API token that matches no
// database row. Its shape matters and it must not be "simplified":
//
//   - api_token.ApiTokenRegex requires exactly 5 alphanumerics, a dot,
//     then 64 alphanumerics. A JWT (three base64url segments, with '-'
//     and '_') fails this and is rejected before the database is
//     consulted.
//   - VerifyApiKey then hex-decodes the 64-character secret, so the tail
//     must also be valid hex. A single non-hex letter there short-circuits
//     the call one step early.
//
// Only a credential clearing both gates reaches the database lookup,
// which is the code path this test exists to cover. Swap in a JWT or a
// non-hex tail and the test still passes -- for the wrong reason.
const wellFormedApiToken = "abcde.0000000000000000000000000000000000000000000000000000000000000000"

// TestDirectorApiTokenWithUninitializedDB is the end-to-end regression
// guard for the nil-database panic.
func TestDirectorApiTokenWithUninitializedDB(t *testing.T) {
	fed := fed_test_utils.NewFedTest(t, fed_test_utils.BothPublicNamespaces)

	directorUrl := param.Server_ExternalWebUrl.GetString()
	require.NotEmpty(t, directorUrl, "fed test did not populate the server web URL")

	req, err := http.NewRequestWithContext(fed.Ctx, http.MethodGet,
		directorUrl+"/api/v1.0/director/discoverServers", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+wellFormedApiToken)

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"a bogus API token must be rejected, not panic; a 500 here means api_token's database handle was nil and gorm panicked on it. Body: %s", string(body))

	// Distinguish "rejected the token" from "could not reach the
	// database". Both are non-200, so the status code alone would not
	// catch a regression that swapped the panic for a fail-closed error
	// while leaving the handle unwired.
	assert.NotContains(t, string(body), "not initialized",
		"the director reached the API-token check but had no database handle -- the hook is not wired through the real startup path")
	assert.NotContains(t, string(body), "not wired",
		"api_token.DB was never wired; web_ui's init() should have set it")
}
