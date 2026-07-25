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

package launcher_utils_test

import (
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/server_structs"
)

// TestDirectorEmitsDirectEndpoints is an end-to-end check of the WS2 director
// path: an origin that advertises an explicit direct-reach endpoint
// (Server.AdvertisedIPs) causes the director to return the
// X-Pelican-Direct-Endpoints header — carrying the origin's slug and the
// advertised address — to a Pelican client. The client-side consumption of that
// header (dialing the endpoint with ServerName=slug) is covered by unit tests;
// here we exercise the real registration -> ServerAd -> redirect -> header path
// through a live federation.
func TestDirectorEmitsDirectEndpoints(t *testing.T) {
	advertised := "203.0.113.5:8443"
	fed := fed_test_utils.NewFedTest(t, `
Server:
  AdvertisedIPs:
    - "`+advertised+`"
Origin:
  StorageType: posix
  Exports:
    - FederationPrefix: /test
      StoragePrefix: /<OVERRIDDEN>
      Capabilities: ["PublicReads", "Writes", "Listings", "DirectReads"]
`)

	fedInfo, err := config.GetFederation(fed.Ctx)
	require.NoError(t, err)
	require.NotEmpty(t, fedInfo.DirectorEndpoint)
	require.NotEmpty(t, fed.Exports)

	// Ask the director for the object as a Pelican client, forcing routing to the
	// origin (directread) so the chosen server is the one that advertised the
	// endpoint. Do not follow the redirect: we want to read the director's
	// response headers.
	objURL := fedInfo.DirectorEndpoint + fed.Exports[0].FederationPrefix + "/nonexistent-object?directread"
	req, err := http.NewRequestWithContext(fed.Ctx, http.MethodGet, objURL, nil)
	require.NoError(t, err)
	req.Header.Set("User-Agent", "pelican-client/7.99.0")
	req.Header.Set("Authorization", "Bearer "+fed.Token)

	client := &http.Client{
		Transport:     config.GetTransport(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	hdr := resp.Header.Get(string(server_structs.XPelicanDirectEndpointsHeaderName))
	require.NotEmpty(t, hdr,
		"director should advertise direct endpoints to a Pelican client (HTTP %d)", resp.StatusCode)
	assert.Contains(t, hdr, advertised, "header should carry the advertised endpoint")
	assert.Contains(t, hdr, "sni=", "header should carry the slug as the TLS ServerName")

	// A non-Pelican client (e.g. curl) must NOT receive the header.
	req2, err := http.NewRequestWithContext(fed.Ctx, http.MethodGet, objURL, nil)
	require.NoError(t, err)
	req2.Header.Set("User-Agent", "curl/8.0.1")
	req2.Header.Set("Authorization", "Bearer "+fed.Token)
	resp2, err := client.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()
	_, _ = io.Copy(io.Discard, resp2.Body)
	assert.Empty(t, resp2.Header.Get(string(server_structs.XPelicanDirectEndpointsHeaderName)),
		"a non-Pelican client must not receive the direct-endpoints header")
}
