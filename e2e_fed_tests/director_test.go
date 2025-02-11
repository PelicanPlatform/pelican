//go:build !windows

/***************************************************************
*
* Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/server_structs"

	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

//go:embed resources/both-public.yml
var bothPubNamespaces string

type serverAdUnmarshal struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Queries the cache for a director test file -- this mimics the way the Pelican
// process at the cache behaves, as its responsible for requesting files from its
// own XRootD component
func TestDirectorCacheHealthTest(t *testing.T) {
	// Spin up a federation
	_ = fed_test_utils.NewFedTest(t, bothPubNamespaces)

	ctx := context.Background()
	ctx, _, _ = test_utils.TestContext(ctx, t)
	fedInfo, err := config.GetFederation(ctx)
	require.NoError(t, err, "Failed to get federation service info")

	directorUrlStr := fedInfo.DirectorEndpoint
	directorUrl, err := url.Parse(directorUrlStr)
	require.NoError(t, err, "Failed to parse director URL")

	// There is no cache that will advertise the /pelican/monitoring namespace directly,
	// so we first discover a cache, then ask for the file. To do that, hit the Director's
	// server list endpoint and iterate through the servers until we find a cache.
	listPath, err := url.JoinPath("api", "v1.0", "director_ui", "servers")
	require.NoError(t, err, "Failed to join server list path")
	directorUrl.Path = listPath
	request, err := http.NewRequest("GET", directorUrl.String(), nil)
	require.NoError(t, err, "Failed to create HTTP request against server list path")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := http.Client{Transport: tr}
	resp, err := client.Do(request)
	assert.NoError(t, err, "Failed to get response")
	defer resp.Body.Close()
	require.Equal(t, resp.StatusCode, http.StatusOK, "Failed to get server list from director")
	dirBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Failed to read server list body")

	// Unmarshal the body into a slice of dummy server ads. Can't use the actual server_structs.ServerAd
	// struct without a custom unmarshaler (because of string --> url conversion)
	var serverAds []serverAdUnmarshal
	err = json.Unmarshal(dirBody, &serverAds)
	require.NoError(t, err, "Failed to unmarshal server ads")
	var cacheUrlStr string
	found := false
	for _, serverAd := range serverAds {
		if serverAd.Type == server_structs.CacheType.String() {
			cacheUrlStr = serverAd.URL
			found = true
			break
		}
	}
	require.True(t, found, "Failed to find a cache server in the server list")
	cacheUrl, err := url.Parse(cacheUrlStr)
	require.NoError(t, err, "Failed to parse cache URL")

	// Now ask the cache for the director test file. When it gets the request,
	// it'll turn around and ask the director for the file, exactly as it would
	// if the cache's own self-test utility requested the file.
	cachePath, err := url.JoinPath(server_utils.MonitoringBaseNs, "directorTest",
		server_utils.DirectorTest.String()+"-2006-01-02T15:04:10Z.txt")
	require.NoError(t, err, "Failed to join path")

	cacheUrl.Path = cachePath
	request, err = http.NewRequest("GET", cacheUrl.String(), nil)
	require.NoError(t, err, "Failed to create HTTP request against cache")

	resp, err = client.Do(request)
	assert.NoError(t, err, "Failed to get response")
	defer resp.Body.Close()
	cacheBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Failed to read cache body")
	assert.Equal(t, resp.StatusCode, http.StatusOK, "Failed to get director test file from cache")
	assert.Contains(t, string(cacheBody), "This object was created by the Pelican director-test functionality")
}
