/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package director

import (
	"context"
	_ "embed"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
)

var (
	//go:embed resources/mock_topology.json
	mockTopology string
)

func TestParseServerAd(t *testing.T) {

	server := utils.Server{
		Endpoint: "http://my-endpoint.com",
		Resource: "MY_SERVER",
	}

	osdf_server := utils.Server{
		Endpoint:     "http://my-endpoint.com",
		Resource:     "MY_SERVER",
		AuthEndpoint: "https://my-auth-endpoint.com",
	}

	// Check that we populate all of the fields correctly -- note that lat/long don't get updated
	// until right before the ad is recorded, so we don't check for that here.
	ad := parseServerAd(server, server_structs.OriginType)
	assert.Equal(t, "http://my-endpoint.com", ad.URL.String())
	assert.Equal(t, "", ad.WebURL.String())
	assert.Equal(t, "MY_SERVER", ad.Name)
	assert.Equal(t, url.URL{}, ad.AuthURL)
	assert.True(t, ad.Type == server_structs.OriginType)

	// A quick check that type is set correctly
	ad = parseServerAd(server, server_structs.CacheType)
	assert.True(t, ad.Type == server_structs.CacheType)

	// A check that the authurl is set correctly for parsing a server ad from topology
	ad = parseServerAd(osdf_server, server_structs.OriginType)
	assert.Equal(t, "http://my-endpoint.com", ad.URL.String())
	assert.Equal(t, "https://my-auth-endpoint.com", ad.AuthURL.String())
}

func JSONHandler(w http.ResponseWriter, r *http.Request) {
	// Set the Content-Type header to indicate JSON.
	w.Header().Set("Content-Type", "application/json")

	// Write the JSON response to the response body.
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(mockTopology))
}
func TestAdvertiseOSDF(t *testing.T) {
	viper.Reset()
	serverAds.DeleteAll()
	topoServer := httptest.NewServer(http.HandlerFunc(JSONHandler))
	defer topoServer.Close()
	viper.Set("Federation.TopologyNamespaceUrl", topoServer.URL)

	err := AdvertiseOSDF(context.Background())
	require.NoError(t, err)

	var foundServer server_structs.Advertisement
	for _, item := range serverAds.Items() {
		if item.Value().URL.Host == "origin1-endpoint.com" {
			foundServer = *item.Value()
		}
	}
	require.NotNil(t, foundServer)
	assert.True(t, foundServer.FromTopology)
	require.NotNil(t, foundServer.NamespaceAds)
	assert.True(t, foundServer.NamespaceAds[0].FromTopology)

	// Test a few values. If they're correct, it indicates the whole process likely succeeded
	nsAd, oAds, cAds := getAdsForPath("/my/server/path/to/file")
	assert.Equal(t, "/my/server", nsAd.Path)
	assert.Equal(t, uint(3), nsAd.Generation[0].MaxScopeDepth)
	assert.Equal(t, "https://origin1-auth-endpoint.com", oAds[0].AuthURL.String())
	assert.Equal(t, "https://cache2.com", cAds[0].URL.String())

	nsAd, oAds, cAds = getAdsForPath("/my/server/2/path/to/file")
	assert.Equal(t, "/my/server/2", nsAd.Path)
	assert.Equal(t, true, nsAd.PublicRead)
	assert.Equal(t, "https://origin2-auth-endpoint.com", oAds[0].AuthURL.String())
	assert.Equal(t, "http://cache-endpoint.com", cAds[0].URL.String())
}

func TestFindDownedTopologyCache(t *testing.T) {
	mockTopoCacheA := utils.Server{AuthEndpoint: "cacheA.org:8443", Endpoint: "cacheA.org:8000", Resource: "CACHE_A"}
	mockTopoCacheB := utils.Server{AuthEndpoint: "cacheB.org:8443", Endpoint: "cacheB.org:8000", Resource: "CACHE_B"}
	mockTopoCacheC := utils.Server{AuthEndpoint: "cacheC.org:8443", Endpoint: "cacheC.org:8000", Resource: "CACHE_C"}
	mockTopoCacheD := utils.Server{AuthEndpoint: "cacheD.org:8443", Endpoint: "cacheD.org:8000", Resource: "CACHE_D"}
	t.Run("empty-response", func(t *testing.T) {
		get := findDownedTopologyCache(
			[]utils.Server{},
			[]utils.Server{},
		)
		assert.Empty(t, get)
	})

	t.Run("no-downed-cache", func(t *testing.T) {
		get := findDownedTopologyCache(
			[]utils.Server{mockTopoCacheA, mockTopoCacheB, mockTopoCacheC, mockTopoCacheD},
			[]utils.Server{mockTopoCacheA, mockTopoCacheB, mockTopoCacheC, mockTopoCacheD},
		)
		assert.Empty(t, get)
	})

	t.Run("one-downed-cache", func(t *testing.T) {
		get := findDownedTopologyCache(
			[]utils.Server{mockTopoCacheA, mockTopoCacheB, mockTopoCacheC},
			[]utils.Server{mockTopoCacheA, mockTopoCacheB, mockTopoCacheC, mockTopoCacheD},
		)
		require.Len(t, get, 1)
		assert.EqualValues(t, mockTopoCacheD, get[0])
	})

	t.Run("two-downed-cache", func(t *testing.T) {
		get := findDownedTopologyCache(
			[]utils.Server{mockTopoCacheB, mockTopoCacheC},
			[]utils.Server{mockTopoCacheA, mockTopoCacheB, mockTopoCacheC, mockTopoCacheD},
		)
		require.Len(t, get, 2)
		assert.EqualValues(t, mockTopoCacheA, get[0])
		assert.EqualValues(t, mockTopoCacheD, get[1])
	})

	t.Run("all-downed-cache", func(t *testing.T) {
		get := findDownedTopologyCache(
			[]utils.Server{},
			[]utils.Server{mockTopoCacheA, mockTopoCacheB, mockTopoCacheC, mockTopoCacheD},
		)
		assert.EqualValues(t, []utils.Server{mockTopoCacheA, mockTopoCacheB, mockTopoCacheC, mockTopoCacheD}, get)
	})
}

func TestUpdateDowntimeFromTopology(t *testing.T) {
	mockTopoCacheA := utils.Server{AuthEndpoint: "cacheA.org:8443", Endpoint: "cacheA.org:8000", Resource: "CACHE_A"}
	mockTopoCacheB := utils.Server{AuthEndpoint: "cacheB.org:8443", Endpoint: "cacheB.org:8000", Resource: "CACHE_B"}
	mockTopoCacheC := utils.Server{AuthEndpoint: "cacheC.org:8443", Endpoint: "cacheC.org:8000", Resource: "CACHE_C"}

	t.Run("no-change-with-same-downtime", func(t *testing.T) {
		filteredServers = map[string]filterType{}
		updateDowntimeFromTopology(
			&utils.TopologyNamespacesJSON{},
			&utils.TopologyNamespacesJSON{Caches: []utils.Server{mockTopoCacheA, mockTopoCacheB}},
		)
		checkResult := func() {
			filteredServersMutex.RLock()
			defer filteredServersMutex.RUnlock()
			assert.Len(t, filteredServers, 2)
			require.NotEmpty(t, filteredServers[mockTopoCacheA.Resource])
			assert.Equal(t, topoFiltered, filteredServers[mockTopoCacheA.Resource])
			require.NotEmpty(t, filteredServers[mockTopoCacheB.Resource])
			assert.Equal(t, topoFiltered, filteredServers[mockTopoCacheB.Resource])
		}
		checkResult()

		// second round of updates
		updateDowntimeFromTopology(
			&utils.TopologyNamespacesJSON{},
			&utils.TopologyNamespacesJSON{Caches: []utils.Server{mockTopoCacheA, mockTopoCacheB}},
		)
		// Same result
		checkResult()
	})

	t.Run("one-server-back-online", func(t *testing.T) {
		filteredServers = map[string]filterType{}
		updateDowntimeFromTopology(
			&utils.TopologyNamespacesJSON{},
			&utils.TopologyNamespacesJSON{Caches: []utils.Server{mockTopoCacheA, mockTopoCacheB}},
		)
		func() {
			filteredServersMutex.RLock()
			defer filteredServersMutex.RUnlock()
			assert.Len(t, filteredServers, 2)
			require.NotEmpty(t, filteredServers[mockTopoCacheA.Resource])
			assert.Equal(t, topoFiltered, filteredServers[mockTopoCacheA.Resource])
			require.NotEmpty(t, filteredServers[mockTopoCacheB.Resource])
			assert.Equal(t, topoFiltered, filteredServers[mockTopoCacheB.Resource])
		}()

		// second round of updates
		updateDowntimeFromTopology(
			&utils.TopologyNamespacesJSON{Caches: []utils.Server{mockTopoCacheA}}, // A is back online
			&utils.TopologyNamespacesJSON{Caches: []utils.Server{mockTopoCacheA, mockTopoCacheB}},
		)

		func() {
			filteredServersMutex.RLock()
			defer filteredServersMutex.RUnlock()
			assert.Len(t, filteredServers, 1)
			require.NotEmpty(t, filteredServers[mockTopoCacheB.Resource])
			assert.Equal(t, topoFiltered, filteredServers[mockTopoCacheB.Resource])
		}()
	})

	t.Run("one-more-server-in-downtime", func(t *testing.T) {
		filteredServers = map[string]filterType{}
		updateDowntimeFromTopology(
			&utils.TopologyNamespacesJSON{},
			&utils.TopologyNamespacesJSON{Caches: []utils.Server{mockTopoCacheA, mockTopoCacheB}},
		)
		func() {
			filteredServersMutex.RLock()
			defer filteredServersMutex.RUnlock()
			assert.Len(t, filteredServers, 2)
			require.NotEmpty(t, filteredServers[mockTopoCacheA.Resource])
			assert.Equal(t, topoFiltered, filteredServers[mockTopoCacheA.Resource])
			require.NotEmpty(t, filteredServers[mockTopoCacheB.Resource])
			assert.Equal(t, topoFiltered, filteredServers[mockTopoCacheB.Resource])
		}()

		// second round of updates
		updateDowntimeFromTopology(
			&utils.TopologyNamespacesJSON{Caches: []utils.Server{}},
			&utils.TopologyNamespacesJSON{Caches: []utils.Server{mockTopoCacheA, mockTopoCacheB, mockTopoCacheC}},
		)

		func() {
			filteredServersMutex.RLock()
			defer filteredServersMutex.RUnlock()
			assert.Len(t, filteredServers, 3)
			require.NotEmpty(t, filteredServers[mockTopoCacheA.Resource])
			assert.Equal(t, topoFiltered, filteredServers[mockTopoCacheA.Resource])
			require.NotEmpty(t, filteredServers[mockTopoCacheB.Resource])
			assert.Equal(t, topoFiltered, filteredServers[mockTopoCacheB.Resource])
			require.NotEmpty(t, filteredServers[mockTopoCacheC.Resource])
			assert.Equal(t, topoFiltered, filteredServers[mockTopoCacheC.Resource])
		}()
	})
}
