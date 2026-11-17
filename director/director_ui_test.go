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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jellydator/ttlcache/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestListServers(t *testing.T) {
	setGinTestMode()
	t.Cleanup(test_utils.SetupTestLogging(t))
	mockOriginServerAd := server_structs.ServerAd{
		URL:       url.URL{Host: "origin.com", Scheme: "https"},
		Type:      server_structs.OriginType.String(),
		Latitude:  123.05,
		Longitude: 456.78,
	}
	mockOriginServerAd.Initialize("test-origin-server")

	mockCacheServerAd := server_structs.ServerAd{
		URL:       url.URL{Host: "cache.com", Scheme: "https"},
		Type:      server_structs.CacheType.String(),
		Latitude:  45.67,
		Longitude: 123.05,
	}
	mockCacheServerAd.Initialize("test-cache-server")

	router := gin.Default()

	router.GET("/servers", listServers)

	serverAds.DeleteAll()
	mockOriginNamespace := mockNamespaceAds(5, "origin1")
	mockCacheNamespace := mockNamespaceAds(4, "cache1")
	serverAds.Set(mockOriginServerAd.URL.String(),
		&server_structs.Advertisement{
			ServerAd:     mockOriginServerAd,
			NamespaceAds: mockOriginNamespace,
		}, ttlcache.DefaultTTL)
	serverAds.Set(mockCacheServerAd.URL.String(),
		&server_structs.Advertisement{
			ServerAd:     mockCacheServerAd,
			NamespaceAds: mockCacheNamespace,
		}, ttlcache.DefaultTTL)

	require.True(t, serverAds.Has(mockOriginServerAd.URL.String()))
	require.True(t, serverAds.Has(mockCacheServerAd.URL.String()))

	expectedListOriginResNss := []string{}
	for _, ns := range mockOriginNamespace {
		expectedListOriginResNss = append(expectedListOriginResNss, ns.Path)
	}

	expectedListCacheResNss := []string{}
	for _, ns := range mockCacheNamespace {
		expectedListCacheResNss = append(expectedListCacheResNss, ns.Path)
	}

	expectedlistOriginRes := listServerResponse{
		Name:              mockOriginServerAd.Name,
		BrokerURL:         mockOriginServerAd.BrokerURL.String(),
		AuthURL:           "",
		URL:               mockOriginServerAd.URL.String(),
		WebURL:            mockOriginServerAd.WebURL.String(),
		Type:              mockOriginServerAd.Type,
		Latitude:          mockOriginServerAd.Latitude,
		Longitude:         mockOriginServerAd.Longitude,
		Caps:              mockOriginServerAd.Caps,
		FromTopology:      mockOriginServerAd.FromTopology,
		HealthStatus:      HealthStatusUnknown,
		NamespacePrefixes: expectedListOriginResNss,
		Version:           "dev",
	}

	expectedlistCacheRes := listServerResponse{
		Name:              mockCacheServerAd.Name,
		BrokerURL:         mockCacheServerAd.BrokerURL.String(),
		AuthURL:           "",
		URL:               mockCacheServerAd.URL.String(),
		WebURL:            mockCacheServerAd.WebURL.String(),
		Type:              mockCacheServerAd.Type,
		Latitude:          mockCacheServerAd.Latitude,
		Longitude:         mockCacheServerAd.Longitude,
		Caps:              mockCacheServerAd.Caps,
		FromTopology:      mockCacheServerAd.FromTopology,
		HealthStatus:      HealthStatusUnknown,
		NamespacePrefixes: expectedListCacheResNss,
		Version:           "dev",
	}

	t.Run("query-origin", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers?server_type=origin", nil)
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 200, w.Code)

		var got []listServerResponse
		err := json.Unmarshal(w.Body.Bytes(), &got)
		require.NoError(t, err)
		require.Equal(t, 1, len(got))
		assert.Equal(t, expectedlistOriginRes, got[0], "Response data does not match expected")
	})

	t.Run("query-cache", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers?server_type=cache", nil)
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 200, w.Code)

		var got []listServerResponse
		err := json.Unmarshal(w.Body.Bytes(), &got)

		require.NoError(t, err)
		require.Equal(t, 1, len(got))
		assert.Equal(t, expectedlistCacheRes, got[0], "Response data does not match expected")
	})

	t.Run("query-all-with-empty-server-type", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers?server_type=", nil)
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 200, w.Code)

		var got []listServerResponse
		err := json.Unmarshal(w.Body.Bytes(), &got)

		require.NoError(t, err)
		require.Equal(t, 2, len(got))
	})

	t.Run("query-all-without-query-param", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers", nil)
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 200, w.Code)

		var got []listServerResponse
		err := json.Unmarshal(w.Body.Bytes(), &got)

		require.NoError(t, err)
		require.Equal(t, 2, len(got))
	})

	t.Run("query-with-invalid-param", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers?server_type=staging", nil)
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 400, w.Code)
	})
}

func TestGetServer(t *testing.T) {
	setGinTestMode()
	t.Cleanup(test_utils.SetupTestLogging(t))
	mockOriginServerAd := server_structs.ServerAd{
		URL:       url.URL{Host: "origin.com", Scheme: "https"},
		Type:      server_structs.OriginType.String(),
		Latitude:  123.05,
		Longitude: 456.78,
	}
	mockOriginServerAd.Initialize("test-origin-server")

	mockCacheServerAd := server_structs.ServerAd{
		URL:       url.URL{Host: "cache.com", Scheme: "https"},
		Type:      server_structs.CacheType.String(),
		Latitude:  45.67,
		Longitude: 123.05,
	}
	mockCacheServerAd.Initialize("test-cache-server")

	router := gin.Default()

	router.GET("/servers/:name", getServerHandler)
	router.GET("/servers/:name/namespaces", listServerNamespaces)

	serverAds.DeleteAll()
	mockOriginNamespace := mockNamespaceAds(5, "origin1")
	mockCacheNamespace := mockNamespaceAds(4, "cache1")
	serverAds.Set(mockOriginServerAd.URL.String(),
		&server_structs.Advertisement{
			ServerAd:     mockOriginServerAd,
			NamespaceAds: mockOriginNamespace,
		}, ttlcache.DefaultTTL)
	serverAds.Set(mockCacheServerAd.URL.String(),
		&server_structs.Advertisement{
			ServerAd:     mockCacheServerAd,
			NamespaceAds: mockCacheNamespace,
		}, ttlcache.DefaultTTL)

	require.True(t, serverAds.Has(mockOriginServerAd.URL.String()))
	require.True(t, serverAds.Has(mockCacheServerAd.URL.String()))

	expectedListOriginResNss := []server_structs.NamespaceAdResponse{}
	for _, ns := range mockOriginNamespace {
		expectedListOriginResNss = append(expectedListOriginResNss, namespaceAdToResponse(&ns))
	}

	expectedListCacheResNss := []server_structs.NamespaceAdResponse{}
	for _, ns := range mockCacheNamespace {
		expectedListCacheResNss = append(expectedListCacheResNss, namespaceAdToResponse(&ns))
	}

	expectedlistOriginRes := serverResponse{
		Name:         mockOriginServerAd.Name,
		BrokerURL:    mockOriginServerAd.BrokerURL.String(),
		AuthURL:      "",
		URL:          mockOriginServerAd.URL.String(),
		WebURL:       mockOriginServerAd.WebURL.String(),
		Type:         mockOriginServerAd.Type,
		Latitude:     mockOriginServerAd.Latitude,
		Longitude:    mockOriginServerAd.Longitude,
		Caps:         mockOriginServerAd.Caps,
		FromTopology: mockOriginServerAd.FromTopology,
		HealthStatus: HealthStatusUnknown,
		Namespaces:   expectedListOriginResNss,
		Version:      "dev",
	}

	expectedlistCacheRes := serverResponse{
		Name:         mockCacheServerAd.Name,
		BrokerURL:    mockCacheServerAd.BrokerURL.String(),
		AuthURL:      "",
		URL:          mockCacheServerAd.URL.String(),
		WebURL:       mockCacheServerAd.WebURL.String(),
		Type:         mockCacheServerAd.Type,
		Latitude:     mockCacheServerAd.Latitude,
		Longitude:    mockCacheServerAd.Longitude,
		Caps:         mockCacheServerAd.Caps,
		FromTopology: mockCacheServerAd.FromTopology,
		HealthStatus: HealthStatusUnknown,
		Namespaces:   expectedListCacheResNss,
		Version:      "dev",
	}

	t.Run("get-origin", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/"+mockOriginServerAd.Name, nil)
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 200, w.Code)

		var got serverResponse
		err := json.Unmarshal(w.Body.Bytes(), &got)
		require.NoError(t, err)
		assert.Equal(t, expectedlistOriginRes, got, "Response data does not match expected")
	})

	t.Run("get-cache", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/"+mockCacheServerAd.Name, nil)
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 200, w.Code)

		var got serverResponse
		err := json.Unmarshal(w.Body.Bytes(), &got)
		require.NoError(t, err)
		assert.Equal(t, expectedlistCacheRes, got, "Response data does not match expected")
	})

	t.Run("get-non-existent-server", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/non-existent-server", nil)
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 404, w.Code)
	})

	t.Run("get-namespaces-of-server", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/"+mockOriginServerAd.Name+"/namespaces", nil)
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 200, w.Code)

		// Check the data
		var got []server_structs.NamespaceAdResponse
		err := json.Unmarshal(w.Body.Bytes(), &got)
		require.NoError(t, err)
		require.Equal(t, len(mockOriginNamespace), len(got))
		for i := range got {
			assert.Equal(t, namespaceAdToResponse(&mockOriginNamespace[i]), got[i], "Response data does not match expected")
		}
	})

	t.Run("get-namespaces-of-non-existent-server", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/non-existent-server/namespaces", nil)
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 404, w.Code)
	})
}

func TestGetNamespaces(t *testing.T) {
	setGinTestMode()
	t.Cleanup(test_utils.SetupTestLogging(t))

	mockOriginServerAd := server_structs.ServerAd{
		URL:       url.URL{Host: "origin.com", Scheme: "https"},
		Type:      server_structs.OriginType.String(),
		Latitude:  123.05,
		Longitude: 456.78,
	}
	mockOriginServerAd.Initialize("test-origin-server")

	mockCacheServerAd := server_structs.ServerAd{
		URL:       url.URL{Host: "cache.com", Scheme: "https"},
		Type:      server_structs.CacheType.String(),
		Latitude:  45.67,
		Longitude: 123.05,
	}
	mockCacheServerAd.Initialize("test-cache-server")

	router := gin.Default()

	router.GET("/namespaces", listNamespacesHandler)

	serverAds.DeleteAll()
	mockOriginNamespace := mockNamespaceAds(5, "origin1")
	mockCacheNamespace := mockNamespaceAds(4, "cache1")
	serverAds.Set(mockOriginServerAd.URL.String(),
		&server_structs.Advertisement{
			ServerAd:     mockOriginServerAd,
			NamespaceAds: mockOriginNamespace,
		}, ttlcache.DefaultTTL)
	serverAds.Set(mockCacheServerAd.URL.String(),
		&server_structs.Advertisement{
			ServerAd:     mockCacheServerAd,
			NamespaceAds: mockCacheNamespace,
		}, ttlcache.DefaultTTL)

	t.Run("get-all-namespaces", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/namespaces", nil)
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 200, w.Code)

		// Check the data
		var got []server_structs.NamespaceAdMappedResponse
		err := json.Unmarshal(w.Body.Bytes(), &got)
		require.NoError(t, err)
		require.Equal(t, len(mockOriginNamespace)+len(mockCacheNamespace), len(got))

		// Create the list of expected responses we should see by adding origin/cache names
		var expected []server_structs.NamespaceAdMappedResponse
		for _, ns := range mockOriginNamespace {
			nsRes := namespaceAdToMappedResponse(&ns)
			nsRes.Origins = append(nsRes.Origins, mockOriginServerAd.Name)
			expected = append(expected, nsRes)
		}
		for _, ns := range mockCacheNamespace {
			nsRes := namespaceAdToMappedResponse(&ns)
			nsRes.Caches = append(nsRes.Caches, mockCacheServerAd.Name)
			expected = append(expected, nsRes)
		}

		// Check that the namespaces are as expected
		for _, ns := range expected {
			assert.Contains(t, got, ns, "Response data does not match expected")
		}
	})

	t.Run("get-all-namespaces-crossover", func(t *testing.T) {

		// Set things up with namespaces that cross over between origin and cache
		serverAds.DeleteAll()
		mockNamespaceSet0 := mockNamespaceAds(5, "origin1")
		mockNamespaceSet1 := mockNamespaceAds(4, "cache1")
		serverAds.Set(mockOriginServerAd.URL.String(),
			&server_structs.Advertisement{
				ServerAd:     mockOriginServerAd,
				NamespaceAds: append(mockNamespaceSet0, mockNamespaceSet1...),
			}, ttlcache.DefaultTTL)
		serverAds.Set(mockCacheServerAd.URL.String(),
			&server_structs.Advertisement{
				ServerAd:     mockCacheServerAd,
				NamespaceAds: mockNamespaceSet0,
			}, ttlcache.DefaultTTL)

		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/namespaces", nil)
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 200, w.Code)

		// Check the data
		var got []server_structs.NamespaceAdMappedResponse
		err := json.Unmarshal(w.Body.Bytes(), &got)
		require.NoError(t, err)
		require.Equal(t, len(mockNamespaceSet0)+len(mockNamespaceSet1), len(got))

		// Create the list of expected responses we should see by adding origin/cache names
		expected := make(map[string]server_structs.NamespaceAdMappedResponse)
		for _, ns := range append(mockNamespaceSet1, mockNamespaceSet0...) {
			nsRes := namespaceAdToMappedResponse(&ns)
			nsRes.Origins = append(nsRes.Origins, mockOriginServerAd.Name)
			expected[nsRes.Path] = nsRes
		}
		// Going to cheat a bit here and use that fact that I know origins superset cache namespaces
		for _, ns := range mockNamespaceSet0 {
			nsMappedRes := expected[ns.Path]
			nsMappedRes.Caches = append(nsMappedRes.Caches, mockCacheServerAd.Name)
			expected[ns.Path] = nsMappedRes
		}

		// Check that the namespaces are as expected
		for _, ns := range expected {
			assert.Contains(t, got, ns, "Response data does not match expected")
		}
	})
}

// A cache re-advertises the namespace list it last fetched from the director,
// so right after an origin comes back the cache can still carry the registry's
// copy of the path, flagged from-registry. The listing must show the origin's
// ad whichever server the snapshot yields first; that order is random, so the
// listing is built many times.
func TestListNamespaceResponsesOriginAdWins(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	serverAds.DeleteAll()
	t.Cleanup(serverAds.DeleteAll)
	resetRegistryQueryState()
	t.Cleanup(resetRegistryQueryState)

	authenticated := server_structs.Capabilities{Reads: true}
	issuerAt := func(host string) []server_structs.TokenIssuer {
		return []server_structs.TokenIssuer{{IssuerUrl: url.URL{Scheme: "https", Host: host}, BasePaths: []string{"/ns"}}}
	}
	serverAd := func(host, serverType string) server_structs.ServerAd {
		ad := server_structs.ServerAd{URL: url.URL{Host: host, Scheme: "https"}, Type: serverType}
		ad.Initialize(host)
		return ad
	}
	origin := serverAd("origin.com", server_structs.OriginType.String())
	cache := serverAd("cache.com", server_structs.CacheType.String())

	originNs := server_structs.NamespaceAd{Path: "/ns", Caps: authenticated, Issuer: issuerAt("origin-issuer.example.org")}
	registryNs := server_structs.NamespaceAd{Path: "/ns", Caps: authenticated, Issuer: issuerAt("registry-issuer.example.org")}
	// The registry still holds the owner's auth state for the path
	registry := ingestRegistryNamespaceAds([]server_structs.NamespaceAd{registryNs})
	registryNamespaceAds.Store(&registry)
	// The cache's last fetch happened while the origin was offline, so it
	// re-advertises the registry's copy, flag included
	staleCopy := registry[0]
	serverAds.Set(origin.URL.String(), &server_structs.Advertisement{ServerAd: origin, NamespaceAds: []server_structs.NamespaceAd{originNs}}, ttlcache.DefaultTTL)
	serverAds.Set(cache.URL.String(), &server_structs.Advertisement{ServerAd: cache, NamespaceAds: []server_structs.NamespaceAd{staleCopy}}, ttlcache.DefaultTTL)

	for i := 0; i < 20; i++ {
		list := listNamespaceResponses()
		require.Len(t, list, 1, "iteration %d", i)
		got := list[0]
		assert.False(t, got.FromRegistry, "iteration %d", i)
		require.Len(t, got.Issuer, 1, "iteration %d", i)
		assert.Equal(t, "https://origin-issuer.example.org", got.Issuer[0].IssuerUrl, "iteration %d", i)
		assert.Equal(t, []string{origin.Name}, got.Origins, "iteration %d", i)
		assert.Equal(t, []string{cache.Name}, got.Caches, "iteration %d", i)
	}
}

func TestGetNamespacesRegistryProvenance(t *testing.T) {
	setGinTestMode()
	t.Cleanup(test_utils.SetupTestLogging(t))
	serverAds.DeleteAll()
	t.Cleanup(serverAds.DeleteAll)
	resetRegistryQueryState()
	t.Cleanup(resetRegistryQueryState)

	public := server_structs.Capabilities{PublicReads: true, Reads: true}
	authenticated := server_structs.Capabilities{Reads: true}
	issuerFor := func(path string) []server_structs.TokenIssuer {
		return []server_structs.TokenIssuer{{IssuerUrl: url.URL{Scheme: "https", Host: "issuer.example.org"}, BasePaths: []string{path}}}
	}
	serverAd := func(host, serverType string, fromTopology bool) server_structs.ServerAd {
		ad := server_structs.ServerAd{URL: url.URL{Host: host, Scheme: "https"}, Type: serverType, FromTopology: fromTopology}
		ad.Initialize(host)
		return ad
	}
	topoOrigin := serverAd("topo-origin.com", server_structs.OriginType.String(), true)
	origin := serverAd("origin.com", server_structs.OriginType.String(), false)
	cache := serverAd("cache.com", server_structs.CacheType.String(), false)

	topoNs := server_structs.NamespaceAd{Path: "/topo", Caps: public, FromTopology: true}
	servedNs := server_structs.NamespaceAd{Path: "/served", Caps: public}
	cachedNs := server_structs.NamespaceAd{Path: "/cached", Caps: authenticated} // the cache's own view, without the issuer
	serverAds.Set(topoOrigin.URL.String(), &server_structs.Advertisement{ServerAd: topoOrigin, NamespaceAds: []server_structs.NamespaceAd{topoNs}}, ttlcache.DefaultTTL)
	serverAds.Set(origin.URL.String(), &server_structs.Advertisement{ServerAd: origin, NamespaceAds: []server_structs.NamespaceAd{servedNs}}, ttlcache.DefaultTTL)
	serverAds.Set(cache.URL.String(), &server_structs.Advertisement{ServerAd: cache, NamespaceAds: []server_structs.NamespaceAd{servedNs, cachedNs}}, ttlcache.DefaultTTL)

	registry := ingestRegistryNamespaceAds([]server_structs.NamespaceAd{
		{Path: "/served", Caps: public},                                        // a live origin advertises it: the origin wins
		{Path: "/cached", Caps: authenticated, Issuer: issuerFor("/cached")},   // only a cache holds it
		{Path: "/offline", Caps: authenticated, Issuer: issuerFor("/offline")}, // nobody serves it
	})
	registryNamespaceAds.Store(&registry)

	router := gin.New()
	router.GET("/namespaces", listNamespacesHandler)
	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/namespaces", nil)
	require.NoError(t, err)
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var list []server_structs.NamespaceAdMappedResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	got := make(map[string]server_structs.NamespaceAdMappedResponse, len(list))
	for _, ns := range list {
		got[ns.Path] = ns
	}
	require.Len(t, got, 4, "one entry per path: %s", w.Body.String())

	// A topology origin's namespace reports its provenance; the converter
	// used to drop fromTopology on the way to this listing
	assert.True(t, got["/topo"].FromTopology)
	assert.False(t, got["/topo"].FromRegistry)
	assert.Equal(t, []string{topoOrigin.Name}, got["/topo"].Origins)

	// The live origin's entry is the one listed; the registry's copy is not
	assert.False(t, got["/served"].FromRegistry)
	assert.Equal(t, []string{origin.Name}, got["/served"].Origins)
	assert.Equal(t, []string{cache.Name}, got["/served"].Caches)

	// A path only caches hold shows the registry's ad together with the caches
	assert.True(t, got["/cached"].FromRegistry)
	assert.Empty(t, got["/cached"].Origins)
	assert.Equal(t, []string{cache.Name}, got["/cached"].Caches)
	require.Len(t, got["/cached"].Issuer, 1, "the descriptive fields come from the registry")
	assert.Equal(t, "https://issuer.example.org", got["/cached"].Issuer[0].IssuerUrl)

	// A path nobody serves is listed from the registry alone
	assert.True(t, got["/offline"].FromRegistry)
	assert.Empty(t, got["/offline"].Origins)
	assert.Empty(t, got["/offline"].Caches)
	assert.Equal(t, authenticated, got["/offline"].Caps)
}
