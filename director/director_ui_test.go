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
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jellydator/ttlcache/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/server_structs"
)

func TestListServers(t *testing.T) {
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

	expectedListOriginResNss := []NamespaceAdV2Response{}
	for _, ns := range mockOriginNamespace {
		expectedListOriginResNss = append(expectedListOriginResNss, namespaceAdV2ToResponse(&ns))
	}

	expectedListCacheResNss := []NamespaceAdV2Response{}
	for _, ns := range mockCacheNamespace {
		expectedListCacheResNss = append(expectedListCacheResNss, namespaceAdV2ToResponse(&ns))
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
		var got []NamespaceAdV2Response
		err := json.Unmarshal(w.Body.Bytes(), &got)
		require.NoError(t, err)
		require.Equal(t, len(mockOriginNamespace), len(got))
		for i := range got {
			assert.Equal(t, namespaceAdV2ToResponse(&mockOriginNamespace[i]), got[i], "Response data does not match expected")
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
		var got []NamespaceAdV2MappedResponse
		err := json.Unmarshal(w.Body.Bytes(), &got)
		require.NoError(t, err)
		require.Equal(t, len(mockOriginNamespace)+len(mockCacheNamespace), len(got))

		// Create the list of expected responses we should see by adding origin/cache names
		var expected []NamespaceAdV2MappedResponse
		for _, ns := range mockOriginNamespace {
			nsRes := namespaceAdV2ToMappedResponse(&ns)
			nsRes.Origins = append(nsRes.Origins, mockOriginServerAd.Name)
			expected = append(expected, nsRes)
		}
		for _, ns := range mockCacheNamespace {
			nsRes := namespaceAdV2ToMappedResponse(&ns)
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
		var got []NamespaceAdV2MappedResponse
		err := json.Unmarshal(w.Body.Bytes(), &got)
		require.NoError(t, err)
		require.Equal(t, len(mockNamespaceSet0)+len(mockNamespaceSet1), len(got))

		// Create the list of expected responses we should see by adding origin/cache names
		expected := make(map[string]NamespaceAdV2MappedResponse)
		for _, ns := range append(mockNamespaceSet1, mockNamespaceSet0...) {
			nsRes := namespaceAdV2ToMappedResponse(&ns)
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
