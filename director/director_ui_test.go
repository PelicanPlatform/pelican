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
		AuthURL:           mockOriginServerAd.URL.String(),
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
		AuthURL:           mockCacheServerAd.URL.String(),
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
