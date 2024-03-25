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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jellydator/ttlcache/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListServers(t *testing.T) {
	router := gin.Default()

	router.GET("/servers", listServers)

	func() {
		serverAdMutex.Lock()
		defer serverAdMutex.Unlock()
		serverAds.Set(mockOriginServerAd, mockNamespaceAds(5, "origin1"), ttlcache.DefaultTTL)
		serverAds.Set(mockCacheServerAd, mockNamespaceAds(4, "cache1"), ttlcache.DefaultTTL)
		require.True(t, serverAds.Has(mockOriginServerAd))
		require.True(t, serverAds.Has(mockCacheServerAd))
	}()

	mocklistOriginRes := listServerResponse{
		Name:        mockOriginServerAd.Name,
		BrokerURL:   mockOriginServerAd.BrokerURL.String(),
		AuthURL:     mockOriginServerAd.AuthURL.String(),
		URL:         mockOriginServerAd.URL.String(),
		WebURL:      mockOriginServerAd.WebURL.String(),
		Type:        mockOriginServerAd.Type,
		Latitude:    mockOriginServerAd.Latitude,
		Longitude:   mockOriginServerAd.Longitude,
		Writes:      mockOriginServerAd.Writes,
		DirectReads: mockOriginServerAd.DirectReads,
		Status:      HealthStatusUnknown,
	}
	mocklistCacheRes := listServerResponse{
		Name:        mockCacheServerAd.Name,
		BrokerURL:   mockCacheServerAd.BrokerURL.String(),
		AuthURL:     mockCacheServerAd.AuthURL.String(),
		URL:         mockCacheServerAd.URL.String(),
		WebURL:      mockCacheServerAd.WebURL.String(),
		Type:        mockCacheServerAd.Type,
		Latitude:    mockCacheServerAd.Latitude,
		Longitude:   mockCacheServerAd.Longitude,
		Writes:      mockCacheServerAd.Writes,
		DirectReads: mockCacheServerAd.DirectReads,
		Status:      HealthStatusUnknown,
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
		if err != nil {
			t.Fatalf("Failed to unmarshal response body: %v", err)
		}
		require.Equal(t, 1, len(got))
		assert.Equal(t, mocklistOriginRes, got[0], "Response data does not match expected")
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
		if err != nil {
			t.Fatalf("Failed to unmarshal response body: %v", err)
		}
		require.Equal(t, 1, len(got))
		assert.Equal(t, mocklistCacheRes, got[0], "Response data does not match expected")
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
		if err != nil {
			t.Fatalf("Failed to unmarshal response body: %v", err)
		}
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
		if err != nil {
			t.Fatalf("Failed to unmarshal response body: %v", err)
		}
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

func TestHandleFilterServer(t *testing.T) {
	t.Cleanup(func() {
		filteredServersMutex.Lock()
		defer filteredServersMutex.Unlock()
		filteredServers = map[string]filterType{}
	})
	router := gin.Default()
	router.GET("/servers/filter/*name", handleFilterServer)

	t.Run("filter-server-success", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/filter/mock-dne", nil)
		filteredServersMutex.Lock()
		delete(filteredServers, "mock-dne")
		filteredServersMutex.Unlock()
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 200, w.Code)

		filteredServersMutex.RLock()
		defer filteredServersMutex.RUnlock()
		assert.Equal(t, tempFiltered, filteredServers["mock-dne"])
	})
	t.Run("filter-server-w-permFiltered", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/filter/mock-pf", nil)
		filteredServersMutex.Lock()
		filteredServers["mock-pf"] = permFiltered
		filteredServersMutex.Unlock()
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 400, w.Code)

		filteredServersMutex.RLock()
		defer filteredServersMutex.RUnlock()
		assert.Equal(t, permFiltered, filteredServers["mock-pf"])

		resB, err := io.ReadAll(w.Body)
		require.NoError(t, err)
		assert.Contains(t, string(resB), "Can't filter a server that already has been fitlered")
	})
	t.Run("filter-server-w-tempFiltered", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/filter/mock-tf", nil)
		filteredServersMutex.Lock()
		filteredServers["mock-tf"] = tempFiltered
		filteredServersMutex.Unlock()
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 400, w.Code)

		filteredServersMutex.RLock()
		defer filteredServersMutex.RUnlock()
		assert.Equal(t, tempFiltered, filteredServers["mock-tf"])

		resB, err := io.ReadAll(w.Body)
		require.NoError(t, err)
		assert.Contains(t, string(resB), "Can't filter a server that already has been fitlered")
	})
	t.Run("filter-server-w-tempAllowed", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/filter/mock-ta", nil)
		filteredServersMutex.Lock()
		filteredServers["mock-ta"] = tempAllowed
		filteredServersMutex.Unlock()
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 200, w.Code)

		filteredServersMutex.RLock()
		defer filteredServersMutex.RUnlock()
		assert.Equal(t, permFiltered, filteredServers["mock-ta"])
	})
	t.Run("filter-with-invalid-name", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/filter/", nil)
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 400, w.Code)
		resB, err := io.ReadAll(w.Body)
		require.NoError(t, err)
		assert.Contains(t, string(resB), "name is a required path parameter")
	})
}

func TestHandleAllowServer(t *testing.T) {
	t.Cleanup(func() {
		filteredServersMutex.Lock()
		defer filteredServersMutex.Unlock()
		filteredServers = map[string]filterType{}
	})
	router := gin.Default()
	router.GET("/servers/allow/*name", handleAllowServer)

	t.Run("allow-server-that-dne", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/allow/mock-dne", nil)
		filteredServersMutex.Lock()
		delete(filteredServers, "mock-dne")
		filteredServersMutex.Unlock()
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 400, w.Code)
		resB, err := io.ReadAll(w.Body)
		require.NoError(t, err)
		assert.Contains(t, string(resB), "Can't allow a server that is not being filtered.")
	})
	t.Run("allow-server-w-permFiltered", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/allow/mock-pf", nil)
		filteredServersMutex.Lock()
		filteredServers["mock-pf"] = permFiltered
		filteredServersMutex.Unlock()
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 200, w.Code)

		filteredServersMutex.RLock()
		defer filteredServersMutex.RUnlock()
		assert.Equal(t, tempAllowed, filteredServers["mock-pf"])
	})
	t.Run("allow-server-w-tempFiltered", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/allow/mock-tf", nil)
		filteredServersMutex.Lock()
		filteredServers["mock-tf"] = tempFiltered
		filteredServersMutex.Unlock()
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 200, w.Code)

		filteredServersMutex.RLock()
		defer filteredServersMutex.RUnlock()
		assert.Empty(t, filteredServers["mock-tf"])
	})
	t.Run("allow-server-w-tempAllowed", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/allow/mock-ta", nil)
		filteredServersMutex.Lock()
		filteredServers["mock-ta"] = tempAllowed
		filteredServersMutex.Unlock()
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 400, w.Code)

		filteredServersMutex.RLock()
		defer filteredServersMutex.RUnlock()
		assert.Equal(t, tempAllowed, filteredServers["mock-ta"])

		resB, err := io.ReadAll(w.Body)
		require.NoError(t, err)
		assert.Contains(t, string(resB), "Can't allow a server that is not being filtered.")
	})
	t.Run("allow-with-invalid-name", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/allow/", nil)
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 400, w.Code)
		resB, err := io.ReadAll(w.Body)
		require.NoError(t, err)
		assert.Contains(t, string(resB), "name is a required path parameter")
	})
}
