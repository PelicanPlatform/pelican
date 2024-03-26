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
