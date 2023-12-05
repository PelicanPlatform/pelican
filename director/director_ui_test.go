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

	t.Run("query-origin", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers?server_type=origin", nil)
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 200, w.Code)

		var got []ServerAd
		err := json.Unmarshal(w.Body.Bytes(), &got)
		if err != nil {
			t.Fatalf("Failed to unmarshal response body: %v", err)
		}
		require.Equal(t, 1, len(got))
		assert.Equal(t, mockOriginServerAd, got[0], "Response data does not match expected")
	})

	t.Run("query-cache", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers?server_type=cache", nil)
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 200, w.Code)

		var got []ServerAd
		err := json.Unmarshal(w.Body.Bytes(), &got)
		if err != nil {
			t.Fatalf("Failed to unmarshal response body: %v", err)
		}
		require.Equal(t, 1, len(got))
		assert.Equal(t, mockCacheServerAd, got[0], "Response data does not match expected")
	})

	t.Run("query-all-with-empty-server-type", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers?server_type=", nil)
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 200, w.Code)

		var got []ServerAd
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

		var got []ServerAd
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
