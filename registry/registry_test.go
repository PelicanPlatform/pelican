package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleWildcard(t *testing.T) {
	// Set up the router
	r := gin.New()
	group := r.Group("/registry")

	group.GET("/*wildcard", wildcardHandler)

	t.Run("return-404-for-unmatched-route", func(t *testing.T) {
		// Create a test request
		req, _ := http.NewRequest("GET", "/registry/no-match", nil)
		w := httptest.NewRecorder()

		// Perform the request
		r.ServeHTTP(w, req)

		// Should return 404 for an unmatched route
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("match-getNamespace", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/registry/getNamespace", nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		// /getNamespace requires X-Pelican-Prefix header to be set or it will return 400
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("match-wildcard-metadataHandler", func(t *testing.T) {
		mockPrefix := "/testnamespace/foo"

		setupMockRegistryDB(t)
		defer teardownMockNamespaceDB(t)

		mockJWKS := jwk.NewSet()
		mockJWKSBytes, err := json.Marshal(mockJWKS)
		require.NoError(t, err)
		insertMockDBData([]Namespace{{Prefix: mockPrefix, Pubkey: string(mockJWKSBytes)}})
		mockNs, err := getNamespaceByPrefix(mockPrefix)

		require.NoError(t, err)
		require.NotNil(t, mockNs)

		req, _ := http.NewRequest("GET", fmt.Sprintf("/registry%s/.well-known/issuer.jwks", mockPrefix), nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		// Should return 200 for matched metadataHandler since the db is empty
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, string(mockJWKSBytes), string(w.Body.Bytes()))
	})
}
