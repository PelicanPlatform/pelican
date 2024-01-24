package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/spf13/viper"
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

	t.Run("match-wildcard-metadataHandler", func(t *testing.T) {
		viper.Reset()
		mockPrefix := "/testnamespace/foo"

		setupMockRegistryDB(t)
		defer teardownMockNamespaceDB(t)

		mockJWKS := jwk.NewSet()
		mockJWKSBytes, err := json.Marshal(mockJWKS)
		require.NoError(t, err)
		err = insertMockDBData([]Namespace{{Prefix: mockPrefix, Pubkey: string(mockJWKSBytes)}})
		require.NoError(t, err)
		mockNs, err := getNamespaceByPrefix(mockPrefix)

		require.NoError(t, err)
		require.NotNil(t, mockNs)

		req, _ := http.NewRequest("GET", fmt.Sprintf("/registry%s/.well-known/issuer.jwks", mockPrefix), nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		// Return 200 as by default Registry.OriginApprovedOnly == false
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, string(mockJWKSBytes), w.Body.String())
	})

	mockApprovalTcs := []struct {
		Name               string
		CacheApprovedOnly  bool
		OriginApprovedOnly bool
		IsApproved         bool
		IsCache            bool
		ExpectedCode       int
	}{
		{
			Name:               "cache-origin-both-req-approv-origin-no-approv",
			CacheApprovedOnly:  true,
			OriginApprovedOnly: true,
			IsApproved:         false,
			IsCache:            false,
			ExpectedCode:       403,
		},
		{
			Name:               "cache-origin-both-req-approv-cache-no-approv",
			CacheApprovedOnly:  true,
			OriginApprovedOnly: true,
			IsApproved:         false,
			IsCache:            true,
			ExpectedCode:       403,
		},
		{
			Name:               "cache-origin-both-req-approv-origin-approv",
			CacheApprovedOnly:  true,
			OriginApprovedOnly: true,
			IsApproved:         true,
			IsCache:            false,
			ExpectedCode:       200,
		},
		{
			Name:               "cache-origin-both-req-approv-cache-approv",
			CacheApprovedOnly:  true,
			OriginApprovedOnly: true,
			IsApproved:         true,
			IsCache:            true,
			ExpectedCode:       200,
		},
	}

	for _, tc := range mockApprovalTcs {
		t.Run(tc.Name, func(t *testing.T) {
			viper.Reset()
			viper.Set("Registry.CacheApprovedOnly", tc.CacheApprovedOnly)
			viper.Set("Registry.OriginApprovedOnly", tc.OriginApprovedOnly)

			mockPrefix := "/testnamespace/foo"
			if tc.IsCache {
				mockPrefix = "/caches/hostname"
			}

			setupMockRegistryDB(t)
			defer teardownMockNamespaceDB(t)

			mockJWKS := jwk.NewSet()
			mockJWKSBytes, err := json.Marshal(mockJWKS)
			require.NoError(t, err)

			mockStatus := Pending
			if tc.IsApproved {
				mockStatus = Approved
			}
			err = insertMockDBData([]Namespace{{Prefix: mockPrefix, Pubkey: string(mockJWKSBytes), AdminMetadata: AdminMetadata{Status: mockStatus}}})
			require.NoError(t, err)
			mockNs, err := getNamespaceByPrefix(mockPrefix)

			require.NoError(t, err)
			require.NotNil(t, mockNs)

			req, _ := http.NewRequest("GET", fmt.Sprintf("/registry%s/.well-known/issuer.jwks", mockPrefix), nil)
			w := httptest.NewRecorder()

			r.ServeHTTP(w, req)

			assert.Equal(t, tc.ExpectedCode, w.Code)
			if tc.ExpectedCode == 200 {
				assert.Equal(t, string(mockJWKSBytes), w.Body.String())
			}
		})
	}
}
