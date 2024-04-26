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

package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleWildcard(t *testing.T) {
	// Set up the router
	r := gin.New()
	group := r.Group("/registry")

	group.GET("/*wildcard", wildcardHandler)

	t.Run("match-prefix-returns-404-for-prefix-dne", func(t *testing.T) {
		setupMockRegistryDB(t)
		defer teardownMockNamespaceDB(t)

		req, _ := http.NewRequest("GET", "/registry/no-match", nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		// Should return 404 for an unmatched route
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("match-prefix-returns-namespace-if-exists", func(t *testing.T) {
		setupMockRegistryDB(t)
		defer teardownMockNamespaceDB(t)
		err := insertMockDBData([]server_structs.Namespace{{Prefix: "/foo/bar", AdminMetadata: server_structs.AdminMetadata{SiteName: "site foo"}}})
		require.NoError(t, err)

		req, _ := http.NewRequest("GET", "/registry/foo/bar", nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		bytes, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		ns := server_structs.Namespace{}
		err = json.Unmarshal(bytes, &ns)
		require.NoError(t, err)
		assert.Equal(t, "site foo", ns.AdminMetadata.SiteName)
	})

	t.Run("match-wildcard-metadataHandler", func(t *testing.T) {
		viper.Reset()
		mockPrefix := "/testnamespace/foo"

		setupMockRegistryDB(t)
		defer teardownMockNamespaceDB(t)

		mockJWKS := jwk.NewSet()
		mockJWKSBytes, err := json.Marshal(mockJWKS)
		require.NoError(t, err)
		err = insertMockDBData([]server_structs.Namespace{{Prefix: mockPrefix, Pubkey: string(mockJWKSBytes)}})
		require.NoError(t, err)
		mockNs, err := getNamespaceByPrefix(mockPrefix)

		require.NoError(t, err)
		require.NotNil(t, mockNs)

		req, _ := http.NewRequest("GET", fmt.Sprintf("/registry%s/.well-known/issuer.jwks", mockPrefix), nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		// Return 200 as by default Registry.RequireOriginApproval == false
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
			viper.Set("Registry.RequireCacheApproval", tc.CacheApprovedOnly)
			viper.Set("Registry.RequireOriginApproval", tc.OriginApprovedOnly)

			mockPrefix := "/testnamespace/foo"
			if tc.IsCache {
				mockPrefix = "/caches/hostname"
			}

			setupMockRegistryDB(t)
			defer teardownMockNamespaceDB(t)

			mockJWKS := jwk.NewSet()
			mockJWKSBytes, err := json.Marshal(mockJWKS)
			require.NoError(t, err)

			mockStatus := server_structs.RegPending
			if tc.IsApproved {
				mockStatus = server_structs.RegApproved
			}
			err = insertMockDBData([]server_structs.Namespace{{Prefix: mockPrefix, Pubkey: string(mockJWKSBytes), AdminMetadata: server_structs.AdminMetadata{Status: mockStatus}}})
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
