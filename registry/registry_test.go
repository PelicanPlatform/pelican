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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
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

func TestCheckNamespaceCompleteHandler(t *testing.T) {
	setupMockRegistryDB(t)
	router := gin.New()
	router.POST("/namespaces/check/status", checkStatusHandler)

	t.Cleanup(func() {
		viper.Reset()
		config.ResetFederationForTest()
	})

	t.Run("request-without-body", func(t *testing.T) {
		r := httptest.NewRecorder()
		req, err := http.NewRequest(http.MethodPost, "/namespaces/check/status", nil)
		require.NoError(t, err)
		router.ServeHTTP(r, req)
		assert.Equal(t, 400, r.Result().StatusCode)
	})

	t.Run("request-without-body", func(t *testing.T) {
		r := httptest.NewRecorder()
		reqBody := server_structs.CheckNamespaceCompleteReq{}
		reqBodyBytes, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, "/namespaces/check/status", bytes.NewBuffer(reqBodyBytes))
		require.NoError(t, err)
		router.ServeHTTP(r, req)
		assert.Equal(t, 200, r.Result().StatusCode)

		resBody, err := io.ReadAll(r.Result().Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"results":{}}`, string(resBody))
	})

	t.Run("request-prefix-dne", func(t *testing.T) {
		resetNamespaceDB(t)

		r := httptest.NewRecorder()
		reqBody := server_structs.CheckNamespaceCompleteReq{Prefixes: []string{"/prefix-dne"}}
		reqBodyBytes, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, "/namespaces/check/status", bytes.NewBuffer(reqBodyBytes))
		require.NoError(t, err)
		router.ServeHTTP(r, req)
		assert.Equal(t, 200, r.Result().StatusCode)

		resBody, err := io.ReadAll(r.Result().Body)
		resStruct := server_structs.CheckNamespaceCompleteRes{}
		require.NoError(t, err)
		err = json.Unmarshal(resBody, &resStruct)
		require.NoError(t, err)

		result, ok := resStruct.Results["/prefix-dne"]
		require.True(t, ok)
		assert.False(t, result.Completed)
		assert.Empty(t, result.EditUrl)
		assert.Equal(t, "Namespace /prefix-dne does not exist", result.Msg)
	})

	t.Run("incomplete-registration", func(t *testing.T) {
		resetNamespaceDB(t)
		viper.Reset()
		config.ResetFederationForTest()
		config.SetFederation(config.FederationDiscovery{
			NamespaceRegistrationEndpoint: "https://registry.org",
		})

		mockJWKS, err := test_utils.GenerateJWKS()
		require.NoError(t, err)

		// Institution and UserId are empty
		err = insertMockDBData([]server_structs.Namespace{mockNamespace("/incomplete-prefix", mockJWKS, "", server_structs.AdminMetadata{})})
		require.NoError(t, err)

		r := httptest.NewRecorder()
		reqBody := server_structs.CheckNamespaceCompleteReq{Prefixes: []string{"/incomplete-prefix"}}
		reqBodyBytes, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, "/namespaces/check/status", bytes.NewBuffer(reqBodyBytes))
		require.NoError(t, err)
		router.ServeHTTP(r, req)
		assert.Equal(t, 200, r.Result().StatusCode)

		resBody, err := io.ReadAll(r.Result().Body)
		resStruct := server_structs.CheckNamespaceCompleteRes{}
		require.NoError(t, err)
		err = json.Unmarshal(resBody, &resStruct)
		require.NoError(t, err)

		result, ok := resStruct.Results["/incomplete-prefix"]
		require.True(t, ok)
		assert.False(t, result.Completed)
		assert.Contains(t, result.EditUrl, "https://registry.org/view/registry/namespace/edit/?id=")
		assert.Contains(t, result.Msg, "Incomplete registration:")
	})

	t.Run("complete-registration", func(t *testing.T) {
		resetNamespaceDB(t)
		viper.Reset()
		config.ResetFederationForTest()
		config.SetFederation(config.FederationDiscovery{
			NamespaceRegistrationEndpoint: "https://registry.org",
		})

		mockJWKS, err := test_utils.GenerateJWKS()
		require.NoError(t, err)
		// Institution and UserId are empty
		err = insertMockDBData(
			[]server_structs.Namespace{
				mockNamespace(
					"/complete-prefix",
					mockJWKS,
					"",
					server_structs.AdminMetadata{UserID: "fake-user-id", Institution: "mock-institution"},
				),
			},
		)
		require.NoError(t, err)

		r := httptest.NewRecorder()
		reqBody := server_structs.CheckNamespaceCompleteReq{Prefixes: []string{"/complete-prefix"}}
		reqBodyBytes, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, "/namespaces/check/status", bytes.NewBuffer(reqBodyBytes))
		require.NoError(t, err)
		router.ServeHTTP(r, req)
		assert.Equal(t, 200, r.Result().StatusCode)

		resBody, err := io.ReadAll(r.Result().Body)
		resStruct := server_structs.CheckNamespaceCompleteRes{}
		require.NoError(t, err)
		err = json.Unmarshal(resBody, &resStruct)
		require.NoError(t, err)

		result, ok := resStruct.Results["/complete-prefix"]
		require.True(t, ok)
		assert.True(t, result.Completed)
		assert.Contains(t, result.EditUrl, "https://registry.org/view/registry/namespace/edit/?id=")
		assert.Empty(t, result.Msg)
	})

	t.Run("multiple-complete-registrations", func(t *testing.T) {
		resetNamespaceDB(t)
		viper.Reset()
		config.ResetFederationForTest()
		config.SetFederation(config.FederationDiscovery{
			NamespaceRegistrationEndpoint: "https://registry.org",
		})

		mockJWKS, err := test_utils.GenerateJWKS()
		require.NoError(t, err)
		// Institution and UserId are empty
		err = insertMockDBData(
			[]server_structs.Namespace{
				mockNamespace(
					"/complete-prefix-1",
					mockJWKS,
					"",
					server_structs.AdminMetadata{UserID: "fake-user-id", Institution: "mock-institution"},
				),
				mockNamespace(
					"/complete-prefix-2",
					mockJWKS,
					"",
					server_structs.AdminMetadata{UserID: "fake-user-id", Institution: "mock-institution"},
				),
				mockNamespace(
					"/foo/bar",
					mockJWKS,
					"",
					server_structs.AdminMetadata{UserID: "fake-user-id", Institution: "mock-institution"},
				),
			},
		)
		require.NoError(t, err)

		r := httptest.NewRecorder()
		reqBody := server_structs.CheckNamespaceCompleteReq{Prefixes: []string{"/complete-prefix-1", "/complete-prefix-2", "/foo/bar"}}
		reqBodyBytes, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, "/namespaces/check/status", bytes.NewBuffer(reqBodyBytes))
		require.NoError(t, err)
		router.ServeHTTP(r, req)
		assert.Equal(t, 200, r.Result().StatusCode)

		resBody, err := io.ReadAll(r.Result().Body)
		resStruct := server_structs.CheckNamespaceCompleteRes{}
		require.NoError(t, err)
		err = json.Unmarshal(resBody, &resStruct)
		require.NoError(t, err)

		result, ok := resStruct.Results["/complete-prefix-1"]
		require.True(t, ok)
		assert.True(t, result.Completed)
		assert.Contains(t, result.EditUrl, "https://registry.org/view/registry/namespace/edit/?id=")
		assert.Empty(t, result.Msg)

		result, ok = resStruct.Results["/complete-prefix-2"]
		require.True(t, ok)
		assert.True(t, result.Completed)
		assert.Contains(t, result.EditUrl, "https://registry.org/view/registry/namespace/edit/?id=")
		assert.Empty(t, result.Msg)

		result, ok = resStruct.Results["/foo/bar"]
		require.True(t, ok)
		assert.True(t, result.Completed)
		assert.Contains(t, result.EditUrl, "https://registry.org/view/registry/namespace/edit/?id=")
		assert.Empty(t, result.Msg)
	})
}
