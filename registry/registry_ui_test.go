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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock wrong data fields for Institution
type mockBadInstitutionFormat struct {
	RORID string `yaml:"ror_id"`
	Inst  string `yaml:"institution"`
}

func GenerateMockJWKS() (string, error) {
	// Create a private key to use for the test
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", errors.Wrap(err, "Error generating private key")
	}

	// Convert from raw ecdsa to jwk.Key
	pKey, err := jwk.FromRaw(privateKey)
	if err != nil {
		return "", errors.Wrap(err, "Unable to convert ecdsa.PrivateKey to jwk.Key")
	}

	//Assign Key id to the private key
	err = jwk.AssignKeyID(pKey)
	if err != nil {
		return "", errors.Wrap(err, "Error assigning kid to private key")
	}

	//Set an algorithm for the key
	err = pKey.Set(jwk.AlgorithmKey, jwa.ES256)
	if err != nil {
		return "", errors.Wrap(err, "Unable to set algorithm for pKey")
	}

	publicKey, err := pKey.PublicKey()
	if err != nil {
		return "", errors.Wrap(err, "Unable to get the public key from private key")
	}

	jwks := jwk.NewSet()
	err = jwks.AddKey(publicKey)
	if err != nil {
		return "", errors.Wrap(err, "Unable to add public key to the jwks")
	}

	jsonData, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		return "", errors.Wrap(err, "Unable to marshal the json into string")
	}
	// Append a new line to the JSON data
	jsonData = append(jsonData, '\n')

	return string(jsonData), nil
}

func TestListNamespaces(t *testing.T) {
	viper.Reset()
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	// Initialize the mock database
	setupMockRegistryDB(t)
	defer teardownMockNamespaceDB(t)

	viper.Set("Server.WebPort", 0)
	viper.Set("Server.ExternalWebUrl", "https://mock-server.com")

	dirName := t.TempDir()
	viper.Set("ConfigDir", dirName)
	viper.Set("Origin.Port", 0)
	err := config.InitServer(ctx, config.OriginType)
	require.NoError(t, err)
	err = config.GeneratePrivateKey(param.IssuerKey.GetString(), elliptic.P256(), false)
	require.NoError(t, err)

	router := gin.Default()

	router.GET("/namespaces", listNamespaces)

	tests := []struct {
		description  string
		serverType   string
		status       string
		expectedCode int
		emptyDB      bool
		notApproved  bool
		authUser     bool
		expectedData []server_structs.Namespace
	}{
		{
			description:  "valid-request-with-empty-db",
			serverType:   string(OriginType),
			expectedCode: http.StatusOK,
			emptyDB:      true,
			expectedData: []server_structs.Namespace{},
		},
		{
			description:  "valid-request-with-origin-type",
			serverType:   string(OriginType),
			expectedCode: http.StatusOK,
			expectedData: mockNssWithOrigins,
		},
		{
			description:  "valid-request-with-cache-type",
			serverType:   string(CacheType),
			expectedCode: http.StatusOK,
			expectedData: mockNssWithCaches,
		},
		{
			description:  "valid-request-without-type",
			expectedCode: http.StatusOK,
			expectedData: mockNssWithMixed,
		},
		{
			description:  "unauthed-not-approved-without-type-returns-empty",
			expectedCode: http.StatusOK,
			expectedData: []server_structs.Namespace{},
			notApproved:  true,
		},
		{
			description:  "unauthed-with-status-pending-returns-403",
			expectedCode: http.StatusForbidden,
			status:       "Pending",
			expectedData: []server_structs.Namespace{},
			notApproved:  true,
			authUser:     false,
		},
		{
			description:  "authed-not-approved-returns",
			expectedCode: http.StatusOK,
			expectedData: mockNssWithMixedNotApproved,
			notApproved:  true,
			authUser:     true,
		},
		{
			description:  "authed-returns-filtered-approved-status",
			expectedCode: http.StatusOK,
			status:       "Approved",
			expectedData: []server_structs.Namespace{},
			notApproved:  true,
			authUser:     true,
		},
		{
			description:  "authed-returns-filtered-pending-status",
			expectedCode: http.StatusOK,
			status:       "Pending",
			expectedData: mockNssWithMixedNotApproved,
			notApproved:  true,
			authUser:     true,
		},
		{
			description:  "authed-returns-400-with-random-status",
			expectedCode: http.StatusBadRequest,
			status:       "random",
			expectedData: nil,
			authUser:     true,
		},
		{
			description:  "invalid-request-parameters",
			serverType:   "random_type", // some invalid query string
			expectedCode: http.StatusBadRequest,
			expectedData: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			if !tc.emptyDB {
				if tc.notApproved {
					err := insertMockDBData(mockNssWithMixedNotApproved)
					if err != nil {
						t.Fatalf("Failed to set up mock data: %v", err)
					}
				} else {
					err := insertMockDBData(mockNssWithMixed)
					if err != nil {
						t.Fatalf("Failed to set up mock data: %v", err)
					}
				}
			}
			defer func() {
				resetNamespaceDB(t)
			}()

			// Create a request to the endpoint
			w := httptest.NewRecorder()
			requestURL := "/namespaces?server_type=" + tc.serverType + "&status=" + tc.status
			req, _ := http.NewRequest("GET", requestURL, nil)
			if tc.authUser {
				tokenCfg := token.NewWLCGToken()
				tokenCfg.Issuer = "https://mock-server.com"
				tokenCfg.Lifetime = time.Minute
				tokenCfg.Subject = "admin"
				tokenCfg.AddScopes(token_scopes.WebUi_Access)
				tokenCfg.AddAudienceAny()
				token, err := tokenCfg.CreateToken()
				require.NoError(t, err)
				req.AddCookie(&http.Cookie{Name: "login", Value: token, Path: "/"})
			}
			router.ServeHTTP(w, req)

			// Check the response
			assert.Equal(t, tc.expectedCode, w.Code)

			if tc.expectedCode == http.StatusOK {
				var got []server_structs.Namespace
				err := json.Unmarshal(w.Body.Bytes(), &got)
				if err != nil {
					t.Fatalf("Failed to unmarshal response body: %v", err)
				}
				assert.True(t, compareNamespaces(tc.expectedData, got, true), "Response data does not match expected")
			}
		})
	}
}

func TestListNamespacesForUser(t *testing.T) {
	viper.Reset()
	_, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	// Initialize the mock database
	setupMockRegistryDB(t)
	defer teardownMockNamespaceDB(t)

	mockUserNss := func() []server_structs.Namespace {
		return []server_structs.Namespace{
			mockNamespace("/foo", "", "", server_structs.AdminMetadata{UserID: "mockUser", Status: server_structs.RegPending}),
			mockNamespace("/bar", "", "", server_structs.AdminMetadata{UserID: "mockUser", Status: server_structs.RegApproved}),
		}
	}()

	tests := []struct {
		description  string
		expectedCode int
		emptyDB      bool
		authUser     bool
		queryParam   string
		expectedData []server_structs.Namespace
	}{
		{
			description:  "unauthed-return-401",
			expectedCode: http.StatusUnauthorized,
			expectedData: []server_structs.Namespace{},
		},
		{
			description:  "valid-request-with-empty-db",
			expectedCode: http.StatusOK,
			emptyDB:      true,
			expectedData: []server_structs.Namespace{},
			authUser:     true,
		},
		{
			description:  "valid-request-without-type",
			expectedCode: http.StatusOK,
			expectedData: mockUserNss,
			authUser:     true,
		},
		{
			description:  "invalid-request-parameters",
			expectedCode: http.StatusBadRequest,
			queryParam:   "?status=random",
			expectedData: nil,
			authUser:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			if !tc.emptyDB {
				err := insertMockDBData(mockNssWithMixed)
				require.NoErrorf(t, err, "Failed to set up mock data: %v", err)
				err = insertMockDBData(mockUserNss)
				require.NoErrorf(t, err, "Failed to set up mock data: %v", err)
			}
			defer func() {
				resetNamespaceDB(t)
			}()

			// Create a request to the endpoint
			w := httptest.NewRecorder()
			requestURL := "/namespaces/user" + tc.queryParam
			req, _ := http.NewRequest("GET", requestURL, nil)
			if tc.authUser {
				router := gin.Default()
				router.GET("/namespaces/user", func(ctx *gin.Context) {
					ctx.Set("User", "mockUser")
				}, listNamespacesForUser)
				router.ServeHTTP(w, req)
			} else {
				router := gin.Default()
				router.GET("/namespaces/user", listNamespacesForUser)
				router.ServeHTTP(w, req)
			}

			// Check the response
			assert.Equal(t, tc.expectedCode, w.Code)

			if tc.expectedCode == http.StatusOK {
				var got []server_structs.Namespace
				err := json.Unmarshal(w.Body.Bytes(), &got)
				require.NoErrorf(t, err, "Failed to unmarshal response body: %v", err)
				assert.True(t, compareNamespaces(tc.expectedData, got, true), "Response data does not match expected")
			}
		})
	}
}

func TestGetNamespace(t *testing.T) {
	_, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	// Initialize the mock database
	setupMockRegistryDB(t)
	defer teardownMockNamespaceDB(t)

	mockUserNs := mockNamespace("/mockUser", "", "", server_structs.AdminMetadata{UserID: "mockUser"})

	tests := []struct {
		description  string
		requestId    string
		expectedCode int
		validID      bool
		checkAdmin   bool
		userName     string
	}{
		{
			description:  "valid-request-with-empty-key",
			expectedCode: http.StatusOK,
			validID:      true,
		},
		{
			description:  "invalid-request-with-str-id",
			requestId:    "crazy-id",
			expectedCode: http.StatusBadRequest,
		},
		{
			description:  "invalid-request-with-0-id",
			requestId:    "0",
			expectedCode: http.StatusBadRequest,
		},
		{
			description:  "invalid-request-with-neg-id",
			requestId:    "-10000",
			expectedCode: http.StatusBadRequest,
		},
		{
			description: "invalid-request-with-empty-id",
			requestId:   "",
			// empty id will resolve a child path of /test which DNE
			expectedCode: http.StatusNotFound,
		},
		{
			description:  "invalid-request-with-id-not-found",
			requestId:    "100",
			expectedCode: http.StatusNotFound,
		},
		{
			description:  "user-can-see-their-own-ns",
			validID:      true,
			checkAdmin:   true,
			userName:     "mockUser",
			expectedCode: http.StatusOK,
		},
		{
			description:  "user-cannot-see-others-ns",
			validID:      true,
			checkAdmin:   true,
			userName:     "randomUser",
			expectedCode: http.StatusForbidden,
		},
		{
			description:  "admin-can-see-any-ns",
			validID:      true,
			checkAdmin:   true,
			userName:     "admin",
			expectedCode: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			if tc.checkAdmin {
				err := insertMockDBData([]server_structs.Namespace{mockUserNs})
				require.NoErrorf(t, err, "Failed to set up mock data: %v", err)
			} else {
				err := insertMockDBData(mockNssWithMixed)
				require.NoErrorf(t, err, "Failed to set up mock data: %v", err)
			}
			defer resetNamespaceDB(t)

			finalId := tc.requestId
			if tc.validID {
				id, err := getLastNamespaceId()
				finalId = strconv.Itoa(id)
				require.NoError(t, err)
			}

			// Create a request to the endpoint
			w := httptest.NewRecorder()
			requestURL := fmt.Sprint("/test/", finalId)
			req, _ := http.NewRequest("GET", requestURL, nil)

			if tc.checkAdmin {
				router := gin.Default()
				router.GET("/test/:id", func(ctx *gin.Context) {
					ctx.Set("User", tc.userName)
				}, getNamespace)
				router.ServeHTTP(w, req)
			} else {
				router := gin.Default()
				router.GET("/test/:id", getNamespace)
				router.ServeHTTP(w, req)
			}

			// Check the response
			require.Equal(t, tc.expectedCode, w.Code)

			if tc.expectedCode == 200 {
				getNs := server_structs.Namespace{}

				bytes, err := io.ReadAll(w.Body)
				require.NoError(t, err)
				err = json.Unmarshal(bytes, &getNs)
				require.NoError(t, err)

				require.NotEqual(t, server_structs.Namespace{}, getNs)
			}
		})
	}
}

func TestGetNamespaceJWKS(t *testing.T) {
	_, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	mockPublicKey, err := GenerateMockJWKS()
	if err != nil {
		t.Fatalf("Failed to set up mock public key: %v", err)
	}
	// Initialize the mock database
	setupMockRegistryDB(t)
	defer teardownMockNamespaceDB(t)

	router := gin.Default()

	router.GET("/test/:id/pubkey", getNamespaceJWKS)

	tests := []struct {
		description  string
		requestId    string
		expectedCode int
		emptyDB      bool
		expectedData string
	}{
		{
			description:  "valid-request-with-empty-key",
			requestId:    "1",
			expectedCode: http.StatusOK,
			expectedData: mockPublicKey,
		},
		{
			description:  "invalid-request-with-str-id",
			requestId:    "crazy-id",
			expectedCode: http.StatusBadRequest,
			expectedData: "",
		},
		{
			description:  "invalid-request-with-0-id",
			requestId:    "0",
			expectedCode: http.StatusBadRequest,
		},
		{
			description:  "invalid-request-with-neg-id",
			requestId:    "-10000",
			expectedCode: http.StatusBadRequest,
		},
		{
			description:  "invalid-request-with-empty-id",
			requestId:    "",
			expectedCode: http.StatusBadRequest,
		},
		{
			description:  "invalid-request-with-id-not-found",
			requestId:    "100",
			expectedCode: http.StatusNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			if !tc.emptyDB {
				err := insertMockDBData([]server_structs.Namespace{
					{
						ID:     1,
						Prefix: "/origin1",
						Pubkey: mockPublicKey,
					},
				})
				if err != nil {
					t.Fatalf("Failed to set up mock data: %v", err)
				}

			}
			defer resetNamespaceDB(t)

			// Create a request to the endpoint
			w := httptest.NewRecorder()
			requestURL := fmt.Sprint("/test/", tc.requestId, "/pubkey")
			req, _ := http.NewRequest("GET", requestURL, nil)
			router.ServeHTTP(w, req)

			// Check the response
			require.Equal(t, tc.expectedCode, w.Code)

			if tc.expectedCode == http.StatusOK {
				assert.Equal(t, tc.expectedData, w.Body.String())
			}
		})
	}
}

func TestUpdateNamespaceStatus(t *testing.T) {
	_, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	// Initialize the mock database
	setupMockRegistryDB(t)
	defer teardownMockNamespaceDB(t)

	mockUserNs := mockNamespace("/mockUser", "", "", server_structs.AdminMetadata{UserID: "mockUser"})

	tests := []struct {
		description  string
		requestId    string
		expectedCode int
		validID      bool
	}{
		{
			description:  "invalid-request-with-str-id",
			requestId:    "crazy-id",
			expectedCode: http.StatusBadRequest,
		},
		{
			description:  "invalid-request-with-0-id",
			requestId:    "0",
			expectedCode: http.StatusBadRequest,
		},
		{
			description:  "invalid-request-with-neg-id",
			requestId:    "-10000",
			expectedCode: http.StatusBadRequest,
		},
		{
			description:  "invalid-request-with-empty-id",
			requestId:    "",
			expectedCode: http.StatusBadRequest,
		},
		{
			description:  "invalid-request-with-id-not-found",
			requestId:    "100",
			expectedCode: http.StatusNotFound,
		},
		{
			description:  "valid-id-should-update-correctly",
			validID:      true,
			expectedCode: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			err := insertMockDBData([]server_structs.Namespace{mockUserNs})
			require.NoErrorf(t, err, "Failed to set up mock data: %v", err)
			defer resetNamespaceDB(t)

			router := gin.Default()
			router.PATCH("/test/:id/approve", func(ctx *gin.Context) {
				ctx.Set("User", "admin")
				updateNamespaceStatus(ctx, server_structs.RegApproved)
			})
			router.PATCH("/test/:id/deny", func(ctx *gin.Context) {
				ctx.Set("User", "admin")
				updateNamespaceStatus(ctx, server_structs.RegDenied)
			})

			finalId := tc.requestId
			if tc.validID {
				id, err := getLastNamespaceId()
				finalId = strconv.Itoa(id)
				require.NoError(t, err)
			}

			// Create a request to the endpoint
			wApprove := httptest.NewRecorder()
			requestURLApprove := fmt.Sprint("/test/", finalId, "/approve")
			reqApprove, _ := http.NewRequest("PATCH", requestURLApprove, nil)

			router.ServeHTTP(wApprove, reqApprove)

			// Check the response
			require.Equal(t, tc.expectedCode, wApprove.Code)

			if tc.expectedCode == 200 {
				bytes, err := io.ReadAll(wApprove.Body)
				require.NoError(t, err)
				assert.JSONEq(t, `{"msg":"success", "status":"success"}`, string(bytes))

				if tc.validID {
					intId, err := strconv.Atoi(finalId)
					require.NoError(t, err)
					ns, err := getNamespaceById(intId)
					require.NoError(t, err)
					assert.True(t, ns.AdminMetadata.Status == server_structs.RegApproved)
					assert.NotEqual(t, time.Time{}, ns.AdminMetadata.ApprovedAt)
					assert.Equal(t, "admin", ns.AdminMetadata.ApproverID)
				}
			}
		})
	}
}

func TestCreateNamespace(t *testing.T) {
	viper.Reset()
	_, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	// Initialize the mock database
	setupMockRegistryDB(t)
	defer teardownMockNamespaceDB(t)

	router := gin.Default()
	router.POST("/namespaces", func(ctx *gin.Context) {
		ctx.Set("User", "admin")
		createUpdateNamespace(ctx, false)
	})

	t.Run("no-user-returns-401", func(t *testing.T) {
		resetNamespaceDB(t)

		router := gin.Default()
		router.POST("/namespaces", func(ctx *gin.Context) {
			createUpdateNamespace(ctx, false)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/namespaces", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
	})

	t.Run("empty-request-returns-400", func(t *testing.T) {
		resetNamespaceDB(t)

		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/namespaces", nil)
		router.ServeHTTP(w, req)

		body, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		assert.JSONEq(t, `{"msg":"Invalid create or update namespace request", "status":"error"}`, string(body))
	})

	t.Run("missing-required-fields-returns-400", func(t *testing.T) {
		resetNamespaceDB(t)

		mockEmptyNs := server_structs.Namespace{}
		mockEmptyNsBytes, err := json.Marshal(mockEmptyNs)
		require.NoError(t, err)
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/namespaces", bytes.NewReader(mockEmptyNsBytes))
		req.Header.Set("Context-Type", "application/json")
		router.ServeHTTP(w, req)

		body, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		assert.Contains(t, string(body), "Field validation for 'Prefix' failed on the 'required' tag")
		assert.Contains(t, string(body), "Field validation for 'Pubkey' failed on the 'required' tag")
		assert.Contains(t, string(body), "Field validation for 'Institution' failed on the 'required' tag")
	})

	t.Run("invalid-prefix-returns-400", func(t *testing.T) {
		resetNamespaceDB(t)

		mockEmptyNs := server_structs.Namespace{Prefix: "/", Pubkey: "badKey", AdminMetadata: server_structs.AdminMetadata{Institution: "001"}}
		mockEmptyNsBytes, err := json.Marshal(mockEmptyNs)
		require.NoError(t, err)
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/namespaces", bytes.NewReader(mockEmptyNsBytes))
		req.Header.Set("Context-Type", "application/json")
		router.ServeHTTP(w, req)

		body, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		assert.Contains(t, string(body), "Error: Field validation for prefix failed:")
	})

	t.Run("existing-prefix-returns-400", func(t *testing.T) {
		resetNamespaceDB(t)
		err := insertMockDBData([]server_structs.Namespace{{Prefix: "/foo", Pubkey: "badKey", AdminMetadata: server_structs.AdminMetadata{Status: server_structs.RegPending}}})
		require.NoError(t, err)
		defer resetNamespaceDB(t)

		mockNs := server_structs.Namespace{Prefix: "/foo", Pubkey: "badKey", AdminMetadata: server_structs.AdminMetadata{Institution: "001"}}
		mockNsBytes, err := json.Marshal(mockNs)
		require.NoError(t, err)
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/namespaces", bytes.NewReader(mockNsBytes))
		req.Header.Set("Context-Type", "application/json")
		router.ServeHTTP(w, req)

		body, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		assert.Contains(t, string(body), "The prefix /foo is already registered")
	})

	t.Run("bad-pubkey-returns-400", func(t *testing.T) {
		resetNamespaceDB(t)

		mockNs := server_structs.Namespace{Prefix: "/foo", Pubkey: "badKey", AdminMetadata: server_structs.AdminMetadata{Institution: "001"}}
		mockNsBytes, err := json.Marshal(mockNs)
		require.NoError(t, err)
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/namespaces", bytes.NewReader(mockNsBytes))
		req.Header.Set("Context-Type", "application/json")
		router.ServeHTTP(w, req)

		body, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		assert.Contains(t, string(body), "Error: Field validation for pubkey failed:")
	})

	t.Run("duplicated-key-returns-400", func(t *testing.T) {
		resetNamespaceDB(t)

		pubKeyStr, err := GenerateMockJWKS()
		require.NoError(t, err)

		err = insertMockDBData([]server_structs.Namespace{{Prefix: "/foo", Pubkey: pubKeyStr, AdminMetadata: server_structs.AdminMetadata{Status: server_structs.RegPending}}})
		require.NoError(t, err)
		defer resetNamespaceDB(t)

		diffPubKeyStr, err := GenerateMockJWKS()
		require.NoError(t, err)

		mockNs := server_structs.Namespace{Prefix: "/foo", Pubkey: diffPubKeyStr, AdminMetadata: server_structs.AdminMetadata{Institution: "001"}}
		mockNsBytes, err := json.Marshal(mockNs)
		require.NoError(t, err)
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/namespaces", bytes.NewReader(mockNsBytes))
		req.Header.Set("Context-Type", "application/json")
		router.ServeHTTP(w, req)

		body, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		assert.Contains(t, string(body), "The prefix /foo is already registered")
	})

	t.Run("key-chaining-failure-returns-400", func(t *testing.T) {
		viper.Reset()
		viper.Set("Registry.RequireKeyChaining", true)
		resetNamespaceDB(t)

		pubKeyStr, err := GenerateMockJWKS()
		require.NoError(t, err)

		err = insertMockDBData([]server_structs.Namespace{{Prefix: "/foo", Pubkey: pubKeyStr, AdminMetadata: server_structs.AdminMetadata{Status: server_structs.RegPending}}})
		require.NoError(t, err)
		defer resetNamespaceDB(t)

		diffPubKeyStr, err := GenerateMockJWKS()
		require.NoError(t, err)

		mockNs := server_structs.Namespace{Prefix: "/foo/bar", Pubkey: diffPubKeyStr, AdminMetadata: server_structs.AdminMetadata{Institution: "001"}}
		mockNsBytes, err := json.Marshal(mockNs)
		require.NoError(t, err)
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/namespaces", bytes.NewReader(mockNsBytes))
		req.Header.Set("Context-Type", "application/json")
		router.ServeHTTP(w, req)

		body, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		assert.Contains(t, string(body), "Cannot register a namespace that is suffixed or prefixed by an already-registered namespace unless the incoming public key matches a registered key")
		viper.Reset()
	})

	t.Run("inst-failure-returns-400", func(t *testing.T) {
		resetNamespaceDB(t)
		mockInsts := []Institution{{ID: "1000"}}
		viper.Set("Registry.Institutions", mockInsts)

		pubKeyStr, err := GenerateMockJWKS()
		require.NoError(t, err)

		mockNs := server_structs.Namespace{Prefix: "/foo", Pubkey: pubKeyStr, AdminMetadata: server_structs.AdminMetadata{Institution: "001"}}
		mockNsBytes, err := json.Marshal(mockNs)
		require.NoError(t, err)
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/namespaces", bytes.NewReader(mockNsBytes))
		req.Header.Set("Context-Type", "application/json")
		router.ServeHTTP(w, req)

		body, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		assert.Contains(t, string(body), `not in the list of available institutions to register`)
	})

	t.Run("valid-request-gives-200", func(t *testing.T) {
		resetNamespaceDB(t)
		mockInsts := []Institution{{ID: "1000"}}
		viper.Set("Registry.Institutions", mockInsts)

		pubKeyStr, err := GenerateMockJWKS()
		require.NoError(t, err)

		mockNs := server_structs.Namespace{Prefix: "/foo", Pubkey: pubKeyStr, AdminMetadata: server_structs.AdminMetadata{Institution: "1000"}}
		mockNsBytes, err := json.Marshal(mockNs)
		require.NoError(t, err)
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/namespaces", bytes.NewReader(mockNsBytes))
		req.Header.Set("Context-Type", "application/json")
		router.ServeHTTP(w, req)

		body, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.JSONEq(t, `{"msg":"Prefix /foo successfully registered", "status":"success"}`, string(body))

		nss, err := getAllNamespaces()
		require.NoError(t, err)
		require.Equal(t, 1, len(nss))
		assert.Equal(t, "/foo", nss[0].Prefix)
		assert.Equal(t, "admin", nss[0].AdminMetadata.UserID)
		assert.Equal(t, server_structs.RegPending, nss[0].AdminMetadata.Status)
		assert.NotEqual(t, time.Time{}, nss[0].AdminMetadata.CreatedAt)
	})

	t.Run("valid-request-w/-custom-fields-gives-200", func(t *testing.T) {
		resetNamespaceDB(t)
		mockInsts := []Institution{{ID: "1000"}}
		customFieldsConf := []map[string]interface{}{
			{"name": "boolean_field", "type": "bool", "required": true},
			{"name": "integer", "type": "int", "required": true},
			{"name": "string_field", "type": "string", "required": true},
			{"name": "datetime_field", "type": "datetime", "required": true},
		}
		viper.Set("Registry.Institutions", mockInsts)
		viper.Set("Registry.CustomRegistrationFields", customFieldsConf)
		err := InitCustomRegistrationFields()
		require.NoError(t, err)

		pubKeyStr, err := GenerateMockJWKS()
		require.NoError(t, err)

		customFieldsVals := map[string]interface{}{
			"boolean_field":  false,
			"integer":        1,
			"string_field":   "random",
			"datetime_field": 1696255200,
		}
		mockNs := Namespace{
			Prefix:        "/foo",
			Pubkey:        pubKeyStr,
			AdminMetadata: AdminMetadata{Institution: "1000"},
			CustomFields:  customFieldsVals,
		}
		mockNsBytes, err := json.Marshal(mockNs)
		require.NoError(t, err)
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/namespaces", bytes.NewReader(mockNsBytes))
		req.Header.Set("Context-Type", "application/json")
		router.ServeHTTP(w, req)

		body, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.JSONEq(t, `{"msg":"Prefix /foo successfully registered", "status":"success"}`, string(body))

		nss, err := getAllNamespaces()
		require.NoError(t, err)
		require.Equal(t, 1, len(nss))
		assert.Equal(t, "/foo", nss[0].Prefix)
		assert.Equal(t, "admin", nss[0].AdminMetadata.UserID)
		assert.Equal(t, Pending, nss[0].AdminMetadata.Status)
		assert.NotEqual(t, time.Time{}, nss[0].AdminMetadata.CreatedAt)
	})

	t.Run("osdf-topology-subspace-request-gives-200", func(t *testing.T) {
		resetNamespaceDB(t)

		_, err := config.SetPreferredPrefix(config.OsdfPrefix)
		require.NoError(t, err)
		topoNamespaces := []string{"/topo/foo", "/topo/bar"}
		svr := topologyMockup(t, topoNamespaces)
		defer svr.Close()
		viper.Set("Federation.TopologyNamespaceURL", svr.URL)
		err = PopulateTopology()
		require.NoError(t, err)

		mockInsts := []Institution{{ID: "1000"}}
		viper.Set("Registry.Institutions", mockInsts)

		pubKeyStr, err := GenerateMockJWKS()
		require.NoError(t, err)

		mockNs := server_structs.Namespace{Prefix: "/topo/foo/bar", Pubkey: pubKeyStr, AdminMetadata: server_structs.AdminMetadata{Institution: "1000"}}
		mockNsBytes, err := json.Marshal(mockNs)
		require.NoError(t, err)
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/namespaces", bytes.NewReader(mockNsBytes))
		req.Header.Set("Context-Type", "application/json")
		router.ServeHTTP(w, req)

		body, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.JSONEq(t, `{"msg":"Prefix /topo/foo/bar successfully registered. Note that there is an existing superspace or subspace of the namespace in the OSDF topology: /topo/foo. The registry admin will review your request and approve your namespace if this is expected.", "status":"success"}`, string(body))

		nss, err := getAllNamespaces()
		require.NoError(t, err)
		require.Equal(t, 1, len(nss))
		assert.Equal(t, "/topo/foo/bar", nss[0].Prefix)
		assert.Equal(t, "admin", nss[0].AdminMetadata.UserID)
		assert.Equal(t, server_structs.RegPending, nss[0].AdminMetadata.Status)
		assert.NotEqual(t, time.Time{}, nss[0].AdminMetadata.CreatedAt)
		viper.Reset()
	})

	t.Run("osdf-topology-same-prefix-request-gives-200", func(t *testing.T) {
		resetNamespaceDB(t)

		_, err := config.SetPreferredPrefix(config.OsdfPrefix)
		require.NoError(t, err)
		topoNamespaces := []string{"/topo/foo", "/topo/bar"}
		svr := topologyMockup(t, topoNamespaces)
		defer svr.Close()
		viper.Set("Federation.TopologyNamespaceURL", svr.URL)
		err = PopulateTopology()
		require.NoError(t, err)

		mockInsts := []Institution{{ID: "1000"}}
		viper.Set("Registry.Institutions", mockInsts)

		pubKeyStr, err := GenerateMockJWKS()
		require.NoError(t, err)

		mockNs := server_structs.Namespace{Prefix: "/topo/foo", Pubkey: pubKeyStr, AdminMetadata: server_structs.AdminMetadata{Institution: "1000"}}
		mockNsBytes, err := json.Marshal(mockNs)
		require.NoError(t, err)
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/namespaces", bytes.NewReader(mockNsBytes))
		req.Header.Set("Context-Type", "application/json")
		router.ServeHTTP(w, req)

		body, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.JSONEq(t, `{"msg":"Prefix /topo/foo successfully registered. Note that there is an existing superspace or subspace of the namespace in the OSDF topology: /topo/foo. The registry admin will review your request and approve your namespace if this is expected.", "status":"success"}`, string(body))

		nss, err := getAllNamespaces()
		require.NoError(t, err)
		require.Equal(t, 1, len(nss))
		assert.Equal(t, "/topo/foo", nss[0].Prefix)
		assert.Equal(t, "admin", nss[0].AdminMetadata.UserID)
		assert.Equal(t, server_structs.RegPending, nss[0].AdminMetadata.Status)
		assert.NotEqual(t, time.Time{}, nss[0].AdminMetadata.CreatedAt)
		viper.Reset()
	})
}

func TestUpdateNamespaceHandler(t *testing.T) {
	viper.Reset()
	_, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	// Initialize the mock database
	setupMockRegistryDB(t)
	defer teardownMockNamespaceDB(t)

	router := gin.Default()
	router.PUT("/namespaces/:id", func(ctx *gin.Context) {
		ctx.Set("User", "mockUser")
		createUpdateNamespace(ctx, true)
	})

	t.Run("no-id-returns-404", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/namespaces/", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
	})

	t.Run("str-id-returns-400", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/namespaces/crazy-id", nil)
		router.ServeHTTP(w, req)

		body, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		assert.JSONEq(t, `{"msg":"Invalid ID format. ID must a positive integer", "status":"error"}`, string(body))
	})

	t.Run("ng-id-returns-400", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/namespaces/-100", nil)
		router.ServeHTTP(w, req)

		body, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		assert.JSONEq(t, `{"msg":"Invalid ID format. ID must a positive integer", "status":"error"}`, string(body))
	})

	t.Run("zero-id-returns-400", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/namespaces/0", nil)
		router.ServeHTTP(w, req)

		body, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		assert.JSONEq(t, `{"msg":"Invalid ID format. ID must a positive integer", "status":"error"}`, string(body))
	})

	t.Run("valid-request-but-ns-dne-returns-404", func(t *testing.T) {
		resetNamespaceDB(t)
		mockInsts := []Institution{{ID: "1000"}}
		viper.Set("Registry.Institutions", mockInsts)

		pubKeyStr, err := GenerateMockJWKS()
		require.NoError(t, err)

		mockNs := server_structs.Namespace{Prefix: "/foo", Pubkey: pubKeyStr, AdminMetadata: server_structs.AdminMetadata{Institution: "1000"}}
		mockNsBytes, err := json.Marshal(mockNs)
		require.NoError(t, err)
		// Create a request to the endpoint

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/namespaces/1", bytes.NewReader(mockNsBytes))
		router.ServeHTTP(w, req)

		body, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
		assert.JSONEq(t, `{"msg":"Can't update namespace: namespace not found", "status":"error"}`, string(body))
	})

	t.Run("valid-request-not-owner-gives-404", func(t *testing.T) {
		resetNamespaceDB(t)
		mockInsts := []Institution{{ID: "1000"}}
		viper.Set("Registry.Institutions", mockInsts)

		pubKeyStr, err := GenerateMockJWKS()
		require.NoError(t, err)

		mockNs := server_structs.Namespace{Prefix: "/foo", Pubkey: pubKeyStr, AdminMetadata: server_structs.AdminMetadata{Institution: "1000", UserID: "notYourNs"}}

		err = insertMockDBData([]server_structs.Namespace{mockNs})
		require.NoError(t, err)

		id, err := getLastNamespaceId()
		require.NoError(t, err)

		mockNsBytes, err := json.Marshal(mockNs)
		require.NoError(t, err)
		// Create a request to the endpoint

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/namespaces/"+strconv.Itoa(id), bytes.NewReader(mockNsBytes))
		router.ServeHTTP(w, req)

		body, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
		assert.JSONEq(t, `{"msg":"Namespace not found. Check the id or if you own the namespace", "status":"error"}`, string(body))
	})

	t.Run("reg-user-cant-change-after-approv", func(t *testing.T) {
		resetNamespaceDB(t)
		mockInsts := []Institution{{ID: "1000"}}
		viper.Set("Registry.Institutions", mockInsts)

		pubKeyStr, err := GenerateMockJWKS()
		require.NoError(t, err)

		mockNs := server_structs.Namespace{
			Prefix: "/foo",
			Pubkey: pubKeyStr,
			AdminMetadata: server_structs.AdminMetadata{
				Institution: "1000",
				UserID:      "mockUser",                 // same as currently sign-in user
				Status:      server_structs.RegApproved, // but it's approved
			},
		}

		err = insertMockDBData([]server_structs.Namespace{mockNs})
		require.NoError(t, err)

		id, err := getLastNamespaceId()
		require.NoError(t, err)

		mockNsBytes, err := json.Marshal(mockNs)
		require.NoError(t, err)
		// Create a request to the endpoint

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/namespaces/"+strconv.Itoa(id), bytes.NewReader(mockNsBytes))
		router.ServeHTTP(w, req)

		body, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.JSONEq(t, `{"msg":"You don't have permission to modify an approved registration. Please contact your federation administrator", "status":"error"}`, string(body))
	})

	t.Run("reg-user-success-change", func(t *testing.T) {
		resetNamespaceDB(t)
		mockInsts := []Institution{{ID: "1000"}}
		viper.Set("Registry.Institutions", mockInsts)

		pubKeyStr, err := GenerateMockJWKS()
		require.NoError(t, err)

		mockNs := server_structs.Namespace{
			Prefix: "/foo",
			Pubkey: pubKeyStr,
			AdminMetadata: server_structs.AdminMetadata{
				Description: "oldDescription",
				Institution: "1000",
				UserID:      "mockUser",                // same as currently sign-in user
				Status:      server_structs.RegPending, // but it's approved
			},
		}

		err = insertMockDBData([]server_structs.Namespace{mockNs})
		require.NoError(t, err)

		id, err := getLastNamespaceId()
		require.NoError(t, err)

		updatedNs := mockNs
		updatedNs.AdminMetadata.Description = "newDescription"

		mockNsBytes, err := json.Marshal(updatedNs)
		require.NoError(t, err)
		// Create a request to the endpoint

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/namespaces/"+strconv.Itoa(id), bytes.NewReader(mockNsBytes))
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)

		nss, err := getAllNamespaces()
		require.NoError(t, err)
		require.Equal(t, 1, len(nss))
		assert.Equal(t, "/foo", nss[0].Prefix)
		assert.Equal(t, "newDescription", nss[0].AdminMetadata.Description)
	})

	t.Run("admin-can-change-anybody", func(t *testing.T) {
		resetNamespaceDB(t)
		mockInsts := []Institution{{ID: "1000"}}
		viper.Set("Registry.Institutions", mockInsts)

		pubKeyStr, err := GenerateMockJWKS()
		require.NoError(t, err)

		mockNs := server_structs.Namespace{
			Prefix: "/foo",
			Pubkey: pubKeyStr,
			AdminMetadata: server_structs.AdminMetadata{
				Description: "oldDescription",
				Institution: "1000",
				UserID:      "mockUser",                 // same as currently sign-in user
				Status:      server_structs.RegApproved, // but it's approved
			},
		}

		err = insertMockDBData([]server_structs.Namespace{mockNs})
		require.NoError(t, err)

		id, err := getLastNamespaceId()
		require.NoError(t, err)

		updatedNs := mockNs
		updatedNs.AdminMetadata.Description = "newDescription"

		mockNsBytes, err := json.Marshal(updatedNs)
		require.NoError(t, err)

		router := gin.Default()
		router.PUT("/namespaces/:id", func(ctx *gin.Context) {
			ctx.Set("User", "admin")
			createUpdateNamespace(ctx, true)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/namespaces/"+strconv.Itoa(id), bytes.NewReader(mockNsBytes))
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)

		nss, err := getAllNamespaces()
		require.NoError(t, err)
		require.Equal(t, 1, len(nss))
		assert.Equal(t, "/foo", nss[0].Prefix)
		assert.Equal(t, "newDescription", nss[0].AdminMetadata.Description)
	})
}

func TestListInsitutions(t *testing.T) {
	viper.Reset()
	router := gin.Default()
	router.GET("/institutions", listInstitutions)

	t.Run("nil-cache-with-nil-config-returns-error", func(t *testing.T) {
		institutionsCache = nil

		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/institutions", nil)
		router.ServeHTTP(w, req)

		bytes, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)

		assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)
		assert.JSONEq(t, `{"msg":"Server didn't configure Registry.Institutions", "status":"error"}`, string(bytes))
	})

	t.Run("cache-hit-returns", func(t *testing.T) {
		viper.Reset()
		mockUrl := url.URL{Scheme: "https", Host: "example.com"}
		viper.Set("Registry.InstitutionsUrl", mockUrl.String())
		mockInsts := []Institution{{Name: "Foo", ID: "001"}}
		institutionsCache = ttlcache.New[string, []Institution]()
		// Expired but never evicted, so Has() still returns true
		institutionsCache.Set(mockUrl.String(), mockInsts, time.Second)

		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/institutions", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		bytes, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)

		getInsts := []Institution{}
		err = json.Unmarshal(bytes, &getInsts)
		require.NoError(t, err)

		assert.Equal(t, mockInsts, getInsts)
	})

	t.Run("nil-cache-with-nonnil-config-returns", func(t *testing.T) {
		viper.Reset()
		institutionsCache = nil

		mockInstsConfig := []Institution{{Name: "foo", ID: "bar"}}
		viper.Set("Registry.Institutions", mockInstsConfig)

		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/institutions", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)

		bytes, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)

		getInsts := []Institution{}
		err = json.Unmarshal(bytes, &getInsts)
		require.NoError(t, err)

		assert.Equal(t, mockInstsConfig, getInsts)
	})

	t.Run("non-nil-cache-with-nonnil-config-return-config", func(t *testing.T) {
		viper.Reset()
		mockUrl := url.URL{Scheme: "https", Host: "example.com"}
		viper.Set("Registry.InstitutionsUrl", mockUrl.String())
		mockInsts := []Institution{{Name: "Foo", ID: "001"}}
		institutionsCache = ttlcache.New[string, []Institution]()
		// Expired but never evicted, so Has() still returns true
		institutionsCache.Set(mockUrl.String(), mockInsts, time.Second)

		mockInstsConfig := []Institution{{Name: "foo", ID: "bar"}}
		viper.Set("Registry.Institutions", mockInstsConfig)

		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/institutions", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)

		bytes, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)

		getInsts := []Institution{}
		err = json.Unmarshal(bytes, &getInsts)
		require.NoError(t, err)

		assert.Equal(t, mockInstsConfig, getInsts)
	})
}

func TestPopulateRegistrationFields(t *testing.T) {
	result := populateRegistrationFields("", server_structs.Namespace{})
	assert.NotEqual(t, 0, len(result))
}
