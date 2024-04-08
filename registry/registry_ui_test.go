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
	"net"
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
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
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
		expectedData []Namespace
	}{
		{
			description:  "valid-request-with-empty-db",
			serverType:   string(OriginType),
			expectedCode: http.StatusOK,
			emptyDB:      true,
			expectedData: []Namespace{},
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
			expectedData: []Namespace{},
			notApproved:  true,
		},
		{
			description:  "unauthed-with-status-pending-returns-403",
			expectedCode: http.StatusForbidden,
			status:       "Pending",
			expectedData: []Namespace{},
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
			expectedData: []Namespace{},
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
				var got []Namespace
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

	mockUserNss := func() []Namespace {
		return []Namespace{
			mockNamespace("/foo", "", "", AdminMetadata{UserID: "mockUser", Status: Pending}),
			mockNamespace("/bar", "", "", AdminMetadata{UserID: "mockUser", Status: Approved}),
		}
	}()

	tests := []struct {
		description  string
		expectedCode int
		emptyDB      bool
		authUser     bool
		queryParam   string
		expectedData []Namespace
	}{
		{
			description:  "unauthed-return-401",
			expectedCode: http.StatusUnauthorized,
			expectedData: []Namespace{},
		},
		{
			description:  "valid-request-with-empty-db",
			expectedCode: http.StatusOK,
			emptyDB:      true,
			expectedData: []Namespace{},
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
				var got []Namespace
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

	mockUserNs := mockNamespace("/mockUser", "", "", AdminMetadata{UserID: "mockUser"})

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
				err := insertMockDBData([]Namespace{mockUserNs})
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
				getNs := Namespace{}

				bytes, err := io.ReadAll(w.Body)
				require.NoError(t, err)
				err = json.Unmarshal(bytes, &getNs)
				require.NoError(t, err)

				require.NotEqual(t, Namespace{}, getNs)
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
				err := insertMockDBData([]Namespace{
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

	mockUserNs := mockNamespace("/mockUser", "", "", AdminMetadata{UserID: "mockUser"})

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
			err := insertMockDBData([]Namespace{mockUserNs})
			require.NoErrorf(t, err, "Failed to set up mock data: %v", err)
			defer resetNamespaceDB(t)

			router := gin.Default()
			router.PATCH("/test/:id/approve", func(ctx *gin.Context) {
				ctx.Set("User", "admin")
				updateNamespaceStatus(ctx, Approved)
			})
			router.PATCH("/test/:id/deny", func(ctx *gin.Context) {
				ctx.Set("User", "admin")
				updateNamespaceStatus(ctx, Denied)
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
					assert.True(t, ns.AdminMetadata.Status == Approved)
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

		mockEmptyNs := Namespace{}
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

		mockEmptyNs := Namespace{Prefix: "/", Pubkey: "badKey", AdminMetadata: AdminMetadata{Institution: "001"}}
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
		err := insertMockDBData([]Namespace{{Prefix: "/foo", Pubkey: "badKey", AdminMetadata: AdminMetadata{Status: Pending}}})
		require.NoError(t, err)
		defer resetNamespaceDB(t)

		mockNs := Namespace{Prefix: "/foo", Pubkey: "badKey", AdminMetadata: AdminMetadata{Institution: "001"}}
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

		mockNs := Namespace{Prefix: "/foo", Pubkey: "badKey", AdminMetadata: AdminMetadata{Institution: "001"}}
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

		err = insertMockDBData([]Namespace{{Prefix: "/foo", Pubkey: pubKeyStr, AdminMetadata: AdminMetadata{Status: Pending}}})
		require.NoError(t, err)
		defer resetNamespaceDB(t)

		diffPubKeyStr, err := GenerateMockJWKS()
		require.NoError(t, err)

		mockNs := Namespace{Prefix: "/foo", Pubkey: diffPubKeyStr, AdminMetadata: AdminMetadata{Institution: "001"}}
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

		err = insertMockDBData([]Namespace{{Prefix: "/foo", Pubkey: pubKeyStr, AdminMetadata: AdminMetadata{Status: Pending}}})
		require.NoError(t, err)
		defer resetNamespaceDB(t)

		diffPubKeyStr, err := GenerateMockJWKS()
		require.NoError(t, err)

		mockNs := Namespace{Prefix: "/foo/bar", Pubkey: diffPubKeyStr, AdminMetadata: AdminMetadata{Institution: "001"}}
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

		mockNs := Namespace{Prefix: "/foo", Pubkey: pubKeyStr, AdminMetadata: AdminMetadata{Institution: "001"}}
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

		mockNs := Namespace{Prefix: "/foo", Pubkey: pubKeyStr, AdminMetadata: AdminMetadata{Institution: "1000"}}
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

		_, err := config.SetPreferredPrefix("OSDF")
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

		mockNs := Namespace{Prefix: "/topo/foo/bar", Pubkey: pubKeyStr, AdminMetadata: AdminMetadata{Institution: "1000"}}
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
		assert.Equal(t, Pending, nss[0].AdminMetadata.Status)
		assert.NotEqual(t, time.Time{}, nss[0].AdminMetadata.CreatedAt)
		viper.Reset()
	})

	t.Run("osdf-topology-same-prefix-request-gives-200", func(t *testing.T) {
		resetNamespaceDB(t)

		_, err := config.SetPreferredPrefix("OSDF")
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

		mockNs := Namespace{Prefix: "/topo/foo", Pubkey: pubKeyStr, AdminMetadata: AdminMetadata{Institution: "1000"}}
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
		assert.Equal(t, Pending, nss[0].AdminMetadata.Status)
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

		mockNs := Namespace{Prefix: "/foo", Pubkey: pubKeyStr, AdminMetadata: AdminMetadata{Institution: "1000"}}
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

		mockNs := Namespace{Prefix: "/foo", Pubkey: pubKeyStr, AdminMetadata: AdminMetadata{Institution: "1000", UserID: "notYourNs"}}

		err = insertMockDBData([]Namespace{mockNs})
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

		mockNs := Namespace{
			Prefix: "/foo",
			Pubkey: pubKeyStr,
			AdminMetadata: AdminMetadata{
				Institution: "1000",
				UserID:      "mockUser", // same as currently sign-in user
				Status:      Approved,   // but it's approved
			},
		}

		err = insertMockDBData([]Namespace{mockNs})
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

		mockNs := Namespace{
			Prefix: "/foo",
			Pubkey: pubKeyStr,
			AdminMetadata: AdminMetadata{
				Description: "oldDescription",
				Institution: "1000",
				UserID:      "mockUser", // same as currently sign-in user
				Status:      Pending,    // but it's approved
			},
		}

		err = insertMockDBData([]Namespace{mockNs})
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

		mockNs := Namespace{
			Prefix: "/foo",
			Pubkey: pubKeyStr,
			AdminMetadata: AdminMetadata{
				Description: "oldDescription",
				Institution: "1000",
				UserID:      "mockUser", // same as currently sign-in user
				Status:      Approved,   // but it's approved
			},
		}

		err = insertMockDBData([]Namespace{mockNs})
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
		func() {
			institutionsCacheMutex.Lock()
			defer institutionsCacheMutex.Unlock()
			institutionsCache = nil
		}()

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
		func() {
			institutionsCacheMutex.Lock()
			defer institutionsCacheMutex.Unlock()
			institutionsCache = ttlcache.New[string, []Institution]()
			// Expired but never evicted, so Has() still returns true
			institutionsCache.Set(mockUrl.String(), mockInsts, time.Second)
		}()

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
		func() {
			institutionsCacheMutex.Lock()
			defer institutionsCacheMutex.Unlock()
			institutionsCache = nil
		}()

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
		func() {
			institutionsCacheMutex.Lock()
			defer institutionsCacheMutex.Unlock()
			institutionsCache = ttlcache.New[string, []Institution]()
			// Expired but never evicted, so Has() still returns true
			institutionsCache.Set(mockUrl.String(), mockInsts, time.Second)
		}()

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
	result := populateRegistrationFields("", Namespace{})
	assert.NotEqual(t, 0, len(result))
}

func TestGetCachedInstitutions(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/institution_ids" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(`[{"id": "https://osg-htc.org/iid/05ejpqr48", "name": "Worcester Polytechnic Institute", "ror_id": "https://ror.org/05ejpqr48"}, {"id": "https://osg-htc.org/iid/017t4sb47", "name": "Wright Institute", "ror_id": "https://ror.org/017t4sb47"}, {"id": "https://osg-htc.org/iid/03v76x132", "name": "Yale University", "ror_id": "https://ror.org/03v76x132"}]`))
			require.NoError(t, err)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	// Hijack the common transport used by Pelican, forcing all connections to go to our test server
	transport := config.GetTransport()
	oldDial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := net.Dialer{}
		return dialer.DialContext(ctx, svr.Listener.Addr().Network(), svr.Listener.Addr().String())
	}
	oldConfig := transport.TLSClientConfig
	transport.TLSClientConfig = svr.TLS.Clone()
	transport.TLSClientConfig.InsecureSkipVerify = true
	t.Cleanup(func() {
		transport.DialContext = oldDial
		transport.TLSClientConfig = oldConfig
	})

	t.Run("nil-cache-returns-error", func(t *testing.T) {
		func() {
			institutionsCacheMutex.Lock()
			defer institutionsCacheMutex.Unlock()
			institutionsCache = nil
		}()
		_, intErr, extErr := getCachedInstitutions()
		assert.Error(t, intErr)
		assert.Error(t, extErr)
		assert.Equal(t, "institutionsCache isn't initialized", intErr.Error())
	})

	t.Run("unset-config-val-returns-error", func(t *testing.T) {
		viper.Reset()
		func() {
			institutionsCacheMutex.Lock()
			defer institutionsCacheMutex.Unlock()
			institutionsCache = ttlcache.New[string, []Institution]()
		}()
		_, intErr, extErr := getCachedInstitutions()
		assert.Error(t, intErr)
		assert.Error(t, extErr)
		assert.Contains(t, intErr.Error(), "Registry.InstitutionsUrl is unset")
	})

	t.Run("random-config-val-returns-error", func(t *testing.T) {
		viper.Reset()
		viper.Set("Registry.InstitutionsUrl", "random-url")
		func() {
			institutionsCacheMutex.Lock()
			defer institutionsCacheMutex.Unlock()
			institutionsCache = ttlcache.New[string, []Institution]()
		}()
		_, intErr, extErr := getCachedInstitutions()
		assert.Error(t, intErr)
		assert.Error(t, extErr)
		// See url.URL for why it won't return error
		assert.Contains(t, intErr.Error(), "Error response when fetching institution list")
	})

	t.Run("cache-hit-with-invalid-ns-returns-error", func(t *testing.T) {
		viper.Reset()
		mockUrl := url.URL{Scheme: "https", Host: "example.com"}
		viper.Set("Registry.InstitutionsUrl", mockUrl.String())
		func() {
			institutionsCacheMutex.Lock()
			defer institutionsCacheMutex.Unlock()
			institutionsCache = ttlcache.New[string, []Institution]()
			institutionsCache.Set(mockUrl.String(), nil, ttlcache.NoTTL)
		}()

		_, intErr, extErr := getCachedInstitutions()
		require.Error(t, intErr)
		require.Error(t, extErr)
		assert.Contains(t, intErr.Error(), "value is nil from key")

		func() {
			institutionsCacheMutex.Lock()
			defer institutionsCacheMutex.Unlock()
			institutionsCache.DeleteAll()
		}()
	})

	t.Run("cache-hit-with-valid-ns", func(t *testing.T) {
		viper.Reset()
		mockUrl := url.URL{Scheme: "https", Host: "example.com"}
		viper.Set("Registry.InstitutionsUrl", mockUrl.String())
		mockInsts := []Institution{{Name: "Foo", ID: "001"}}

		func() {
			institutionsCacheMutex.Lock()
			defer institutionsCacheMutex.Unlock()
			institutionsCache = ttlcache.New[string, []Institution]()
			institutionsCache.Set(mockUrl.String(), mockInsts, ttlcache.NoTTL)
		}()

		getInsts, intErr, extErr := getCachedInstitutions()
		require.NoError(t, intErr)
		require.NoError(t, extErr)
		assert.Equal(t, mockInsts, getInsts)

		func() {
			institutionsCacheMutex.Lock()
			defer institutionsCacheMutex.Unlock()
			institutionsCache.DeleteAll()
		}()
	})

	t.Run("cache-hit-with-expired-item", func(t *testing.T) {
		viper.Reset()
		mockUrl := url.URL{Scheme: "https", Host: "example.com"}
		viper.Set("Registry.InstitutionsUrl", mockUrl.String())
		mockInsts := []Institution{{Name: "Foo", ID: "001"}}

		func() {
			institutionsCacheMutex.Lock()
			defer institutionsCacheMutex.Unlock()
			institutionsCache = ttlcache.New[string, []Institution]()
			// Expired but never evicted, so Has() still returns true
			institutionsCache.Set(mockUrl.String(), mockInsts, time.Second)
		}()

		time.Sleep(2 * time.Second)
		getInsts, intErr, extErr := getCachedInstitutions()
		require.Error(t, intErr)
		require.Error(t, extErr)
		assert.Equal(t, "Fail to get institutions from internal cache, key might be expired", extErr.Error())
		assert.Equal(t, 0, len(getInsts))

		func() {
			institutionsCacheMutex.Lock()
			defer institutionsCacheMutex.Unlock()
			institutionsCache.DeleteAll()
		}()
	})

	t.Run("cache-miss-with-success-fetch", func(t *testing.T) {
		viper.Reset()
		logrus.SetLevel(logrus.InfoLevel)
		hook := test.NewGlobal()
		defer hook.Reset()

		// This is dangerous as we rely on external API to decide if the test succeeds,
		// but this is the one way to test with our custom http client
		viper.Set("Registry.InstitutionsUrl", "https://topology.opensciencegrid.org/institution_ids")
		institutionsCache = ttlcache.New[string, []Institution]()

		getInsts, intErr, extErr := getCachedInstitutions()
		require.NoError(t, intErr)
		require.NoError(t, extErr)
		assert.Greater(t, len(getInsts), 0)
		assert.Equal(t, 1, len(hook.Entries))
		assert.Contains(t, hook.LastEntry().Message, "Cache miss for institutions TTL cache")

		func() {
			institutionsCacheMutex.Lock()
			defer institutionsCacheMutex.Unlock()
			institutionsCache.DeleteAll()
		}()
	})

	t.Run("cache-miss-with-404-fetch", func(t *testing.T) {
		viper.Reset()

		viper.Set("Registry.InstitutionsUrl", "https://example.com/foo.bar")
		institutionsCache = ttlcache.New[string, []Institution]()

		getInsts, intErr, extErr := getCachedInstitutions()
		require.Error(t, intErr)
		require.Error(t, extErr)
		assert.Equal(t, "Error response when fetching institution list with code 404", intErr.Error())
		assert.Equal(t, len(getInsts), 0)

		func() {
			institutionsCacheMutex.Lock()
			defer institutionsCacheMutex.Unlock()
			institutionsCache.DeleteAll()
		}()
	})

	t.Run("cache-hit-with-two-success-fetch", func(t *testing.T) {
		viper.Reset()
		logrus.SetLevel(logrus.InfoLevel)
		hook := test.NewGlobal()
		defer hook.Reset()

		// This is dangerous as we rely on external API to decide if the test succeeds,
		// but this is the one way to test with our custom http client
		viper.Set("Registry.InstitutionsUrl", "https://topology.opensciencegrid.org/institution_ids")
		institutionsCache = ttlcache.New[string, []Institution]()

		getInsts, intErr, extErr := getCachedInstitutions()
		require.NoError(t, intErr)
		require.NoError(t, extErr)
		assert.Greater(t, len(getInsts), 0)
		assert.Equal(t, 1, len(hook.Entries))
		assert.Contains(t, hook.LastEntry().Message, "Cache miss for institutions TTL cache")

		hook.Reset()

		getInsts2, intErr, extErr := getCachedInstitutions()
		require.NoError(t, intErr)
		require.NoError(t, extErr)
		assert.Greater(t, len(getInsts2), 0)
		assert.Equal(t, getInsts, getInsts2)
		// No cache miss
		assert.Equal(t, 0, len(hook.Entries))

		func() {
			institutionsCacheMutex.Lock()
			defer institutionsCacheMutex.Unlock()
			institutionsCache.DeleteAll()
		}()
	})
}

func TestCheckUniqueInstitutions(t *testing.T) {
	t.Run("empty-gives-true", func(t *testing.T) {
		unique := checkUniqueInstitutions([]Institution{})
		assert.True(t, unique)
	})

	t.Run("unique-gives-true", func(t *testing.T) {
		unique := checkUniqueInstitutions([]Institution{{ID: "1"}, {ID: "2"}})
		assert.True(t, unique)
	})

	t.Run("duplicated-gives-false", func(t *testing.T) {
		unique := checkUniqueInstitutions([]Institution{{ID: "1"}, {ID: "1"}})
		assert.False(t, unique)
	})

	t.Run("large-entries", func(t *testing.T) {
		unique := checkUniqueInstitutions([]Institution{
			{ID: "1"}, {ID: "2"}, {ID: "3"}, {ID: "4"}, {ID: "1"},
		})
		assert.False(t, unique)
	})
}

func TestInitInstConfig(t *testing.T) {
	institutionsCache = ttlcache.New[string, []Institution]()
	t.Run("wrong-inst-config-returns-error", func(t *testing.T) {
		ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
		defer func() { require.NoError(t, egrp.Wait()) }()
		defer cancel()
		viper.Reset()
		mockWrongInst := []mockBadInstitutionFormat{{RORID: "mockID", Inst: "mockInst"}}
		// YAML is also incorrect format, viper is expecting mapstructure
		mockWrongInstByte, err := yaml.Marshal(mockWrongInst)
		require.NoError(t, err)
		viper.Set("Registry.Institutions", mockWrongInstByte)
		err = InitInstConfig(ctx, egrp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Fail to read Registry.Institutions.")
	})

	t.Run("valid-inst-config-with-dup-ids-returns-err", func(t *testing.T) {
		ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
		defer func() { require.NoError(t, egrp.Wait()) }()
		defer cancel()
		viper.Reset()
		mockMap := make(map[string]string)
		mockMap["ID"] = "mockID"
		mockMap["Name"] = "mockName"
		viper.Set("Registry.Institutions", []map[string]string{mockMap, mockMap})
		err := InitInstConfig(ctx, egrp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Institution IDs read from config are not unique")
	})

	t.Run("valid-inst-config-with-unique-ids", func(t *testing.T) {
		ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
		defer func() { require.NoError(t, egrp.Wait()) }()
		defer cancel()
		viper.Reset()
		mockMap1 := make(map[string]string)
		mockMap1["ID"] = "mockID"
		mockMap1["Name"] = "mockName"
		mockMap2 := make(map[string]string)
		mockMap2["ID"] = "mockID2"
		mockMap2["Name"] = "mockName"
		viper.Set("Registry.Institutions", []map[string]string{mockMap1, mockMap2})
		err := InitInstConfig(ctx, egrp)
		require.NoError(t, err)
	})

	t.Run("config-val-url-both-set-gives-config", func(t *testing.T) {
		institutionsCache = nil
		defer func() {
			institutionsCache = ttlcache.New[string, []Institution]()
		}()

		ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
		defer func() { require.NoError(t, egrp.Wait()) }()
		defer cancel()

		viper.Reset()
		logrus.SetLevel(logrus.InfoLevel)
		hook := test.NewGlobal()
		defer hook.Reset()

		mockMap1 := make(map[string]string)
		mockMap1["ID"] = "mockID"
		mockMap1["Name"] = "mockName"
		mockMap2 := make(map[string]string)
		mockMap2["ID"] = "mockID2"
		mockMap2["Name"] = "mockName"
		viper.Set("Registry.Institutions", []map[string]string{mockMap1, mockMap2})
		viper.Set("Registry.InstitutionsUrl", "https://example.com")
		err := InitInstConfig(ctx, egrp)
		require.NoError(t, err)
		// This means we didn't config ttl cache
		require.Nil(t, institutionsCache)
		require.Equal(t, 1, len(hook.Entries))
		assert.Equal(t, "Registry.Institutions and Registry.InstitutionsUrl are both set. Registry.InstitutionsUrl is ignored", hook.LastEntry().Message)
	})

	t.Run("valid-inst-config-with-dup-ids-and-url-returns-err", func(t *testing.T) {
		ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
		defer func() { require.NoError(t, egrp.Wait()) }()
		defer cancel()
		viper.Reset()
		mockMap := make(map[string]string)
		mockMap["ID"] = "mockID"
		mockMap["Name"] = "mockName"
		viper.Set("Registry.Institutions", []map[string]string{mockMap, mockMap})
		viper.Set("Registry.InstitutionsUrl", "https://example.com")
		err := InitInstConfig(ctx, egrp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Institution IDs read from config are not unique")
	})

	t.Run("only-url-set-with-invalid-data-is-non-blocking", func(t *testing.T) {
		institutionsCache = nil
		defer func() {
			institutionsCache = ttlcache.New[string, []Institution]()
		}()

		ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
		defer func() { require.NoError(t, egrp.Wait()) }()
		defer cancel()

		viper.Reset()
		logrus.SetLevel(logrus.WarnLevel)
		hook := test.NewGlobal()
		defer hook.Reset()

		// Invalid URL
		viper.Set("Registry.InstitutionsUrl", "https://example.com")
		err := InitInstConfig(ctx, egrp)
		// No error should return, this is non-blcoking
		require.NoError(t, err)
		require.Equal(t, 1, len(hook.Entries))
		assert.Contains(t, hook.LastEntry().Message, "Failed to populate institution cache.")
		assert.NotNil(t, institutionsCache)
	})

	t.Run("only-url-set-with-valid-data", func(t *testing.T) {
		institutionsCache = nil
		defer func() {
			institutionsCache = ttlcache.New[string, []Institution]()
		}()
		ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
		defer func() { require.NoError(t, egrp.Wait()) }()
		defer cancel()

		viper.Reset()
		logrus.SetLevel(logrus.InfoLevel)
		hook := test.NewGlobal()
		defer hook.Reset()

		// Valid URL, Although very dangerous to do so
		viper.Set("Registry.InstitutionsUrl", "https://topology.opensciencegrid.org/institution_ids")
		err := InitInstConfig(ctx, egrp)
		// No error should return, this is non-blcoking
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(hook.Entries), 1)
		assert.Contains(t, hook.LastEntry().Message, "Successfully populated institution TTL cache")
		assert.NotNil(t, institutionsCache)
		assert.GreaterOrEqual(t, institutionsCache.Len(), 1)
	})
}
