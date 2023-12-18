package registry

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		return "", errors.Wrap(err, "Unable to marshall the json into string")
	}
	// Append a new line to the JSON data
	jsonData = append(jsonData, '\n')

	return string(jsonData), nil
}

func TestListNamespaces(t *testing.T) {
	// Initialize the mock database
	err := setupMockNamespaceDB()
	if err != nil {
		t.Fatalf("Failed to set up mock namespace DB: %v", err)
	}
	defer teardownMockNamespaceDB()

	router := gin.Default()

	router.GET("/namespaces", listNamespaces)

	tests := []struct {
		description  string
		serverType   string
		expectedCode int
		emptyDB      bool
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
			serverType:   "",
			expectedCode: http.StatusOK,
			expectedData: mockNssWithMixed,
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
				err := insertMockDBData(mockNssWithMixed)
				if err != nil {
					t.Fatalf("Failed to set up mock data: %v", err)
				}
			}
			defer func() {
				err := resetNamespaceDB()
				if err != nil {
					t.Fatalf("Failed to reset mock namespace DB: %v", err)
				}
			}()

			// Create a request to the endpoint
			w := httptest.NewRecorder()
			requestURL := ""
			if tc.serverType != "" {
				requestURL = "/namespaces?server_type=" + tc.serverType
			} else {
				requestURL = "/namespaces"
			}
			req, _ := http.NewRequest("GET", requestURL, nil)
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

func TestGetNamespaceJWKS(t *testing.T) {
	mockPublicKey, err := GenerateMockJWKS()
	if err != nil {
		t.Fatalf("Failed to set up mock public key: %v", err)
	}
	// Initialize the mock database
	err = setupMockNamespaceDB()
	if err != nil {
		t.Fatalf("Failed to set up mock namespace DB: %v", err)
	}
	defer teardownMockNamespaceDB()

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
			defer func() {
				err := resetNamespaceDB()
				if err != nil {
					t.Fatalf("Failed to reset mock namespace DB: %v", err)
				}
			}()

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
