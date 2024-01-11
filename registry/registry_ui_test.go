package registry

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spf13/viper"
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
	_, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	// Initialize the mock database
	setupMockRegistryDB(t)
	defer teardownMockNamespaceDB(t)

	router := gin.Default()

	router.GET("/namespaces", listNamespaces)

	tests := []struct {
		description  string
		serverType   string
		expectedCode int
		emptyDB      bool
		notApproved  bool
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
			description:  "unauthed-not-approved-without-type-returns-empty",
			serverType:   "",
			expectedCode: http.StatusOK,
			expectedData: []Namespace{},
			notApproved:  true,
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

func TestPopulateRegistrationFields(t *testing.T) {
	result := populateRegistrationFields("", Namespace{})
	assert.NotEqual(t, 0, len(result))
}

func TestGetCachedInstitutions(t *testing.T) {
	t.Run("nil-cache-returns-error", func(t *testing.T) {
		institutionsCache = nil

		_, intErr, extErr := getCachedInstitutions()
		assert.Error(t, intErr)
		assert.Error(t, extErr)
		assert.Equal(t, "institutionsCache isn't initialized", intErr.Error())
	})

	t.Run("unset-config-val-returns-error", func(t *testing.T) {
		viper.Reset()
		institutionsCache = ttlcache.New[string, []Institution]()
		_, intErr, extErr := getCachedInstitutions()
		assert.Error(t, intErr)
		assert.Error(t, extErr)
		assert.Contains(t, intErr.Error(), "Registry.InstitutionsUrl is unset")
	})

	t.Run("random-config-val-returns-error", func(t *testing.T) {
		viper.Reset()
		viper.Set("Registry.InstitutionsUrl", "random-url")
		institutionsCache = ttlcache.New[string, []Institution]()
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
		institutionsCache = ttlcache.New[string, []Institution]()

		func() {
			institutionsCacheMutex.Lock()
			defer institutionsCacheMutex.Unlock()
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
		institutionsCache = ttlcache.New[string, []Institution]()
		mockInsts := []Institution{{Name: "Foo", ID: "001"}}

		func() {
			institutionsCacheMutex.Lock()
			defer institutionsCacheMutex.Unlock()
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
