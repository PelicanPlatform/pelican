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

package broker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token_scopes"
)

func TestGetCacheHostnameFromToken(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	test_utils.InitClient(t, nil)

	test_utils.MockFederationRoot(t, &pelican_url.FederationDiscovery{
		RegistryEndpoint: "https://your-registry.com",
	}, nil)

	tok, err := jwt.NewBuilder().
		Issuer(`https://your-registry.com/api/v1.0/registry/caches/https://cache.com`).
		IssuedAt(time.Now()).
		Build()
	require.NoError(t, err)
	tokByte, err := jwt.Sign(tok, jwt.WithInsecureNoSignature())
	require.NoError(t, err)

	hostname, err := getCacheHostnameFromToken(tokByte)
	require.NoError(t, err)
	assert.Equal(t, "https://cache.com", hostname)
}

// TestGetRegistryIssValue_RejectsTraversal verifies that a namespace prefix
// cannot walk out of the registry's API path.  The prefix arrives in the
// request body before the caller's token is verified and is joined into the
// registry URL, and joining cleans the result, so ".." segments would silently
// aim the key lookup at some other path on the registry.
func TestGetRegistryIssValue_RejectsTraversal(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	test_utils.InitClient(t, nil)
	test_utils.MockFederationRoot(t, &pelican_url.FederationDiscovery{
		RegistryEndpoint: "https://registry.example.com",
	}, nil)

	t.Run("Rejected", func(t *testing.T) {
		for _, prefix := range []string{
			"",
			"caches/example",
			"../../../../evil",
			"/caches/../../origins/secret",
			"/caches/x/../../../../../../etc/passwd",
			"/caches/./example",
		} {
			_, err := getRegistryIssValue(prefix)
			assert.Error(t, err, "prefix %q should be rejected", prefix)
		}
	})

	t.Run("Accepted", func(t *testing.T) {
		// A cache's prefix embeds the cache's URL, so a prefix is not required
		// to survive path cleaning unchanged.
		for _, prefix := range []string{
			"/caches/example",
			"/origins/example",
			"/caches/https://cache.example.com",
			"/foo/bar/baz",
		} {
			iss, err := getRegistryIssValue(prefix)
			require.NoError(t, err, "prefix %q should be accepted", prefix)
			assert.Contains(t, iss, "https://registry.example.com/api/v1.0/registry")
		}
	})
}

// jwksTestServer is a stand-in registry that serves a namespace's JWKS.  Its
// key set can be rotated and the whole server can be taken "down" to simulate
// a registry outage, while counting the fetches it actually served.
type jwksTestServer struct {
	mu      sync.Mutex
	keys    jwk.Set
	down    bool
	status  int
	fetches int
	server  *httptest.Server
}

// setStatus makes the stand-in registry answer with the given status, as it
// does for a namespace that is not registered (404) or not approved (403).
func (s *jwksTestServer) setStatus(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = code
}

func newJwksTestServer(t *testing.T) *jwksTestServer {
	s := &jwksTestServer{keys: jwk.NewSet()}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.fetches++
		if s.down {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if s.status != 0 {
			w.WriteHeader(s.status)
			_, _ = w.Write([]byte(`{"status":"error","msg":"namespace prefix was not found"}`))
			return
		}
		data, err := json.Marshal(s.keys)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	t.Cleanup(s.server.Close)
	return s
}

// rotateTo generates a fresh signing key with the given key ID, publishes only
// that key, and returns the private half for signing tokens.
func (s *jwksTestServer) rotateTo(t *testing.T, kid string) jwk.Key {
	privEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	priv, err := jwk.FromRaw(privEC)
	require.NoError(t, err)
	require.NoError(t, priv.Set(jwk.KeyIDKey, kid))
	require.NoError(t, priv.Set(jwk.AlgorithmKey, jwa.ES256))

	pub, err := priv.PublicKey()
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, kid))
	require.NoError(t, pub.Set(jwk.AlgorithmKey, jwa.ES256))

	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pub))

	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = set
	return priv
}

func (s *jwksTestServer) setDown(down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = down
}

func (s *jwksTestServer) fetchCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetches
}

// setupBrokerKeyTest points the federation at the given stand-in registry and
// launches a fresh namespace key cache.
func setupBrokerKeyTest(t *testing.T, registryEndpoint string) context.Context {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	test_utils.InitClient(t, nil)

	test_utils.MockFederationRoot(t, &pelican_url.FederationDiscovery{
		RegistryEndpoint: registryEndpoint,
	}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	egrp, ctx := errgroup.WithContext(ctx)
	t.Cleanup(func() {
		cancel()
		_ = egrp.Wait()
	})

	setNamespaceKeys(nil)
	LaunchNamespaceKeyMaintenance(ctx, egrp)
	return ctx
}

// mintBrokerToken signs a broker token for the namespace with the given key.
func mintBrokerToken(t *testing.T, key jwk.Key, prefix, audience string, scope token_scopes.TokenScope) string {
	iss, err := getRegistryIssValue(prefix)
	require.NoError(t, err)

	tok, err := jwt.NewBuilder().
		Issuer(iss).
		Subject("test-subject").
		Audience([]string{audience}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Minute)).
		Claim("scope", scope.String()).
		Build()
	require.NoError(t, err)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, key))
	require.NoError(t, err)
	return string(signed)
}

// TestGetRegistryIssuerInfo_LoadFailures verifies that an unreachable registry
// surfaces as an error, and that calling in before the cache is initialized
// does the same rather than panicking.
func TestGetRegistryIssuerInfo_LoadFailures(t *testing.T) {
	// Point the federation at a registry endpoint that refuses connections.
	ctx := setupBrokerKeyTest(t, "https://127.0.0.1:1")

	_, _, err := getRegistryIssuerInfo(ctx, "/caches/example")
	require.Error(t, err)

	// Restore the launched cache via Cleanup so the shutdown goroutine still
	// sees it even if the check below fails.
	orig := getNamespaceKeys()
	t.Cleanup(func() { setNamespaceKeys(orig) })
	setNamespaceKeys(nil)
	_, _, err = getRegistryIssuerInfo(ctx, "/caches/other")
	require.Error(t, err)
}

// TestGetRegistryIssuerInfo_RecoversAfterRegistryOutage verifies that a
// namespace whose first fetch failed is retried on a later request rather than
// being stuck with no keys.
func TestGetRegistryIssuerInfo_RecoversAfterRegistryOutage(t *testing.T) {
	registry := newJwksTestServer(t)
	registry.rotateTo(t, "key-1")
	registry.setDown(true)

	// Stand in for the throttle window having elapsed between the two
	// requests below; TestRefreshNamespaceKeys_RateLimited covers the throttle
	// itself.
	withNamespaceKeyRetryInterval(t, 0)
	ctx := setupBrokerKeyTest(t, registry.server.URL)
	const prefix = "/caches/example"

	_, _, err := getRegistryIssuerInfo(ctx, prefix)
	require.Error(t, err, "a down registry should surface an error")

	// The registry comes back.  The cached fetcher is reused, so recovery
	// depends on the forced refresh rather than on the entry expiring.
	registry.setDown(false)

	_, keyset, err := getRegistryIssuerInfo(ctx, prefix)
	require.NoError(t, err, "keys should be retrieved once the registry recovers")
	require.NotNil(t, keyset)
	assert.Equal(t, 1, keyset.Len())
}

// TestGetRegistryIssuerInfo_ServesLastKnownGoodWhileRegistryDown verifies that
// once a namespace's keys have been retrieved, a registry outage does not
// disturb them: the cached keyset is served without touching the network.
func TestGetRegistryIssuerInfo_ServesLastKnownGoodWhileRegistryDown(t *testing.T) {
	registry := newJwksTestServer(t)
	registry.rotateTo(t, "key-1")

	ctx := setupBrokerKeyTest(t, registry.server.URL)
	const prefix = "/caches/example"

	_, keyset, err := getRegistryIssuerInfo(ctx, prefix)
	require.NoError(t, err)
	require.NotNil(t, keyset)
	fetchesAfterFirst := registry.fetchCount()
	require.Positive(t, fetchesAfterFirst)

	registry.setDown(true)

	for i := 0; i < 3; i++ {
		_, keyset, err = getRegistryIssuerInfo(ctx, prefix)
		require.NoError(t, err, "a registry outage must not break a namespace whose keys are already cached")
		require.NotNil(t, keyset)
		_, found := keyset.LookupKeyID("key-1")
		assert.True(t, found, "the last known good key should still be served")
	}
	assert.Equal(t, fetchesAfterFirst, registry.fetchCount(),
		"serving cached keys should not contact the registry")
}

// TestVerifyToken_PicksUpRotatedKey verifies that a token signed by a key
// registered after the keyset was cached is accepted without waiting for the
// background refresh interval.
func TestVerifyToken_PicksUpRotatedKey(t *testing.T) {
	registry := newJwksTestServer(t)
	firstKey := registry.rotateTo(t, "key-1")

	// Let the rotation path fire without waiting out the throttle.  This is read
	// when the cache is built, so it has to be set before the setup below.
	withNamespaceKeyRetryInterval(t, 0)

	ctx := setupBrokerKeyTest(t, registry.server.URL)
	const prefix = "/caches/example"
	const audience = "https://broker.example.com"

	tok := mintBrokerToken(t, firstKey, prefix, audience, token_scopes.Broker_Reverse)
	ok, err := verifyToken(ctx, tok, prefix, audience, token_scopes.Broker_Reverse)
	require.NoError(t, err)
	assert.True(t, ok, "a token signed by the registered key should verify")

	// The namespace rotates to a new key; the cached keyset still holds only
	// the old one.
	secondKey := registry.rotateTo(t, "key-2")
	rotatedTok := mintBrokerToken(t, secondKey, prefix, audience, token_scopes.Broker_Reverse)

	ok, err = verifyToken(ctx, rotatedTok, prefix, audience, token_scopes.Broker_Reverse)
	require.NoError(t, err, "an unknown key ID should trigger a refresh rather than a hard failure")
	assert.True(t, ok, "a token signed by a newly registered key should verify")

	// The retired key must no longer verify, since the refreshed set replaced it.
	staleTok := mintBrokerToken(t, firstKey, prefix, audience, token_scopes.Broker_Reverse)
	ok, _ = verifyToken(ctx, staleTok, prefix, audience, token_scopes.Broker_Reverse)
	assert.False(t, ok, "a token signed by the retired key should be rejected")
}

// TestRefreshNamespaceKeys_RateLimited verifies that out-of-band refreshes are
// throttled, so a stream of tokens naming unknown key IDs cannot become a
// stream of registry fetches.
func TestRefreshNamespaceKeys_RateLimited(t *testing.T) {
	registry := newJwksTestServer(t)
	registry.rotateTo(t, "key-1")

	withNamespaceKeyRetryInterval(t, time.Hour)
	ctx := setupBrokerKeyTest(t, registry.server.URL)
	const prefix = "/caches/example"

	_, _, err := getRegistryIssuerInfo(ctx, prefix)
	require.NoError(t, err)
	fetchesAfterFirst := registry.fetchCount()

	// The initial fetch just happened, so a refresh is suppressed.
	for i := 0; i < 3; i++ {
		set, err := refreshNamespaceKeys(ctx, prefix)
		require.NoError(t, err)
		assert.Nil(t, set, "a refresh inside the throttle window should be suppressed")
	}
	assert.Equal(t, fetchesAfterFirst, registry.fetchCount(), "the registry should not be contacted")
}

// TestVerifyToken_StopsAfterNamespaceDeregistered verifies that a namespace the
// registry no longer vouches for stops verifying promptly, rather than being
// carried by its cached keys until the staleness ceiling.  The registry answers
// 404 for a prefix that is not registered and 403 for one whose approval has
// been withdrawn; both are how an administrator removes a service.
func TestVerifyToken_StopsAfterNamespaceDeregistered(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			registry := newJwksTestServer(t)
			key := registry.rotateTo(t, "key-1")

			withNamespaceKeyRetryInterval(t, 0)
			ctx := setupBrokerKeyTest(t, registry.server.URL)
			const prefix = "/caches/example"
			const audience = "https://broker.example.com"

			tok := mintBrokerToken(t, key, prefix, audience, token_scopes.Broker_Reverse)
			ok, err := verifyToken(ctx, tok, prefix, audience, token_scopes.Broker_Reverse)
			require.NoError(t, err)
			require.True(t, ok)

			// The namespace is removed from the registry.  Cached keys stay
			// usable until they next come up for revalidation, so drive the
			// refreshes the revalidation schedule would perform; the keys are
			// dropped once the registry has repeated itself.
			registry.setStatus(status)
			for i := 0; i < 2; i++ {
				_, err = refreshNamespaceKeys(ctx, prefix)
				require.Error(t, err)
			}

			ok, _ = verifyToken(ctx, tok, prefix, audience, token_scopes.Broker_Reverse)
			assert.False(t, ok,
				"a de-registered namespace should stop verifying once the registry has said so, "+
					"rather than being carried to the staleness ceiling")
		})
	}
}

// withNamespaceKeyRetryInterval sets the fetch throttle for the duration of a
// test.  The cache reads it when it is built, so callers must set it before
// launching the key cache.
func withNamespaceKeyRetryInterval(t *testing.T, d time.Duration) {
	orig := namespaceKeyRetryInterval
	namespaceKeyRetryInterval = d
	t.Cleanup(func() { namespaceKeyRetryInterval = orig })
}
