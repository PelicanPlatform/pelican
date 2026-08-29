/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

package token

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
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// jwksServer is a stand-in issuer whose keys can be rotated and which can be
// taken down, counting the requests it serves.
type jwksServer struct {
	mu      sync.Mutex
	keys    jwk.Set
	down    bool
	status  int
	fetches int
	server  *httptest.Server
}

func newJwksServer(t *testing.T) *jwksServer {
	s := &jwksServer{keys: jwk.NewSet()}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.fetches++
		if s.down {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if s.status != 0 {
			// Mimic the registry, which answers with a JSON error document.
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

func (s *jwksServer) rotateTo(t *testing.T, kid string) {
	privEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	priv, err := jwk.FromRaw(privEC)
	require.NoError(t, err)
	pub, err := priv.PublicKey()
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, kid))
	require.NoError(t, pub.Set(jwk.AlgorithmKey, jwa.ES256))

	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pub))

	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = set
}

func (s *jwksServer) setDown(down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = down
}

// setStatus makes the server answer every request with the given status,
// standing in for a registry reporting that a namespace is unregistered (404)
// or no longer approved (403).  Zero restores normal service.
func (s *jwksServer) setStatus(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = code
}

func (s *jwksServer) fetchCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetches
}

func (s *jwksServer) resolver() JwksUrlResolver {
	return func(context.Context) (string, error) { return s.server.URL, nil }
}

// newTestJwksCache builds a cache whose goroutines are cleaned up with the test.
func newTestJwksCache(t *testing.T, options ...JwksCacheOption) *JwksCache {
	ctx, cancel := context.WithCancel(context.Background())
	egrp, ctx := errgroup.WithContext(ctx)
	t.Cleanup(func() {
		cancel()
		_ = egrp.Wait()
	})
	return NewJwksCache(ctx, egrp, options...)
}

func TestJwksCache_FetchesAndCaches(t *testing.T) {
	issuer := newJwksServer(t)
	issuer.rotateTo(t, "key-1")
	kc := newTestJwksCache(t)

	set, err := kc.Keys(context.Background(), "issuer-a", issuer.resolver())
	require.NoError(t, err)
	require.NotNil(t, set)
	_, found := set.LookupKeyID("key-1")
	assert.True(t, found)
	assert.Equal(t, 1, issuer.fetchCount())

	// A second read inside the revalidate window is served from cache.
	set, err = kc.Keys(context.Background(), "issuer-a", issuer.resolver())
	require.NoError(t, err)
	require.NotNil(t, set)
	assert.Equal(t, 1, issuer.fetchCount(), "a cached keyset should not be re-fetched")
}

// TestJwksCache_ServesThroughOutage verifies that an issuer going down does not
// break verification for keys already cached.
func TestJwksCache_ServesThroughOutage(t *testing.T) {
	issuer := newJwksServer(t)
	issuer.rotateTo(t, "key-1")
	kc := newTestJwksCache(t)

	_, err := kc.Keys(context.Background(), "issuer-a", issuer.resolver())
	require.NoError(t, err)
	fetches := issuer.fetchCount()

	issuer.setDown(true)
	for i := 0; i < 3; i++ {
		set, err := kc.Keys(context.Background(), "issuer-a", issuer.resolver())
		require.NoError(t, err, "an outage must not break an issuer whose keys are cached")
		_, found := set.LookupKeyID("key-1")
		assert.True(t, found)
	}
	assert.Equal(t, fetches, issuer.fetchCount(), "serving cached keys should not contact the issuer")
}

// TestJwksCache_FailsClosedPastMaxStaleness verifies the ceiling: once the keys
// are older than the limit and cannot be refreshed, they are no longer served.
func TestJwksCache_FailsClosedPastMaxStaleness(t *testing.T) {
	issuer := newJwksServer(t)
	issuer.rotateTo(t, "key-1")
	// Everything is immediately stale, so the next read must revalidate.
	kc := newTestJwksCache(t,
		WithJwksRevalidateInterval(0),
		WithJwksMaxStaleness(0),
		WithJwksRetryInterval(0),
	)

	_, err := kc.Keys(context.Background(), "issuer-a", issuer.resolver())
	require.NoError(t, err)

	issuer.setDown(true)
	_, err = kc.Keys(context.Background(), "issuer-a", issuer.resolver())
	require.Error(t, err, "keys past the staleness ceiling must not be served")
	assert.Contains(t, err.Error(), "refusing to use public keys")

	// Once the issuer is reachable again the keys are usable.
	issuer.setDown(false)
	set, err := kc.Keys(context.Background(), "issuer-a", issuer.resolver())
	require.NoError(t, err)
	require.NotNil(t, set)
}

// TestJwksCache_RevalidatesInBackground verifies that a stale-but-usable keyset
// is served immediately while a refresh happens out of band.
func TestJwksCache_RevalidatesInBackground(t *testing.T) {
	issuer := newJwksServer(t)
	issuer.rotateTo(t, "key-1")
	kc := newTestJwksCache(t,
		WithJwksRevalidateInterval(0), // always due for revalidation
		WithJwksRetryInterval(0),
	)

	set, err := kc.Keys(context.Background(), "issuer-a", issuer.resolver())
	require.NoError(t, err)
	_, found := set.LookupKeyID("key-1")
	require.True(t, found)

	issuer.rotateTo(t, "key-2")

	// The read is served from the cached set; the refresh happens behind it.
	set, err = kc.Keys(context.Background(), "issuer-a", issuer.resolver())
	require.NoError(t, err)
	require.NotNil(t, set)

	require.Eventually(t, func() bool {
		set, err := kc.Keys(context.Background(), "issuer-a", issuer.resolver())
		if err != nil {
			return false
		}
		_, found := set.LookupKeyID("key-2")
		return found
	}, 5*time.Second, 10*time.Millisecond, "the rotated key should be picked up by the background refresh")
}

// TestJwksCache_ThrottlesAttempts verifies that a down issuer is not contacted
// once per request.
func TestJwksCache_ThrottlesAttempts(t *testing.T) {
	issuer := newJwksServer(t)
	issuer.setDown(true)
	kc := newTestJwksCache(t, WithJwksRetryInterval(time.Hour))

	_, err := kc.Keys(context.Background(), "issuer-a", issuer.resolver())
	require.Error(t, err)
	assert.Equal(t, 1, issuer.fetchCount())

	for i := 0; i < 5; i++ {
		_, err = kc.Keys(context.Background(), "issuer-a", issuer.resolver())
		require.Error(t, err)
	}
	assert.Equal(t, 1, issuer.fetchCount(), "repeated requests must not each contact a down issuer")
}

// TestJwksCache_CollapsesConcurrentFetches verifies that a burst of concurrent
// requests for an uncached issuer produces one outbound fetch.
func TestJwksCache_CollapsesConcurrentFetches(t *testing.T) {
	issuer := newJwksServer(t)
	issuer.rotateTo(t, "key-1")
	kc := newTestJwksCache(t, WithJwksRetryInterval(0))

	var wg sync.WaitGroup
	errs := make([]error, 16)
	start := make(chan struct{})
	for i := 0; i < len(errs); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = kc.Keys(context.Background(), "issuer-a", issuer.resolver())
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "concurrent caller %d", i)
	}
	assert.Equal(t, 1, issuer.fetchCount(), "concurrent misses should collapse into one fetch")
}

// TestJwksCache_EvictsLeastRecentlyUsed verifies the capacity bound, which is
// what keeps caller-influenced keys from growing the cache without limit.
func TestJwksCache_EvictsLeastRecentlyUsed(t *testing.T) {
	issuer := newJwksServer(t)
	issuer.rotateTo(t, "key-1")
	kc := newTestJwksCache(t, WithJwksCapacity(2), WithJwksRetryInterval(0))

	for _, key := range []string{"a", "b", "c"} {
		_, err := kc.Keys(context.Background(), key, issuer.resolver())
		require.NoError(t, err)
	}
	assert.LessOrEqual(t, kc.entries.Len(), 2, "the cache must not grow past its capacity")
}

// TestJwksCache_DropsKeysWhenIssuerReportsAbsence verifies that an issuer which
// is reachable and says the keys should not be used causes them to be
// discarded, rather than served until the staleness ceiling.  This is how a
// de-registered or de-approved namespace stops verifying promptly.
func TestJwksCache_DropsKeysWhenIssuerReportsAbsence(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusGone, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			issuer := newJwksServer(t)
			issuer.rotateTo(t, "key-1")
			kc := newTestJwksCache(t,
				WithJwksDropOnAbsence(),
				WithJwksRevalidateInterval(0), // always due for revalidation
				WithJwksRetryInterval(0),
			)

			_, err := kc.Keys(context.Background(), "issuer-a", issuer.resolver())
			require.NoError(t, err)

			issuer.setStatus(status)

			// Each read serves the cached keys and revalidates behind it, so the
			// keys drop once the issuer has repeated itself.
			require.Eventually(t, func() bool {
				_, err := kc.Keys(context.Background(), "issuer-a", issuer.resolver())
				return err != nil
			}, 5*time.Second, 10*time.Millisecond, "keys should stop being served once the issuer reports them absent")
		})
	}
}

// TestJwksCache_KeepsKeysOnSingleAbsence verifies that one bad response does not
// revoke an issuer: a registry that 404s once and then recovers should leave
// verification undisturbed.
func TestJwksCache_KeepsKeysOnSingleAbsence(t *testing.T) {
	issuer := newJwksServer(t)
	issuer.rotateTo(t, "key-1")
	kc := newTestJwksCache(t,
		WithJwksDropOnAbsence(),
		WithJwksRetryInterval(0),
	)

	_, err := kc.Keys(context.Background(), "issuer-a", issuer.resolver())
	require.NoError(t, err)

	// One absence, then the issuer is healthy again.
	issuer.setStatus(http.StatusNotFound)
	_, err = kc.Refresh(context.Background(), "issuer-a", issuer.resolver())
	require.Error(t, err)
	issuer.setStatus(0)

	set, err := kc.Keys(context.Background(), "issuer-a", issuer.resolver())
	require.NoError(t, err, "a single absence must not discard the keys")
	require.NotNil(t, set)
	_, found := set.LookupKeyID("key-1")
	assert.True(t, found)
}

// TestJwksCache_KeepsKeysWhenIssuerCannotAnswer verifies that the drop applies
// only to real answers: an issuer that is down, however many times, leaves the
// cached keys in place.
func TestJwksCache_KeepsKeysWhenIssuerCannotAnswer(t *testing.T) {
	issuer := newJwksServer(t)
	issuer.rotateTo(t, "key-1")
	kc := newTestJwksCache(t,
		WithJwksDropOnAbsence(),
		WithJwksRetryInterval(0),
	)

	_, err := kc.Keys(context.Background(), "issuer-a", issuer.resolver())
	require.NoError(t, err)

	issuer.setDown(true)
	for i := 0; i < 5; i++ {
		_, err = kc.Refresh(context.Background(), "issuer-a", issuer.resolver())
		require.Error(t, err)
	}

	set, err := kc.Keys(context.Background(), "issuer-a", issuer.resolver())
	require.NoError(t, err, "an unreachable issuer must not discard the keys")
	require.NotNil(t, set)
	_, found := set.LookupKeyID("key-1")
	assert.True(t, found)
}

// TestJwksCache_AbsenceIgnoredWithoutOption verifies that the drop is opt-in:
// without it, a 404 is just another failed fetch and the keys keep serving.
func TestJwksCache_AbsenceIgnoredWithoutOption(t *testing.T) {
	issuer := newJwksServer(t)
	issuer.rotateTo(t, "key-1")
	kc := newTestJwksCache(t, WithJwksRetryInterval(0))

	_, err := kc.Keys(context.Background(), "issuer-a", issuer.resolver())
	require.NoError(t, err)

	issuer.setStatus(http.StatusNotFound)
	for i := 0; i < 5; i++ {
		_, err = kc.Refresh(context.Background(), "issuer-a", issuer.resolver())
		require.Error(t, err)
	}

	set, err := kc.Keys(context.Background(), "issuer-a", issuer.resolver())
	require.NoError(t, err, "without the option, keys should still be served")
	require.NotNil(t, set)
}

// TestJwksCache_ReportsHttpStatus verifies that a non-200 response is reported
// as such, rather than reaching the parser and surfacing as a parse failure.
func TestJwksCache_ReportsHttpStatus(t *testing.T) {
	issuer := newJwksServer(t)
	issuer.rotateTo(t, "key-1")
	issuer.setStatus(http.StatusNotFound)
	kc := newTestJwksCache(t, WithJwksRetryInterval(0))

	_, err := kc.Keys(context.Background(), "issuer-a", issuer.resolver())
	require.Error(t, err)

	var fetchErr *JwksFetchError
	require.ErrorAs(t, err, &fetchErr)
	assert.Equal(t, http.StatusNotFound, fetchErr.StatusCode)
	assert.True(t, fetchErr.IsAbsence())
}

// TestJwksCache_ResolverFailure verifies that a resolver error is reported and
// does not poison the entry against a later attempt.
func TestJwksCache_ResolverFailure(t *testing.T) {
	issuer := newJwksServer(t)
	issuer.rotateTo(t, "key-1")
	kc := newTestJwksCache(t, WithJwksRetryInterval(0))

	failing := func(context.Context) (string, error) {
		return "", errors.New("discovery unavailable")
	}
	_, err := kc.Keys(context.Background(), "issuer-a", failing)
	require.Error(t, err)

	set, err := kc.Keys(context.Background(), "issuer-a", issuer.resolver())
	require.NoError(t, err, "a later attempt should succeed once the URL resolves")
	require.NotNil(t, set)
}
