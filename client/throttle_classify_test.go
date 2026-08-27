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

package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/singleflight"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
)

// A cache sheds a request with 429 to say "come back later". Every request
// flavor the client issues has to recognize that, because an unclassified 429
// lands in the generic 4xx bucket, which is not retryable: the transfer would
// be reported as a permanent client error and the job would give up on a cache
// that was merely busy.

// TestObjectCachedThrottleIsClassified pins the cache-status probe. It issues
// a one-byte ranged GET and, when that does not answer the question, falls
// back to a HEAD.
//
// The fallback is the trap: a cache answers HEAD without consulting its fair
// scheduler, so the HEAD very likely succeeds even while the GET is being
// shed. If the throttle from the GET were discarded, the probe would report
// the object's cache status as authoritative on the strength of a request that
// never went through the scheduler.
func TestObjectCachedThrottleIsClassified(t *testing.T) {
	test_utils.InitClient(t, map[param.Param]any{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var headCount atomic.Int32
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			// A healthy-looking HEAD: this is what would overwrite the
			// throttle if the GET's classification were dropped.
			headCount.Add(1)
			w.Header().Set("Content-Length", "1024")
			w.Header().Set("Age", "42")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "17")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"origin_unresponsive","detail":"origin is not delivering data"}`))
	}))
	defer svr.Close()

	svrURL, err := url.Parse(svr.URL)
	require.NoError(t, err)
	svrURL.Path = "/ns/object"

	age, size, _, _, err := objectCached(ctx, svrURL, nil, false)

	require.Error(t, err, "a shed cache-status probe must not be reported as an answer")
	var throttled *CacheThrottleError
	require.ErrorAs(t, err, &throttled)
	assert.Equal(t, string(ShedOriginUnresponsive), throttled.Reason)
	assert.Equal(t, 17*time.Second, throttled.RetryAfter)
	assert.ErrorIs(t, err, ErrTooManyRequests)
	assert.True(t, IsRetryable(err), "a throttled probe must be retryable")

	assert.Zero(t, headCount.Load(),
		"the HEAD fallback must not run after a shed; its answer would overwrite the throttle")
	assert.Equal(t, -1, age, "no cache age was learned")
	assert.Zero(t, size, "no size was learned")
}

// TestObjectCachedHeadThrottleIsClassified covers the second request the probe
// can make: when the ranged GET succeeds but carries no Content-Range, the
// probe falls back to a HEAD, and that HEAD can be shed too.
func TestObjectCachedHeadThrottleIsClassified(t *testing.T) {
	test_utils.InitClient(t, map[param.Param]any{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		// 200 with no Content-Range, so the probe still needs the HEAD.
		w.WriteHeader(http.StatusOK)
	}))
	defer svr.Close()

	svrURL, err := url.Parse(svr.URL)
	require.NoError(t, err)
	svrURL.Path = "/ns/object"

	_, _, _, _, err = objectCached(ctx, svrURL, nil, false)
	require.Error(t, err)
	var throttled *CacheThrottleError
	require.ErrorAs(t, err, &throttled)
	assert.Equal(t, 5*time.Second, throttled.RetryAfter)
	assert.True(t, IsRetryable(err))
}

// TestStatHttpThrottleIsClassified pins the stat path, which reaches a cache
// through a WebDAV PROPFIND rather than the plain HTTP client.
//
// This is the path the cache itself takes to answer a HEAD request
// (HeadObject -> DoStat), so an unclassified throttle here has two victims: a
// client's stat is reported as a permanent failure, and the cache turns its
// upstream's 429 into a 500, telling its own client that something went wrong
// internally rather than to retry.
func TestStatHttpThrottleIsClassified(t *testing.T) {
	test_utils.InitClient(t, map[param.Param]any{})

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer svr.Close()

	svrURL, err := url.Parse(svr.URL)
	require.NoError(t, err)

	dest := &pelican_url.PelicanURL{
		Scheme: "pelican://",
		Host:   "example-federation.org",
		Path:   "/ns/object",
	}
	dirResp := server_structs.DirectorResponse{
		ObjectServers: []*url.URL{{Scheme: svrURL.Scheme, Host: svrURL.Host, Path: "/ns/object"}},
	}

	_, err = statHttp(context.Background(), dest, dirResp, nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTooManyRequests,
		"a shed stat must satisfy the same sentinel check as any other throttle")
	var throttled *CacheThrottleError
	require.ErrorAs(t, err, &throttled)
	assert.Equal(t, svrURL.Host, throttled.Endpoint)
	assert.True(t, IsRetryable(err),
		"an unclassified 429 would be a non-retryable specification error")
}

// TestStatHttpNotFoundStillClassified guards the neighbouring branches: adding
// the throttle case must not disturb how a genuinely missing object is
// reported, which is the answer that tells a client to stop rather than retry.
func TestStatHttpNotFoundStillClassified(t *testing.T) {
	test_utils.InitClient(t, map[param.Param]any{})

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer svr.Close()

	svrURL, err := url.Parse(svr.URL)
	require.NoError(t, err)

	dest := &pelican_url.PelicanURL{
		Scheme: "pelican://",
		Host:   "example-federation.org",
		Path:   "/ns/object",
	}
	dirResp := server_structs.DirectorResponse{
		ObjectServers: []*url.URL{{Scheme: svrURL.Scheme, Host: svrURL.Host, Path: "/ns/object"}},
	}

	_, err = statHttp(context.Background(), dest, dirResp, nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrObjectNotFound)
	assert.NotErrorIs(t, err, ErrTooManyRequests)
	assert.False(t, IsRetryable(err), "a missing object is not worth retrying")
}

// newTPCTestToken returns a token generator with the value already set, so
// nothing tries to acquire one from a federation that does not exist.
func newTPCTestToken() *tokenGenerator {
	tg := &tokenGenerator{Sync: new(singleflight.Group)}
	tg.SetToken("test-token")
	return tg
}

// newTPCTestTransfer builds the minimal transferFile copyHTTP needs: a source
// to HEAD and a destination to COPY to.
func newTPCTestTransfer(ctx context.Context, srcURL, destURL *url.URL) *transferFile {
	return &transferFile{
		ctx:       ctx,
		remoteURL: &url.URL{Scheme: "pelican", Host: "example-federation.org", Path: "/ns/object"},
		attempts:  []transferAttemptDetails{{Url: srcURL}},
		token:     newTPCTestToken(),
		job: &TransferJob{
			uuid:     uuid.New(),
			xferType: transferTypeCopy,
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   "example-federation.org",
				Path:   "/ns/object",
			},
			destDirResp: server_structs.DirectorResponse{
				ObjectServers: []*url.URL{destURL},
			},
		},
	}
}

// TestCopyHTTPSourceThrottleIsClassified pins the third-party-copy source
// probe. A copy starts by HEADing the source to learn its size; a source that
// sheds that HEAD has not refused the copy permanently, it has asked for a
// retry.
func TestCopyHTTPSourceThrottleIsClassified(t *testing.T) {
	test_utils.InitClient(t, map[param.Param]any{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "12")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer src.Close()
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the destination must not be contacted after the source shed the request")
	}))
	defer dest.Close()

	srcURL, err := url.Parse(src.URL + "/ns/object")
	require.NoError(t, err)
	destURL, err := url.Parse(dest.URL + "/ns/object")
	require.NoError(t, err)

	_, err = copyHTTP(newTPCTestTransfer(ctx, srcURL, destURL))
	require.Error(t, err)
	var throttled *CacheThrottleError
	require.ErrorAs(t, err, &throttled)
	assert.Equal(t, 12*time.Second, throttled.RetryAfter)
	// A response to HEAD carries no body, so there is no structured reason to
	// report on this leg -- only that the source shed the request.
	assert.Empty(t, throttled.Reason)
	assert.Equal(t, srcURL.Host, throttled.Endpoint)
	assert.ErrorIs(t, err, ErrTooManyRequests)
	assert.True(t, IsRetryable(err))
}

// TestCopyHTTPDestinationThrottleIsClassified pins the other half: the source
// is healthy, but the destination sheds the COPY itself.
func TestCopyHTTPDestinationThrottleIsClassified(t *testing.T) {
	test_utils.InitClient(t, map[param.Param]any{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "2048")
		w.WriteHeader(http.StatusOK)
	}))
	defer src.Close()
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "45")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"cache_overloaded","detail":"pending buffer is full"}`))
	}))
	defer dest.Close()

	srcURL, err := url.Parse(src.URL + "/ns/object")
	require.NoError(t, err)
	destURL, err := url.Parse(dest.URL + "/ns/object")
	require.NoError(t, err)

	_, err = copyHTTP(newTPCTestTransfer(ctx, srcURL, destURL))
	require.Error(t, err)
	var throttled *CacheThrottleError
	require.ErrorAs(t, err, &throttled)
	assert.Equal(t, string(ShedCacheOverloaded), throttled.Reason)
	assert.Equal(t, 45*time.Second, throttled.RetryAfter)
	assert.Equal(t, destURL.Host, throttled.Endpoint)
	assert.True(t, IsRetryable(err),
		"a shed copy must be retried rather than reported as a permanent failure")
}
