//go:build !windows

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

package fed_tests

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// validShedReasons is the closed set of machine-parseable reasons a cache may
// put in the "error" field of a 429 body. The values come from the
// client.ShedReason constants rather than fresh string literals on purpose:
// the scheduler, the cache's HTTP layer, and the client's body parser must all
// agree on the same spelling, and reusing the constants makes any future
// rename break here instead of silently degrading a production 429 into an
// unclassifiable throttle.
var validShedReasons = []string{
	string(client.ShedOriginUnresponsive),
	string(client.ShedOriginSlow),
	string(client.ShedCacheOverloaded),
}

// isPerOriginShedReason reports whether a reason blames the upstream origin
// (as opposed to cache-wide saturation). These are the reasons produced by the
// scheduler's per-origin pending path.
func isPerOriginShedReason(reason string) bool {
	return reason == string(client.ShedOriginUnresponsive) ||
		reason == string(client.ShedOriginSlow)
}

// burstOriginConfig is this test's private copy of the persistent-cache origin
// configuration (resources/persistent_cache_config.yaml) plus one addition:
// Origin.TransferRateLimit. The shared resource file is used by many other
// tests that do not want a slow origin, so the knob is added here instead of
// there.
//
// posixv2 is the origin backend that honors the rate limit (see
// origin_serve/rate_limited_fs.go), and 40 KB/s against a 256 KiB object makes
// every cache-miss fetch take ~6.5 s. That is what turns this test from a race
// into arithmetic: the fetch the scheduler admits first is still holding its
// tag's only active slot when the remaining requests of the burst arrive.
const burstOriginConfig = `Origin:
  StorageType: "posixv2"
  EnableDirectReads: true
  TransferRateLimit: 40KB/s
  Exports:
    - StoragePrefix: /<SHOULD BE OVERRIDDEN>
      FederationPrefix: /test
      Capabilities: ["PublicReads", "Writes", "DirectReads", "Listings"]
`

// burstObjectPath is the federation path of the i'th object of a burst set.
func burstObjectPath(prefix string, i int) string {
	return fmt.Sprintf("/test/%s-%d.bin", prefix, i)
}

// burstObjectURL is the pelican:// URL of the i'th object of a burst set.
func burstObjectURL(prefix string, i int) string {
	return fmt.Sprintf("pelican://%s:%d%s",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(),
		burstObjectPath(prefix, i))
}

// stageBurstObjects places n objects with identical contents but distinct
// paths on the origin. Distinct paths are what make a burst interesting: each
// one becomes its own cache-miss download inside the cache and therefore has
// to independently clear scheduler admission, rather than coalescing onto a
// single in-flight fetch.
//
// The objects are written straight into the origin's storage directory instead
// of being uploaded through the origin's HTTP interface, because the origin's
// rate limiter is a single bucket shared by reads and writes: pushing
// nRequests * 256 KiB through it at 40 KB/s would take minutes and outlive the
// upload tokens. The rate limit exists to slow the cache's fetches down, not
// the staging of the test data.
func stageBurstObjects(t *testing.T, ft *fed_test_utils.FedTest, prefix string, payload []byte, n int) {
	t.Helper()
	storageDir := ft.Exports[0].StoragePrefix
	for i := 0; i < n; i++ {
		objectFile := filepath.Join(storageDir, fmt.Sprintf("%s-%d.bin", prefix, i))
		require.NoError(t, os.WriteFile(objectFile, payload, 0644))
	}
}

// TestScheduler_BurstRejects429 drives a real federation hard enough that the
// cache's fair scheduler sheds admissions, then follows a shed out through
// both surfaces it has to satisfy:
//
//  1. Raw HTTP against the cache: status 429, Retry-After: 60, and a JSON body
//     {"error": <reason>, "detail": ...} whose reason is one of the three
//     client.ShedReason values.
//  2. The Pelican client: client.DoGet turns that response into a typed
//     *client.CacheThrottleError carrying the reason, the parsed Retry-After
//     duration, and a retryable classification.
//
// Taken together the phases weld one cross-component contract end to end:
// scheduler shed reason → cache 429 header + JSON → client body/header
// parsing → typed retryable error. Unit tests can cover each hop in
// isolation; only a fed test shows that the hops line up under real load.
//
// Configuration (all set before NewFedTest, because NewPersistentCache reads
// these once at construction time):
//
//	Cache.EnableV2                           true — the persistent cache owns the scheduler
//	Cache.WorkerCount                        2
//	Cache.Throttle.PerOriginStarvingPercent  25   → starving cap = ceil(2 * 25/100) = 1
//	Cache.Throttle.PerOriginActivePercent    25   → active cap   = ceil(2 * 25/100) = 1
//	Cache.Throttle.PendingBufferSize         16
//	Cache.Throttle.PerOriginPendingSize      1
//	Cache.Throttle.EMAWindow                 1s
//
// plus, on the origin side (burstOriginConfig):
//
//	Origin.TransferRateLimit                 40KB/s
//
// Why that configuration sheds: every object in a burst lives on the same
// origin, so all admissions share one scheduler tag. That tag may hold a
// single in-flight transfer (active cap 1) and queue a single pending one
// (per-origin pending 1), so at most two of a 30-request burst are in the
// system at any moment and the other ~28 arrive to find the tag's FIFO already
// full.
//
// The rate limit is what makes that deterministic rather than timing-dependent.
// A 256 KiB object at 40 KB/s takes ~6.5 s to fetch, so the admitted transfer
// still holds the tag's only active slot for seconds after the burst is issued
// — the shed count follows from the caps instead of from how fast the origin
// happens to be. It also keeps the successful requests comfortably inside the
// budget: only two fetches ever run, back to back, so the slowest 200 response
// lands ~13 s in, well under the 60 s HTTP client timeout below and under
// ft.Ctx's deadline (inherited from the go-test timeout).
//
// Those rejections are attributed to the origin rather than the cache: the
// per-origin pending cap is checked before the global pending buffer, and the
// 16-entry global buffer is comfortably larger than anything one origin can
// occupy here, so it never becomes the binding limit. The reason is then
// origin_unresponsive while the tag's in-flight fetch has yet to produce a
// first byte, or origin_slow once it has. A cache_overloaded verdict is
// legal but not expected: it requires the tag's FIFO to be full at an instant
// when the tag holds no in-flight transfer at all.
func TestScheduler_BurstRejects429(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Enable the persistent cache and clamp the fair scheduler down.
	require.NoError(t, param.Cache_EnableV2.Set(true))
	require.NoError(t, param.Cache_WorkerCount.Set(2))
	require.NoError(t, param.Cache_Throttle_PerOriginStarvingPercent.Set(25))
	require.NoError(t, param.Cache_Throttle_PerOriginActivePercent.Set(25))
	require.NoError(t, param.Cache_Throttle_PendingBufferSize.Set(16))
	require.NoError(t, param.Cache_Throttle_PerOriginPendingSize.Set(1))
	require.NoError(t, param.Cache_Throttle_EMAWindow.Set(time.Second))

	ft := fed_test_utils.NewFedTest(t, burstOriginConfig)
	require.NotNil(t, ft)
	require.Greater(t, len(ft.Exports), 0)

	// A 256 KiB payload against the origin's 40 KB/s limit makes each
	// cache-miss fetch take ~6.5 s, so an admitted transfer is guaranteed to
	// still hold its tag's active slot while the rest of the burst arrives.
	const nRequests = 30
	const httpPrefix = "burst"
	const clientPrefix = "client-burst"
	payload := bytes.Repeat([]byte("scheduler-burst-test-"), 256*1024/21+1)[:256*1024]

	testToken := getTempTokenForTest(t)
	stageBurstObjects(t, ft, httpPrefix, payload, nRequests)

	// Phase 1: raw HTTP against the cache.
	//
	// Resolve one director-provided cache URL, then derive the per-object URL
	// template from it. The redirect looks like:
	//   https://<cache>/api/v1.0/cache/data/<origin>/test/burst-0.bin?authz=…
	// so we split at the object path to pull out the (scheme+host+API+origin)
	// prefix and the query string, then rebuild for each object.
	firstObject := burstObjectPath(httpPrefix, 0)
	cacheObj0URL := getCacheRedirectURL(ft.Ctx, t, firstObject, testToken)
	parsed, err := url.Parse(cacheObj0URL)
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(parsed.Path, firstObject),
		"redirect path %q must end with the object path we asked for", parsed.Path)
	prefix := strings.TrimSuffix(parsed.Path, firstObject)
	query := parsed.RawQuery
	t.Logf("cache base URL: %s://%s%s (query %q)", parsed.Scheme, parsed.Host, prefix, query)

	type result struct {
		status     int
		retryAfter string
		// reason is the "error" field of a 429 JSON body.
		reason string
		err    error
	}
	results := make([]result, nRequests)
	httpClient := &http.Client{
		Transport: config.GetTransport(),
		// Bound every request so a stalled cache fails this test with a clear
		// transport error instead of consuming the package-level go-test
		// timeout and taking unrelated tests down with it.
		Timeout: 60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Follow redirects, but stop after a handful of hops and hand back
			// the last response rather than erroring out.
			if len(via) > 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	var wg sync.WaitGroup
	for i := 0; i < nRequests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			reqURL := &url.URL{
				Scheme:   parsed.Scheme,
				Host:     parsed.Host,
				Path:     prefix + burstObjectPath(httpPrefix, i),
				RawQuery: query,
			}
			req, err := http.NewRequestWithContext(ft.Ctx, http.MethodGet, reqURL.String(), nil)
			if err != nil {
				results[i] = result{err: err}
				return
			}
			req.Header.Set("Authorization", "Bearer "+testToken)
			resp, err := httpClient.Do(req)
			if err != nil {
				results[i] = result{err: err}
				return
			}
			defer resp.Body.Close()
			res := result{
				status:     resp.StatusCode,
				retryAfter: resp.Header.Get("Retry-After"),
			}
			if resp.StatusCode == http.StatusTooManyRequests {
				// The reason is the whole point of the 429 body; parse it
				// rather than discarding it like a successful payload.
				body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
				if readErr != nil {
					results[i] = result{err: readErr}
					return
				}
				var parsedBody struct {
					Error  string `json:"error"`
					Detail string `json:"detail"`
				}
				if jsonErr := json.Unmarshal(body, &parsedBody); jsonErr != nil {
					results[i] = result{err: fmt.Errorf("429 body %q is not JSON: %w", string(body), jsonErr)}
					return
				}
				res.reason = parsedBody.Error
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			results[i] = res
		}(i)
	}
	wg.Wait()

	// Tally outcomes.
	histogram := map[int]int{}
	reasons := map[string]int{}
	var status429, withRetryAfter, perOriginReasons, errCount int
	for _, r := range results {
		if r.err != nil {
			errCount++
			t.Logf("transport error during raw burst: %v", r.err)
			continue
		}
		histogram[r.status]++
		if r.status == http.StatusTooManyRequests {
			status429++
			if r.retryAfter == "60" {
				withRetryAfter++
			}
			reasons[r.reason]++
			assert.Contains(t, validShedReasons, r.reason,
				"429 body must carry one of the machine-parseable shed reasons")
			if isPerOriginShedReason(r.reason) {
				perOriginReasons++
			}
		}
	}
	t.Logf("raw burst results: 429=%d (with Retry-After=%d), errors=%d, histogram=%v, reasons=%v",
		status429, withRetryAfter, errCount, histogram, reasons)

	require.Zero(t, errCount,
		"every raw burst request must complete at the HTTP layer; %d failed in transport", errCount)
	require.Greater(t, status429, 0,
		"tight fair scheduler must produce at least one HTTP 429 across a %d-way concurrent burst; instead got histogram=%v",
		nRequests, histogram)
	assert.Equal(t, status429, withRetryAfter,
		"every 429 response must include the documented Retry-After: 60 header")
	assert.Greater(t, perOriginReasons, 0,
		"the per-origin pending cap must shed at least one request with an origin-specific reason (%s or %s); saw reasons=%v",
		client.ShedOriginUnresponsive, client.ShedOriginSlow, reasons)

	// Phase 2: the same shed as seen through the Pelican client.
	//
	// A fresh object set keeps these downloads on the cache-miss path (a hit
	// is served from local storage and never reaches the scheduler), and a
	// fresh token avoids the one-minute lifetime of the phase-1 token, which
	// phase 1 may well have burned through waiting on 40 KB/s fetches.
	clientToken := getTempTokenForTest(t)
	stageBurstObjects(t, ft, clientPrefix, payload, nRequests)

	downloadDir := t.TempDir()
	clientErrs := make([]error, nRequests)
	var clientWg sync.WaitGroup
	for i := 0; i < nRequests; i++ {
		clientWg.Add(1)
		go func(i int) {
			defer clientWg.Done()
			dest := filepath.Join(downloadDir, fmt.Sprintf("%s-%d.bin", clientPrefix, i))
			_, err := client.DoGet(ft.Ctx, burstObjectURL(clientPrefix, i), dest, false,
				client.WithToken(clientToken))
			clientErrs[i] = err
		}(i)
	}
	clientWg.Wait()

	var throttledCount, otherErrCount, okCount int
	clientReasons := map[string]int{}
	for _, err := range clientErrs {
		if err == nil {
			okCount++
			continue
		}
		var throttleErr *client.CacheThrottleError
		if !errors.As(err, &throttleErr) {
			otherErrCount++
			t.Logf("non-throttle client error: %v", err)
			continue
		}
		throttledCount++
		clientReasons[throttleErr.Reason]++
		assert.Contains(t, validShedReasons, throttleErr.Reason,
			"throttle error must carry a reason parsed from the cache's 429 body")
		assert.Equal(t, 60*time.Second, throttleErr.RetryAfter,
			"throttle error must carry the cache's Retry-After: 60 as a duration")
		assert.True(t, client.ShouldRetry(err),
			"a throttle is transient by construction and must be classified retryable: %v", err)
	}
	t.Logf("client burst results: throttled=%d (reasons=%v), other errors=%d, succeeded=%d",
		throttledCount, clientReasons, otherErrCount, okCount)

	require.Greater(t, throttledCount, 0,
		"at least one client.DoGet in a %d-way burst must fail with *client.CacheThrottleError; instead got %d successes and %d other errors",
		nRequests, okCount, otherErrCount)
}
