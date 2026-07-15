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

// TestScheduler_BurstRejects429 exercises the whole fed under a
// scheduler tightened enough that a concurrent burst of cache-miss
// requests forces per-origin admission rejections. The test asserts
// that at least some of those rejections surface as HTTP 429 with
// Retry-After: 60 — i.e. the wire contract the cache advertises to
// clients under overload actually fires under real load, not just in
// unit-level mocks.
//
// Configuration knobs (set via param before NewFedTest):
//   - Cache.WorkerCount:                    4  — tiny pool
//   - Cache.Throttle.PerOriginStarvingPercent: 25% (starving cap = 1)
//   - Cache.Throttle.PerOriginActivePercent:   25% (active cap = 1)
//   - Cache.Throttle.PendingBufferSize:     2  — very tight
//   - Cache.Throttle.PerOriginPendingSize:  2
//   - Cache.Throttle.EMAWindow:             1s
//
// With those knobs and a burst of N=30 concurrent requests for
// distinct objects on the same origin, at most ~3 requests can be
// admitted at any moment (1 in-flight + 2 pending); the rest fill
// the FIFO faster than transfers can complete and get 429'd.
func TestScheduler_BurstRejects429(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Enable the persistent cache and clamp the fair scheduler down.
	// Params must be set BEFORE NewFedTest starts the servers, since
	// NewPersistentCache reads them at construction time.
	require.NoError(t, param.Cache_EnableV2.Set(true))
	require.NoError(t, param.Cache_WorkerCount.Set(2))
	require.NoError(t, param.Cache_Throttle_PerOriginStarvingPercent.Set(25))
	require.NoError(t, param.Cache_Throttle_PerOriginActivePercent.Set(25))
	require.NoError(t, param.Cache_Throttle_PendingBufferSize.Set(1))
	require.NoError(t, param.Cache_Throttle_PerOriginPendingSize.Set(1))
	require.NoError(t, param.Cache_Throttle_EMAWindow.Set(time.Second))

	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)
	require.NotNil(t, ft)
	require.Greater(t, len(ft.Exports), 0)

	// Upload N distinct objects to the origin, one per burst request.
	// Distinct paths mean distinct persistentDownload entries in the
	// cache — each has to independently reach scheduler admission
	// rather than piggybacking on the same in-flight download.
	//
	// A modest 256 KiB payload gives the origin enough real transfer
	// time that concurrent scheduler admissions overlap.
	const nRequests = 30
	payload := bytes.Repeat([]byte("scheduler-burst-test-"), 256*1024/21+1)[:256*1024]
	localDir := t.TempDir()
	testToken := getTempTokenForTest(t)
	for i := 0; i < nRequests; i++ {
		localFile := filepath.Join(localDir, fmt.Sprintf("burst-%d.bin", i))
		require.NoError(t, os.WriteFile(localFile, payload, 0644))
		uploadURL := fmt.Sprintf("pelican://%s:%d/test/burst-%d.bin",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), i)
		_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
		require.NoError(t, err)
	}

	// Resolve one director-provided cache URL, then derive the per-
	// object URL template from it. The redirect looks like:
	//   https://<cache>/api/v1.0/cache/data/<origin>/test/burst-0.bin?authz=…
	// so we split at /test/ to pull out the (scheme+host+API+origin)
	// prefix and the query string, then rebuild for each object.
	cacheObj0URL := getCacheRedirectURL(ft.Ctx, t, "/test/burst-0.bin", testToken)
	parsed, err := url.Parse(cacheObj0URL)
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(parsed.Path, "/test/burst-0.bin"),
		"redirect path %q must end with the object path we asked for", parsed.Path)
	prefix := strings.TrimSuffix(parsed.Path, "/test/burst-0.bin")
	query := parsed.RawQuery
	t.Logf("cache base URL: %s://%s%s (query %q)", parsed.Scheme, parsed.Host, prefix, query)

	// Fire the burst.
	type result struct {
		status     int
		retryAfter string
		err        error
	}
	results := make([]result, nRequests)
	httpClient := &http.Client{
		Transport: config.GetTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Follow redirects, but preserve Authorization on same-host hops
			// so we don't lose the token when the cache HEADs upstream.
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
				Path:     fmt.Sprintf("%s/test/burst-%d.bin", prefix, i),
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
			_, _ = io.Copy(io.Discard, resp.Body)
			results[i] = result{
				status:     resp.StatusCode,
				retryAfter: resp.Header.Get("Retry-After"),
			}
		}(i)
	}
	wg.Wait()

	// Tally outcomes.
	histogram := map[int]int{}
	var status429, withRetryAfter, errCount int
	for _, r := range results {
		if r.err != nil {
			errCount++
			continue
		}
		histogram[r.status]++
		if r.status == http.StatusTooManyRequests {
			status429++
			if r.retryAfter == "60" {
				withRetryAfter++
			}
		}
	}
	t.Logf("burst results: 429=%d (with Retry-After=%d), errors=%d, histogram=%v",
		status429, withRetryAfter, errCount, histogram)

	require.Greater(t, status429, 0,
		"tight fair scheduler must produce at least one HTTP 429 across a %d-way concurrent burst; instead got histogram=%v (errors=%d)",
		nRequests, histogram, errCount)
	assert.Equal(t, status429, withRetryAfter,
		"every 429 response must include the documented Retry-After: 60 header")
}
