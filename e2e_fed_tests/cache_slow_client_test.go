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
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// These tests cover a cache miss whose download from the origin takes longer
// than LocalCache.PrefetchTimeout.  The origin is limited to 2 MB/s and the
// timeout is 1 s, so an 8 MB object takes about four times the timeout.
//
// The cache streams a miss to the client from its own disk while a separate
// transfer fills it from the origin, so the client's pace must not matter to
// that transfer.  Before this was fixed, the transfer's idle timer saw no
// activity from readers of an in-flight download, declared it idle once the
// timeout passed -- however fast the client read -- and the cache then
// deleted the object it had just finished downloading.

const (
	slowClientOriginRate = "2MB/s"
	slowClientObjectSize = 8 * 1024 * 1024

	// abandonedObjectSize is the size of an object whose download is
	// abandoned part-way: large enough that the download is still well
	// short of the end when the idle timeout stops it, even on a loaded
	// machine.
	abandonedObjectSize = 16 * 1024 * 1024
)

func startSlowClientFed(t *testing.T) (*fed_test_utils.FedTest, string) {
	t.Helper()
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	require.NoError(t, param.Cache_EnableV2.Set(true))
	require.NoError(t, param.LocalCache_PrefetchTimeout.Set(time.Second))
	ft := fed_test_utils.NewFedTest(t, slowOriginConfig(slowClientOriginRate))
	return ft, getTempTokenForTest(t)
}

// originBytesRead is how many bytes the origin's POSIXv2 backend has read
// from its storage, the origin's view of how far a transfer has gone.
func originBytesRead(t *testing.T) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	total := 0.0
	for _, mf := range families {
		if mf.GetName() != "pelican_storage_bytes_read_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "backend" && l.GetValue() == metrics.BackendPOSIXv2 {
					total += m.GetCounter().GetValue()
				}
			}
		}
	}
	return total
}

// originOpens is how many times the origin's POSIXv2 backend has opened a
// file: one per request the cache sends it.
func originOpens(t *testing.T) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	total := 0.0
	for _, mf := range families {
		if mf.GetName() != "pelican_storage_opens_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "backend" && l.GetValue() == metrics.BackendPOSIXv2 {
					total += m.GetCounter().GetValue()
				}
			}
		}
	}
	return total
}

// cacheGet starts a GET from the cache that asks, as every Pelican client
// does, for the transfer's status in the X-Transfer-Status trailer.
func cacheGet(t *testing.T, ctx context.Context, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)
	req.Header.Set("X-Transfer-Status", "true")
	req.Header.Set("TE", "trailers")
	resp, err := (&http.Client{Transport: config.GetTransport()}).Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return resp
}

// requireTransferOK checks the X-Transfer-Status trailer of a response read
// to the end.  A Pelican client fails the attempt on anything but 200, even
// when every byte arrived.
func requireTransferOK(t *testing.T, resp *http.Response) {
	t.Helper()
	require.Equal(t, "200: OK", resp.Trailer.Get("X-Transfer-Status"),
		"the client must be told the transfer succeeded")
}

// requireCached checks that the object is served without the origin reading
// it again -- i.e. that the cache kept it.
func requireCached(t *testing.T, ctx context.Context, url string, want []byte) {
	t.Helper()
	before := originBytesRead(t)
	resp := cacheGet(t, ctx, url)
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.True(t, bytes.Equal(want, got), "the cached copy must be intact")
	requireTransferOK(t, resp)
	assert.Less(t, originBytesRead(t)-before, float64(len(want))/2,
		"the second read must be served from the cache, not fetched from the origin again")
}

// TestCacheMissOutlastingIdleTimeoutIsKept: a client that reads as fast as it
// can still outlasts the idle timeout, because the origin is slow.  The cache
// must keep the object.
func TestCacheMissOutlastingIdleTimeoutIsKept(t *testing.T) {
	ft, token := startSlowClientFed(t)
	content := writeOriginFile(t, ft, "slow_origin.bin", slowClientObjectSize)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/slow_origin.bin", token)
	ctx, cancel := context.WithTimeout(ft.Ctx, 2*time.Minute)
	defer cancel()

	resp := cacheGet(t, ctx, cacheURL)
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.True(t, bytes.Equal(content, got))
	requireTransferOK(t, resp)

	requireCached(t, ctx, cacheURL, content)
}

// TestCacheMissWithStalledClientIsKept: a client that stops reading part-way
// must neither slow nor stop the cache's download from the origin, which runs
// to completion while the client sits on the open response.
func TestCacheMissWithStalledClientIsKept(t *testing.T) {
	ft, token := startSlowClientFed(t)
	content := writeOriginFile(t, ft, "stalled_client.bin", slowClientObjectSize)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/stalled_client.bin", token)
	ctx, cancel := context.WithTimeout(ft.Ctx, 2*time.Minute)
	defer cancel()

	start := originBytesRead(t)
	resp := cacheGet(t, ctx, cacheURL)
	defer resp.Body.Close()
	head := make([]byte, 64*1024)
	_, err := io.ReadFull(resp.Body, head)
	require.NoError(t, err)

	// The client stops reading.  The origin must still serve the whole object.
	require.Eventually(t, func() bool { return originBytesRead(t)-start >= slowClientObjectSize },
		time.Minute, 100*time.Millisecond, "the cache's download must run to completion while the client stalls")

	rest, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.True(t, bytes.Equal(content, append(head, rest...)))
	requireTransferOK(t, resp)

	requireCached(t, ctx, cacheURL, content)
}

// TestAbandonedCacheMissKeepsWholeBlocks: when the only client goes away, the
// download is cancelled after the idle timeout -- really cancelled, so the
// origin stops sending -- and the whole blocks already written are kept, so a
// later read fetches only the rest.
func TestAbandonedCacheMissKeepsWholeBlocks(t *testing.T) {
	ft, token := startSlowClientFed(t)
	content := writeOriginFile(t, ft, "abandoned.bin", abandonedObjectSize)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/abandoned.bin", token)
	ctx, cancel := context.WithTimeout(ft.Ctx, 2*time.Minute)
	defer cancel()

	start := originBytesRead(t)
	resp := cacheGet(t, ctx, cacheURL)
	head := make([]byte, 64*1024)
	_, err := io.ReadFull(resp.Body, head)
	require.NoError(t, err)
	resp.Body.Close()

	// The origin stops sending before the end of the object: the download
	// was cancelled, not merely forgotten.
	last := -1.0
	require.Eventually(t, func() bool {
		read := originBytesRead(t) - start
		stopped := read == last
		last = read
		return stopped
	}, time.Minute, 1500*time.Millisecond, "the abandoned download must stop")
	fetchedFirst := last
	require.Less(t, fetchedFirst, float64(abandonedObjectSize), "the download must stop before the end")
	require.Greater(t, fetchedFirst, 0.0)

	// A later read gets the whole object, fetching only what was not kept --
	// and in one request, not one per read.
	before := originBytesRead(t)
	opens := originOpens(t)
	resp = cacheGet(t, ctx, cacheURL)
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.True(t, bytes.Equal(content, got))
	requireTransferOK(t, resp)
	assert.Less(t, originBytesRead(t)-before, float64(abandonedObjectSize)-fetchedFirst/2,
		"the blocks the abandoned download wrote must be kept, not fetched again")
	assert.LessOrEqual(t, originOpens(t)-opens, 2.0,
		"the rest of the object must be fetched by one background fill, not one request per read")
}

// TestLaterReaderOfACacheMissKeepsItGoing: a reader that arrives while a miss
// is filling the object reaches it as a cache hit, not through the download
// that the first reader started.  It must keep that download going after the
// first reader leaves, just as the first reader did.
func TestLaterReaderOfACacheMissKeepsItGoing(t *testing.T) {
	ft, token := startSlowClientFed(t)
	content := writeOriginFile(t, ft, "two_readers.bin", slowClientObjectSize)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/two_readers.bin", token)
	ctx, cancel := context.WithTimeout(ft.Ctx, 2*time.Minute)
	defer cancel()

	start := originBytesRead(t)
	first := cacheGet(t, ctx, cacheURL)
	head := make([]byte, 64*1024)
	_, err := io.ReadFull(first.Body, head)
	require.NoError(t, err)

	second := cacheGet(t, ctx, cacheURL)
	defer second.Body.Close()
	_, err = io.ReadFull(second.Body, head)
	require.NoError(t, err)
	first.Body.Close() // the first reader leaves; the second stays, stalled

	require.Eventually(t, func() bool { return originBytesRead(t)-start >= slowClientObjectSize },
		time.Minute, 100*time.Millisecond, "the download must run to completion while the second reader is open")
	rest, err := io.ReadAll(second.Body)
	require.NoError(t, err)
	require.True(t, bytes.Equal(content, append(head, rest...)))
	requireTransferOK(t, second)

	requireCached(t, ctx, cacheURL, content)
}

// TestAbandonedFillStops: the background fill that resumes a partly cached
// object follows the same rule as the download that a miss starts -- once
// its last reader has gone for the idle timeout, it stops, keeping the whole
// blocks it wrote.
func TestAbandonedFillStops(t *testing.T) {
	ft, token := startSlowClientFed(t)
	content := writeOriginFile(t, ft, "abandoned_twice.bin", abandonedObjectSize)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/abandoned_twice.bin", token)
	ctx, cancel := context.WithTimeout(ft.Ctx, 2*time.Minute)
	defer cancel()

	// abandon reads the start of the object and leaves, then waits for the
	// origin to stop sending; it returns how much the origin sent.
	abandon := func(offset int64) float64 {
		start := originBytesRead(t)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cacheURL, nil)
		require.NoError(t, err)
		if offset > 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
		}
		resp, err := (&http.Client{Transport: config.GetTransport()}).Do(req)
		require.NoError(t, err)
		_, err = io.ReadFull(resp.Body, make([]byte, 64*1024))
		require.NoError(t, err)
		resp.Body.Close()
		last := -1.0
		require.Eventually(t, func() bool {
			read := originBytesRead(t) - start
			stopped := read == last
			last = read
			return stopped
		}, time.Minute, 1500*time.Millisecond, "the abandoned transfer must stop")
		return last
	}

	first := abandon(0)
	require.Less(t, first, float64(abandonedObjectSize))
	// Read on from where the first download stopped: a fill starts there,
	// and is abandoned in turn.
	second := abandon(int64(first))
	require.Greater(t, second, 0.0)
	require.Less(t, first+second, float64(abandonedObjectSize), "the fill must stop before the end")

	resp := cacheGet(t, ctx, cacheURL)
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.True(t, bytes.Equal(content, got))
	requireTransferOK(t, resp)
}

// TestRangeAheadOfACacheMissIsNotHeldBehindIt: a range request for the end
// of an object whose miss is still being downloaded, in order, is served by
// a fill of its own range rather than held until the download reaches it --
// here about eight seconds, for a slow origin and a large object hours.  The
// download then goes on and completes the object around the filled range.
func TestRangeAheadOfACacheMissIsNotHeldBehindIt(t *testing.T) {
	ft, token := startSlowClientFed(t)
	content := writeOriginFile(t, ft, "range_ahead.bin", abandonedObjectSize)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/range_ahead.bin", token)
	ctx, cancel := context.WithTimeout(ft.Ctx, 2*time.Minute)
	defer cancel()

	// Start the miss, and stay with it so it runs to the end.
	whole := cacheGet(t, ctx, cacheURL)
	defer whole.Body.Close()
	head := make([]byte, 64*1024)
	_, err := io.ReadFull(whole.Body, head)
	require.NoError(t, err)

	const tailSize = 64 * 1024
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cacheURL, nil)
	require.NoError(t, err)
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-", abandonedObjectSize-tailSize))
	req.Header.Set("X-Transfer-Status", "true")
	req.Header.Set("TE", "trailers")
	started := time.Now()
	resp, err := (&http.Client{Transport: config.GetTransport()}).Do(req)
	require.NoError(t, err)
	tail, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	elapsed := time.Since(started)
	t.Logf("The range ahead of the download was served in %v", elapsed)
	require.NoError(t, err)
	require.Equal(t, http.StatusPartialContent, resp.StatusCode)
	require.True(t, bytes.Equal(content[abandonedObjectSize-tailSize:], tail))
	requireTransferOK(t, resp)
	assert.Less(t, elapsed, 4*time.Second,
		"the range must not wait for the download, which needs about eight seconds to reach it")

	rest, err := io.ReadAll(whole.Body)
	require.NoError(t, err)
	require.True(t, bytes.Equal(content, append(head, rest...)))
	requireTransferOK(t, whole)
	requireCached(t, ctx, cacheURL, content)
}
