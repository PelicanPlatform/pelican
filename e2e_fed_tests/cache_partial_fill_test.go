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
	"mime"
	"mime/multipart"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// These tests cover how a partly cached object is completed: by background
// fills -- one origin request per gap -- rather than one origin request per
// read of the client's.

const partialFillObjectSize = 4 * 1024 * 1024

func startPartialFillFed(t *testing.T, originRate string) (*fed_test_utils.FedTest, string) {
	t.Helper()
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	require.NoError(t, param.Cache_EnableV2.Set(true))
	ft := fed_test_utils.NewFedTest(t, slowOriginConfig(originRate))
	return ft, getTempTokenForTest(t)
}

// cacheStart caches only the first 64 KB of an object: a range read of an
// object the cache has not seen fetches just that range.
func cacheStart(t *testing.T, ctx context.Context, url string) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)
	req.Header.Set("Range", "bytes=0-65535")
	resp, err := (&http.Client{Transport: config.GetTransport()}).Do(req)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusPartialContent, resp.StatusCode)
}

// TestPartlyCachedObjectsFillConcurrently: more readers of partly cached
// objects than there are prefetch slots each complete their object with one
// origin request, not one per read.
func TestPartlyCachedObjectsFillConcurrently(t *testing.T) {
	// Slow enough that every fill is still running when the last starts.
	ft, token := startPartialFillFed(t, "8MB/s")
	ctx, cancel := context.WithTimeout(ft.Ctx, 2*time.Minute)
	defer cancel()

	const objects = 8
	contents := make([][]byte, objects)
	urls := make([]string, objects)
	for i := range objects {
		name := fmt.Sprintf("partial_%d.bin", i)
		contents[i] = writeOriginFile(t, ft, name, partialFillObjectSize)
		urls[i] = waitForCacheRedirectURL(t, ft, "/test/"+name, token)
		cacheStart(t, ctx, urls[i])
	}

	opens := originOpens(t)
	var wg sync.WaitGroup
	for i := range objects {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := cacheGet(t, ctx, urls[i])
			defer resp.Body.Close()
			got, err := io.ReadAll(resp.Body)
			assert.NoError(t, err)
			assert.True(t, bytes.Equal(contents[i], got), "object %d", i)
		}()
	}
	wg.Wait()
	t.Logf("completing %d partly cached objects took %v origin requests", objects, originOpens(t)-opens)
	assert.LessOrEqual(t, originOpens(t)-opens, float64(2*objects),
		"each object must be completed by a fill, not one request per read")
}

// TestPartlyCachedObjectFillsEachRangeOfAMultiRangeRead: a multi-range
// request -- what ROOT and davix send for a vector read -- fills each range
// with one request, not one per read.
func TestPartlyCachedObjectFillsEachRangeOfAMultiRangeRead(t *testing.T) {
	ft, token := startPartialFillFed(t, "16MB/s")
	ctx, cancel := context.WithTimeout(ft.Ctx, 2*time.Minute)
	defer cancel()
	content := writeOriginFile(t, ft, "multirange.bin", partialFillObjectSize)
	url := waitForCacheRedirectURL(t, ft, "/test/multirange.bin", token)
	cacheStart(t, ctx, url)

	type span struct{ start, end int }
	spans := []span{{1 << 20, 2<<20 - 1}, {3 << 20, 3<<20 + 512<<10 - 1}}
	opens := originOpens(t)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d,%d-%d", spans[0].start, spans[0].end, spans[1].start, spans[1].end))
	resp, err := (&http.Client{Transport: config.GetTransport()}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusPartialContent, resp.StatusCode)
	_, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	require.NoError(t, err)
	parts := multipart.NewReader(resp.Body, params["boundary"])
	for _, s := range spans {
		part, err := parts.NextPart()
		require.NoError(t, err)
		got, err := io.ReadAll(part)
		require.NoError(t, err)
		require.True(t, bytes.Equal(content[s.start:s.end+1], got))
	}
	t.Logf("the multi-range read took %v origin requests", originOpens(t)-opens)
	assert.LessOrEqual(t, originOpens(t)-opens, float64(2*len(spans)),
		"each range must be filled by one request, not one per read")
}

// TestPartlyCachedObjectFillsAllOfAFailedIfRangeRead: when a range request's
// If-Range precondition fails, the whole object is sent, and the whole
// object is filled with one request, not the requested range with one and
// the rest one read at a time.
func TestPartlyCachedObjectFillsAllOfAFailedIfRangeRead(t *testing.T) {
	ft, token := startPartialFillFed(t, "16MB/s")
	ctx, cancel := context.WithTimeout(ft.Ctx, 2*time.Minute)
	defer cancel()
	content := writeOriginFile(t, ft, "ifrange.bin", partialFillObjectSize)
	url := waitForCacheRedirectURL(t, ft, "/test/ifrange.bin", token)
	cacheStart(t, ctx, url)

	opens := originOpens(t)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)
	req.Header.Set("Range", "bytes=1048576-1049599")
	req.Header.Set("If-Range", `"some-other-version"`)
	resp, err := (&http.Client{Transport: config.GetTransport()}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "a failed If-Range gets the whole object")
	got, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.True(t, bytes.Equal(content, got))
	t.Logf("the read took %v origin requests", originOpens(t)-opens)
	assert.LessOrEqual(t, originOpens(t)-opens, 2.0, "the object must be filled by one request, not one per read")
}
