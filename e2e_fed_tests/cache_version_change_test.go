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
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestRangeFillRefusesAReplacedObject checks that a cached object filled by
// range reads is never assembled from two versions of the origin's file.
//
// A range read of an uncached object initializes it from a stat and fetches
// only the blocks it needs.  If the file is replaced at the origin before a
// later range read fetches more blocks, those blocks would belong to the new
// version while the cached ones belong to the old.  The cache must instead
// refuse the new version's bytes for the old object and drop it, so that the
// next read fetches the current version whole.
func TestRangeFillRefusesAReplacedObject(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	require.NoError(t, param.Cache_EnableV2.Set(true))
	ft := fed_test_utils.NewFedTest(t, slowOriginConfig("100MB/s"))
	token := getTempTokenForTest(t)

	const fileSize = 2 * 1024 * 1024
	original := writeOriginFile(t, ft, "versioned.bin", fileSize)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/versioned.bin", token)

	tail := fmt.Sprintf("bytes=%d-%d", 1536*1024, 1792*1024-1)
	head := fmt.Sprintf("bytes=0-%d", 256*1024-1)

	// A range from the middle caches part of the original.
	r := doRangeRead(ft.Ctx, cacheURL, "", "", tail)
	require.NoError(t, r.err)
	require.Equal(t, http.StatusPartialContent, r.statusCode)
	require.Equal(t, original[1536*1024:1792*1024], r.body)

	// A second range of the same version fills in more of it: the origin's
	// differing stat and GET entity tags must not get in the way.
	r = doRangeRead(ft.Ctx, cacheURL, "", "", fmt.Sprintf("bytes=%d-%d", 1024*1024, 1280*1024-1))
	require.NoError(t, r.err)
	require.Equal(t, http.StatusPartialContent, r.statusCode)
	require.Equal(t, original[1024*1024:1280*1024], r.body, "a fill of the same version must succeed")

	// The file is replaced at the origin by a different version.
	replacement := make([]byte, fileSize)
	for i := range replacement {
		replacement[i] = byte((i*7 + 3) % 253)
	}
	path := filepath.Join(ft.Exports[0].StoragePrefix, "versioned.bin")
	require.NoError(t, os.WriteFile(path, replacement, 0644))
	later := time.Now().Add(time.Hour)
	require.NoError(t, os.Chtimes(path, later, later))

	// A range the cache does not hold yet.  It may fail -- the cached
	// object can no longer be completed -- or be served from the new
	// version, but it must not be the new version's bytes spliced into the
	// old object.
	r = doRangeRead(ft.Ctx, cacheURL, "", "", head)
	if r.err == nil && r.statusCode == http.StatusPartialContent && r.transferStatus == "200: OK" {
		assert.Equal(t, replacement[:256*1024], r.body)
	}

	// Whatever happened, the cache must not now hold a mix: the range it
	// cached from the original is either still the original's with the
	// object never having taken the new bytes, or -- once the object has
	// been dropped and fetched again -- the replacement's.  What it must
	// never do is answer the head from the replacement and the tail from
	// the original.
	r2 := doRangeRead(ft.Ctx, cacheURL, "", "", head)
	r3 := doRangeRead(ft.Ctx, cacheURL, "", "", tail)
	require.NoError(t, r2.err)
	require.NoError(t, r3.err)
	headIsNew := string(r2.body) == string(replacement[:256*1024])
	tailIsNew := string(r3.body) == string(replacement[1536*1024:1792*1024])
	assert.Equal(t, headIsNew, tailIsNew,
		"the cache served the head of one version and the tail of another (head new: %v, tail new: %v)", headIsNew, tailIsNew)
	assert.True(t, headIsNew, "after the replaced object is dropped, the current version is served")
}
