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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/utils"
)

// dirFileBytes sums the sizes of all regular files under dir, skipping the
// embedded BadgerDB metadata directory ("db") so the result reflects cached
// object bytes on disk, not database overhead.
func dirFileBytes(t testing.TB, dir string) int64 {
	t.Helper()
	var total int64
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// The cache may unlink files mid-walk during eviction; ignore.
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.IsDir() && info.Name() == "db" {
			return filepath.SkipDir
		}
		if info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	require.NoError(t, err)
	return total
}

// logCacheTree logs the immediate children of dir with their recursive byte
// totals, to make on-disk layout visible if an eviction assertion fails.
func logCacheTree(t testing.TB, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Logf("cache tree: cannot read %s: %v", dir, err)
		return
	}
	for _, e := range entries {
		child := filepath.Join(dir, e.Name())
		if e.IsDir() {
			t.Logf("cache tree: %s/ = %d bytes", child, dirFileBytes(t, child))
		} else if info, ierr := e.Info(); ierr == nil {
			t.Logf("cache tree: %s = %d bytes", child, info.Size())
		}
	}
}

// TestPersistentCache_LotEviction is the V2 counterpart to the V1 XRootD
// eviction e2e: with LotMan enabled on a real federation cache, it downloads
// well past the high watermark and proves the cache's watermark-driven eviction
// loop reclaims space back toward the low watermark. Because LotMan is enabled,
// eviction runs through the lot-aware planner (lot-usage sync + priority
// buckets, then the greediest-namespace fallback), so this exercises the full
// V2 pipeline end-to-end: download -> object/lot accounting -> eviction.
//
// Deterministic lot-priority ordering (over-quota/expired lots evicted first)
// and object-cap trimming are covered separately by the local_cache unit/
// integration tests (TestPriorityBuckets, TestTrimObjectCapsEvicts); the
// sibling TestPersistentCache_LotUsageTracked covers the lots usage API.
func TestPersistentCache_LotEviction(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	require.NoError(t, param.Cache_EnableV2.Set(true))
	require.NoError(t, param.Cache_EnableLotman.Set(true))
	require.NoError(t, param.Lotman_EnableAPI.Set(true))

	// Small absolute watermarks so a handful of small downloads exceed the high
	// watermark and trigger eviction (no need to fill gigabytes). The cache's
	// eviction loop checks every ~10s and evicts down to the low watermark.
	require.NoError(t, param.Cache_LowWatermark.Set("2m"))
	require.NoError(t, param.Cache_HighWaterMark.Set("4m"))
	// EnableLotman requires all three file-size directives; keep them below the
	// low watermark and base < nominal < max.
	require.NoError(t, param.Cache_FilesBaseSize.Set("256k"))
	require.NoError(t, param.Cache_FilesNominalSize.Set("512k"))
	require.NoError(t, param.Cache_FilesMaxSize.Set("1m"))
	// Push per-lot usage into the lot DB promptly so the lot-aware eviction
	// planner sees fresh usage on each pass.
	require.NoError(t, param.Cache_LotUsageReconcileInterval.Set(time.Second))

	lowWmBytes, err := utils.ParseBytes(param.Cache_LowWatermark.GetString())
	require.NoError(t, err)
	highWmBytes, err := utils.ParseBytes(param.Cache_HighWaterMark.GetString())
	require.NoError(t, err)

	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)
	require.NotNil(t, ft)

	// Cache enough objects under /test to blow well past the high watermark:
	// 16 x 512 KiB = 8 MiB downloaded, vs a 4 MiB high / 2 MiB low watermark.
	const (
		numObjects = 16
		objectSize = 512 * 1024 // 512 KiB
	)
	content := strings.Repeat("0123456789abcdef", objectSize/16) // exactly objectSize bytes
	require.Len(t, content, objectSize)

	localTmpDir := t.TempDir()
	storageToken := getTempTokenForTest(t)
	var downloadedBytes int64
	for i := 0; i < numObjects; i++ {
		localFile := filepath.Join(localTmpDir, fmt.Sprintf("evict_%02d.bin", i))
		require.NoError(t, os.WriteFile(localFile, []byte(content), 0644))

		objURL := fmt.Sprintf("pelican://%s:%d/test/evict_%02d.bin",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), i)
		_, err := client.DoPut(ft.Ctx, localFile, objURL, false, client.WithToken(storageToken))
		require.NoError(t, err)

		downloadFile := filepath.Join(localTmpDir, fmt.Sprintf("dl_%02d.bin", i))
		_, err = client.DoGet(ft.Ctx, objURL, downloadFile, false, client.WithToken(ft.Token))
		require.NoError(t, err)
		downloadedBytes += objectSize
	}

	// Sanity: we pushed more than the high watermark through the cache, so
	// eviction must engage for on-disk usage to settle below it.
	require.Greater(t, downloadedBytes, int64(highWmBytes),
		"test should download more than the high watermark to force eviction")

	// Cache object data lives under <Cache.StorageLocation>/persistent-cache
	// (BadgerDB metadata in the "db" subdir, which dirFileBytes skips).
	cacheDir := filepath.Join(param.Cache_StorageLocation.GetString(), "persistent-cache")
	require.DirExists(t, cacheDir, "persistent cache directory should exist")
	logCacheTree(t, cacheDir)

	// Without eviction all 8 MiB would remain on disk. The watermark loop caps
	// usage at the high watermark (evicting down to the low watermark whenever it
	// is exceeded), so on-disk object bytes must settle at no more than the high
	// watermark plus one object of overshoot between passes -- well below what we
	// downloaded. That gap is the proof that eviction reclaimed space.
	evictTarget := int64(highWmBytes) + objectSize
	var peak, last int64
	ok := assert.Eventually(t, func() bool {
		last = dirFileBytes(t, cacheDir)
		if last > peak {
			peak = last
		}
		return last <= evictTarget
	}, 180*time.Second, 2*time.Second)
	if !ok {
		logCacheTree(t, cacheDir)
	}
	require.True(t, ok,
		"on-disk cache usage should be capped at/below the high watermark by eviction; "+
			"downloaded %d, high watermark %d, target %d, peak %d, last %d",
		downloadedBytes, highWmBytes, evictTarget, peak, last)
	// Guard against a false pass from measuring the wrong location: we must have
	// actually observed object data on disk for the cap above to mean anything.
	require.Greater(t, peak, int64(objectSize),
		"expected to observe cached object data on disk (measurement sanity); peak %d", peak)
	require.Less(t, last, downloadedBytes,
		"on-disk usage (%d) must be less than total downloaded (%d) -- i.e. eviction occurred",
		last, downloadedBytes)

	t.Logf("eviction proven: downloaded %d bytes, peaked at %d on disk, settled at %d (high watermark %d, low watermark %d)",
		downloadedBytes, peak, last, highWmBytes, lowWmBytes)
}
