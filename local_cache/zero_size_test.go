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

package local_cache_test

import (
	"context"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestZeroSizedObjectCache tests that zero-byte objects are correctly handled
// by the persistent cache: stored, retrieved on miss, and retrieved on hit.
func TestZeroSizedObjectCache(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	ft := fed_test_utils.NewFedTest(t, pubOriginCfg)

	testCacheDir := t.TempDir()
	pc, err := local_cache.NewPersistentCache(ft.Ctx, ft.Egrp, local_cache.PersistentCacheConfig{
		BaseDir: testCacheDir,
	})
	require.NoError(t, err)
	defer pc.Close()

	// Create a zero-byte file on the origin
	originPath := filepath.Join(ft.Exports[0].StoragePrefix, "empty.txt")
	err = os.WriteFile(originPath, []byte{}, 0644)
	require.NoError(t, err)

	t.Run("GetMiss", func(t *testing.T) {
		reader, err := pc.Get(context.Background(), "/test/empty.txt", "")
		require.NoError(t, err, "cache GET on zero-byte object should succeed")
		byteBuff, err := io.ReadAll(reader)
		assert.NoError(t, err)
		assert.Equal(t, 0, len(byteBuff), "zero-byte object should return empty content")
		reader.Close()
	})

	t.Run("GetHit", func(t *testing.T) {
		reader, err := pc.Get(context.Background(), "/test/empty.txt", "")
		require.NoError(t, err, "cache GET (hit) on zero-byte object should succeed")
		byteBuff, err := io.ReadAll(reader)
		assert.NoError(t, err)
		assert.Equal(t, 0, len(byteBuff), "zero-byte object should return empty content on hit")
		reader.Close()
	})

	t.Run("Stat", func(t *testing.T) {
		size, err := pc.Stat("/test/empty.txt", "")
		require.NoError(t, err, "Stat on zero-byte object should succeed")
		assert.Equal(t, uint64(0), size, "Stat should report 0 bytes")
	})
}

// TestZeroSizedObjectDoGet tests that the transfer engine correctly handles
// zero-byte objects through the local cache using client.DoGet.
func TestZeroSizedObjectDoGet(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	ft := fed_test_utils.NewFedTest(t, pubOriginCfg)

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	te, err := client.NewTransferEngine(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		cancel()
		if err := egrp.Wait(); err != nil && err != context.Canceled {
			require.NoError(t, err)
		}
		if err := te.Shutdown(); err != nil {
			log.Errorln("Failure when shutting down transfer engine:", err)
		}
		server_utils.ResetTestState()
	})

	cacheUrl := &url.URL{
		Scheme: "unix",
		Path:   param.LocalCache_Socket.GetString(),
	}

	// Create a zero-byte file on the origin
	originPath := filepath.Join(ft.Exports[0].StoragePrefix, "empty.txt")
	err = os.WriteFile(originPath, []byte{}, 0644)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	downloadUrl := "pelican://" + param.Server_Hostname.GetString() + ":" +
		strconv.Itoa(param.Server_WebPort.GetInt()) + "/test/empty.txt"
	destPath := filepath.Join(tmpDir, "empty.txt")

	tr, err := client.DoGet(ctx, downloadUrl, destPath, false,
		client.WithCaches(cacheUrl))
	require.NoError(t, err, "DoGet failed for zero-byte object")
	require.Equal(t, 1, len(tr), "expected exactly 1 transfer result")
	assert.NoError(t, tr[0].Error, "transfer should succeed for zero-byte object")
	assert.Equal(t, int64(0), tr[0].TransferredBytes,
		"transferred bytes should be 0 for zero-byte object")

	// Verify the file was created (even though empty)
	info, err := os.Stat(destPath)
	require.NoError(t, err, "downloaded file should exist")
	assert.Equal(t, int64(0), info.Size(), "downloaded file should be empty")
}

// TestZeroSizedObjectAmongRegular tests that a mix of zero-byte and regular
// objects can coexist in the cache without issues.
func TestZeroSizedObjectAmongRegular(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	// Create zero-byte files in the origin directory before XRootD starts.
	// Files created at runtime trigger a Content-Length caching bug in the
	// XRootD POSIX backend, so all test files must exist at startup.
	ft := fed_test_utils.NewFedTest(t, pubOriginCfg, func(storageDir string) {
		require.NoError(t, os.WriteFile(filepath.Join(storageDir, "empty1.txt"), []byte{}, 0644))
		require.NoError(t, os.WriteFile(filepath.Join(storageDir, "empty2.txt"), []byte{}, 0644))
	})

	testCacheDir := t.TempDir()
	pc, err := local_cache.NewPersistentCache(ft.Ctx, ft.Egrp, local_cache.PersistentCacheConfig{
		BaseDir: testCacheDir,
	})
	require.NoError(t, err)
	defer pc.Close()

	// Download regular file first (pre-created by NewFedTest)
	reader, err := pc.Get(context.Background(), "/test/hello_world.txt", "")
	require.NoError(t, err)
	byteBuff, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, "Hello, World!", string(byteBuff))
	reader.Close()

	// Verify hello_world.txt is cached
	size, err := pc.StatCachedOnly("/test/hello_world.txt", "")
	require.NoError(t, err)
	assert.Equal(t, uint64(13), size)

	// Stat zero-byte files via HEAD (not GET) to avoid the XRootD
	// Content-Length caching bug that affects GET responses for
	// zero-byte files following a non-zero GET.
	size, err = pc.Stat("/test/empty1.txt", "")
	require.NoError(t, err)
	assert.Equal(t, uint64(0), size)

	size, err = pc.Stat("/test/empty2.txt", "")
	require.NoError(t, err)
	assert.Equal(t, uint64(0), size)

	// Confirm hello_world.txt is still accessible
	reader, err = pc.Get(context.Background(), "/test/hello_world.txt", "")
	require.NoError(t, err)
	byteBuff, err = io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, "Hello, World!", string(byteBuff))
	reader.Close()
}
