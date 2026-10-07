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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/fed_test_utils"
	local_cache "github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// partialObjectEnv is a federation whose origin holds a 1 MB object, and a
// cache that holds only the start of it.
type partialObjectEnv struct {
	ft   *fed_test_utils.FedTest
	pc   *local_cache.PersistentCache
	path string
	size int64
}

func newPartialObjectEnv(t *testing.T) *partialObjectEnv {
	t.Helper()
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	ft := fed_test_utils.NewFedTest(t, pubOriginCfg)
	fp, err := os.OpenFile(filepath.Join(ft.Exports[0].StoragePrefix, "partial.bin"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	require.NoError(t, err)
	size := test_utils.WriteBigBuffer(t, fp, 1)

	pc, err := local_cache.NewPersistentCache(ft.Ctx, ft.Egrp, local_cache.PersistentCacheConfig{BaseDir: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { pc.Close() })

	// A range read caches only the first part of the object.
	sr, _, err := pc.GetSeekableReader(context.Background(), "/test/partial.bin", "", true)
	require.NoError(t, err)
	_, err = io.ReadFull(sr, make([]byte, 8192))
	require.NoError(t, err)
	require.NoError(t, sr.Close())
	require.False(t, pc.IsFullyCached(ft.Ctx, "/test/partial.bin", ""))
	return &partialObjectEnv{ft: ft, pc: pc, path: "/test/partial.bin", size: int64(size)}
}

// TestGetOfAPartlyCachedObject checks that Get -- what the prestage worker
// reads through -- fetches the blocks of a partly cached object that are not
// on disk, rather than failing at the first one.
func TestGetOfAPartlyCachedObject(t *testing.T) {
	env := newPartialObjectEnv(t)
	r, err := env.pc.Get(env.ft.Ctx, env.path, "")
	require.NoError(t, err)
	n, err := io.Copy(io.Discard, r)
	require.NoError(t, r.Close())
	require.NoError(t, err, "Get of a partly cached object must fetch the rest")
	require.Equal(t, env.size, n)
	// The fill that fetched the rest marks the object complete once its
	// transfer reports, a moment after the last block is written.
	require.Eventually(t, func() bool { return env.pc.IsFullyCached(env.ft.Ctx, env.path, "") },
		10*time.Second, 20*time.Millisecond)
}

// TestPartlyCachedObjectIsNotCached checks that only-if-cached (served from
// StatCachedOnly) counts an object as cached only once it is whole: a partly
// cached one would fetch its missing blocks from the origin, which the client
// asked not to happen.
func TestPartlyCachedObjectIsNotCached(t *testing.T) {
	env := newPartialObjectEnv(t)
	_, err := env.pc.StatCachedOnly(env.path, "")
	require.ErrorIs(t, err, local_cache.ErrNotCached)

	r, err := env.pc.Get(env.ft.Ctx, env.path, "")
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, r)
	require.NoError(t, err)
	require.NoError(t, r.Close())
	require.Eventually(t, func() bool {
		size, err := env.pc.StatCachedOnly(env.path, "")
		return err == nil && int64(size) == env.size
	}, 10*time.Second, 50*time.Millisecond, "once whole, the object is cached")
}
