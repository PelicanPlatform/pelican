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

package client

import (
	"context"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/server_structs"
)

func makeDirResp(namespace string) server_structs.DirectorResponse {
	return server_structs.DirectorResponse{
		XPelNsHdr: server_structs.XPelNs{
			Namespace: namespace,
		},
		ObjectServers: []*url.URL{{Host: namespace + ".example.com"}},
	}
}

func TestDirRespCacheLookup(t *testing.T) {
	cache := NewDirRespCache(5 * time.Minute)

	t.Run("Miss", func(t *testing.T) {
		_, ok := cache.Lookup("/no/such/path")
		assert.False(t, ok)
	})

	t.Run("ExactMatch", func(t *testing.T) {
		resp := makeDirResp("/test")
		cache.Store("/test", "", resp)

		got, ok := cache.Lookup("/test")
		require.True(t, ok)
		assert.Equal(t, "/test", got.XPelNsHdr.Namespace)
	})

	t.Run("PrefixMatch", func(t *testing.T) {
		resp := makeDirResp("/data/project")
		cache.Store("/data/project", "", resp)

		got, ok := cache.Lookup("/data/project/subdir/file.txt")
		require.True(t, ok)
		assert.Equal(t, "/data/project", got.XPelNsHdr.Namespace)
	})

	t.Run("LongestPrefixWins", func(t *testing.T) {
		cache.Store("/a", "", makeDirResp("/a"))
		cache.Store("/a/b", "", makeDirResp("/a/b"))
		cache.Store("/a/b/c", "", makeDirResp("/a/b/c"))

		got, ok := cache.Lookup("/a/b/c/d/e.txt")
		require.True(t, ok)
		assert.Equal(t, "/a/b/c", got.XPelNsHdr.Namespace,
			"should match the longest prefix")

		got, ok = cache.Lookup("/a/b/x.txt")
		require.True(t, ok)
		assert.Equal(t, "/a/b", got.XPelNsHdr.Namespace)

		got, ok = cache.Lookup("/a/x.txt")
		require.True(t, ok)
		assert.Equal(t, "/a", got.XPelNsHdr.Namespace)
	})

	t.Run("NoPartialSegmentMatch", func(t *testing.T) {
		cache2 := NewDirRespCache(5 * time.Minute)
		cache2.Store("/abc", "", makeDirResp("/abc"))

		// "/abcdef" should NOT match "/abc" because "abc" is not a path prefix of "abcdef"
		// (there's no "/" separator).  The lookup walks up path.Dir so:
		// /abcdef → / (no /abc match for /abcdef since path.Dir(/abcdef)=/ directly)
		_, ok := cache2.Lookup("/abcdef")
		assert.False(t, ok, "should not match partial segment")
	})

	t.Run("FoobarNotCoveredByFoo", func(t *testing.T) {
		cache2 := NewDirRespCache(5 * time.Minute)
		cache2.Store("/foo", "", makeDirResp("/foo"))

		// "/foobar" is a different path segment — it must NOT match "/foo".
		_, ok := cache2.Lookup("/foobar")
		assert.False(t, ok, "/foobar should not be covered by /foo")

		// "/foobar/baz" should also not match.
		_, ok = cache2.Lookup("/foobar/baz")
		assert.False(t, ok, "/foobar/baz should not be covered by /foo")

		// But "/foo/bar" SHOULD match (different segment under /foo).
		got, ok := cache2.Lookup("/foo/bar")
		assert.True(t, ok, "/foo/bar should be covered by /foo")
		assert.Equal(t, "/foo", got.XPelNsHdr.Namespace)
	})
}

func TestDirRespCacheExpiry(t *testing.T) {
	cache := NewDirRespCache(50 * time.Millisecond)
	cache.Store("/test", "", makeDirResp("/test"))

	// Should be present immediately
	_, ok := cache.Lookup("/test/file.txt")
	require.True(t, ok)

	// Wait for expiry
	time.Sleep(60 * time.Millisecond)

	_, ok = cache.Lookup("/test/file.txt")
	assert.False(t, ok, "entry should have expired")
}

func TestDirRespCacheInvalidate(t *testing.T) {
	cache := NewDirRespCache(5 * time.Minute)
	cache.Store("/test", "", makeDirResp("/test"))

	_, ok := cache.Lookup("/test/file.txt")
	require.True(t, ok)

	cache.Invalidate("/test")

	_, ok = cache.Lookup("/test/file.txt")
	assert.False(t, ok)
}

func TestDirRespCacheInvalidateAll(t *testing.T) {
	cache := NewDirRespCache(5 * time.Minute)
	cache.Store("/a", "", makeDirResp("/a"))
	cache.Store("/b", "", makeDirResp("/b"))

	assert.Equal(t, 2, cache.Len())

	cache.InvalidateAll()

	assert.Equal(t, 0, cache.Len())
	_, ok := cache.Lookup("/a/file")
	assert.False(t, ok)
}

func TestDirRespCacheCleanExpired(t *testing.T) {
	cache := NewDirRespCache(50 * time.Millisecond)
	cache.Store("/expired", "", makeDirResp("/expired"))

	time.Sleep(60 * time.Millisecond)

	cache.Store("/fresh", "", makeDirResp("/fresh"))
	assert.Equal(t, 2, cache.Len())

	cache.cleanExpired()
	assert.Equal(t, 1, cache.Len())

	_, ok := cache.Lookup("/fresh/file")
	assert.True(t, ok)
}

func TestDirRespCacheOverwrite(t *testing.T) {
	cache := NewDirRespCache(5 * time.Minute)

	resp1 := makeDirResp("/test")
	resp2 := makeDirResp("/test-updated")
	resp2.XPelNsHdr.Namespace = "/test" // same namespace

	cache.Store("/test", "", resp1)
	cache.Store("/test", "", resp2)

	got, ok := cache.Lookup("/test/file")
	require.True(t, ok)
	assert.Equal(t, resp2.ObjectServers[0].Host, got.ObjectServers[0].Host,
		"later store should overwrite earlier")
}

func TestMatchesPrefix(t *testing.T) {
	tests := []struct {
		path, prefix string
		want         bool
	}{
		{"/a/b/c", "/a/b", true},
		{"/a/b/c", "/a/b/c", true},
		{"/a/b/c", "/a", true},
		{"/a/b/c", "/", true},
		{"/abc", "/ab", false},     // partial segment
		{"/foobar", "/foo", false}, // path-prefix, not string-prefix
		{"/foo/bar", "/foo", true},  // proper child segment
		{"/a", "/a/b", false},       // prefix longer than path
		{"/x/y", "/a/b", false},
	}
	for _, tc := range tests {
		t.Run(tc.path+"_"+tc.prefix, func(t *testing.T) {
			assert.Equal(t, tc.want, matchesPrefix(tc.path, tc.prefix))
		})
	}
}

// --- LookupOrLoad tests ---

func TestLookupOrLoadCacheHit(t *testing.T) {
	cache := NewDirRespCache(5 * time.Minute)
	resp := makeDirResp("/data")
	cache.Store("/data", "", resp)

	var loaderCalled atomic.Int32
	got, err := cache.LookupOrLoad(context.Background(), "/data/file.txt", func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
		loaderCalled.Add(1)
		return server_structs.DirectorResponse{}, "", nil
	})
	require.NoError(t, err)
	assert.Equal(t, resp.ObjectServers[0].Host, got.ObjectServers[0].Host)
	assert.Equal(t, int32(0), loaderCalled.Load(), "loader should not be called on cache hit")
}

func TestLookupOrLoadCacheMiss(t *testing.T) {
	cache := NewDirRespCache(5 * time.Minute)
	resp := makeDirResp("/data")

	got, err := cache.LookupOrLoad(context.Background(), "/data/subdir/file.txt", func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
		return resp, "/data", nil
	})
	require.NoError(t, err)
	assert.Equal(t, resp.ObjectServers[0].Host, got.ObjectServers[0].Host)

	// The result should now be cached.
	cached, ok := cache.Lookup("/data/other.txt")
	require.True(t, ok)
	assert.Equal(t, resp.ObjectServers[0].Host, cached.ObjectServers[0].Host)
}

func TestLookupOrLoadCoalesces(t *testing.T) {
	cache := NewDirRespCache(5 * time.Minute)
	resp := makeDirResp("/ns")

	var loaderCalls atomic.Int32
	// Gate so all goroutines start waiting before the loader returns.
	gate := make(chan struct{})

	const numWaiters = 10
	var wg sync.WaitGroup
	wg.Add(numWaiters)

	var results [numWaiters]server_structs.DirectorResponse
	var errs [numWaiters]error

	for i := 0; i < numWaiters; i++ {
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = cache.LookupOrLoad(context.Background(), "/ns/file.txt", func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
				loaderCalls.Add(1)
				<-gate // wait for the gate to open
				return resp, "/ns", nil
			})
		}(i)
	}

	// Give goroutines time to enter LookupOrLoad.
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()

	assert.Equal(t, int32(1), loaderCalls.Load(), "loader should be called exactly once")
	for i := 0; i < numWaiters; i++ {
		require.NoError(t, errs[i], "waiter %d", i)
		assert.Equal(t, resp.ObjectServers[0].Host, results[i].ObjectServers[0].Host)
	}
}

func TestLookupOrLoadContextCancel(t *testing.T) {
	cache := NewDirRespCache(5 * time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	loaderStarted := make(chan struct{})

	go func() {
		// Start a load that blocks for a long time.
		_, _ = cache.LookupOrLoad(context.Background(), "/slow/file.txt", func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
			close(loaderStarted)
			time.Sleep(5 * time.Second)
			return makeDirResp("/slow"), "/slow", nil
		})
	}()

	// Wait for the loader to start, then try a second caller with a cancelled context.
	<-loaderStarted
	cancel()
	_, err := cache.LookupOrLoad(ctx, "/slow/file.txt", func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
		t.Fatal("loader should not be called for second waiter")
		return server_structs.DirectorResponse{}, "", nil
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestLookupOrLoadNoPartialSegment(t *testing.T) {
	cache := NewDirRespCache(5 * time.Minute)
	cache.Store("/foo", "", makeDirResp("/foo"))

	var loaderCalled atomic.Int32
	resp := makeDirResp("/foobar")

	// LookupOrLoad for /foobar/file.txt should NOT match /foo and must invoke the loader.
	got, err := cache.LookupOrLoad(context.Background(), "/foobar/file.txt", func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
		loaderCalled.Add(1)
		return resp, "/foobar", nil
	})
	require.NoError(t, err)
	assert.Equal(t, int32(1), loaderCalled.Load(), "loader must be called because /foo does not cover /foobar")
	assert.Equal(t, "/foobar", got.XPelNsHdr.Namespace)

	// Verify /foo/bar/file.txt still hits the /foo cache entry without calling the loader.
	var loaderCalled2 atomic.Int32
	got2, err := cache.LookupOrLoad(context.Background(), "/foo/bar/file.txt", func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
		loaderCalled2.Add(1)
		return server_structs.DirectorResponse{}, "", nil
	})
	require.NoError(t, err)
	assert.Equal(t, int32(0), loaderCalled2.Load(), "loader should not be called for /foo/bar")
	assert.Equal(t, "/foo", got2.XPelNsHdr.Namespace)
}

func TestLookupOrLoadLoaderError(t *testing.T) {
	cache := NewDirRespCache(5 * time.Minute)
	expectedErr := assert.AnError

	_, err := cache.LookupOrLoad(context.Background(), "/fail/file.txt", func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
		return server_structs.DirectorResponse{}, "", expectedErr
	})
	require.ErrorIs(t, err, expectedErr)

	// Nothing should be cached on error.
	_, ok := cache.Lookup("/fail/file.txt")
	assert.False(t, ok)
	assert.Equal(t, 0, cache.Len())
}

// This test tackles a regression that occurred when the director response caching was first implemented
// in the transfer engine.  It would cache the exact response for an object and on reuse, the original object's
// URL would be used instead of the new object.
func TestDirRespCacheStripsFederationPath(t *testing.T) {
	t.Run("StoreStripsAndLookupReconstitutes", func(t *testing.T) {
		cache := NewDirRespCache(5 * time.Minute)
		resp := server_structs.DirectorResponse{
			XPelNsHdr: server_structs.XPelNs{Namespace: "/test"},
			ObjectServers: []*url.URL{
				{Scheme: "https", Host: "origin.example.com", Path: "/api/v1.0/origin/data/test/file1.bin"},
				{Scheme: "https", Host: "cache.example.com", Path: "/test/file1.bin"},
			},
		}

		cache.Store("/test", "/test/file1.bin", resp)

		// Looking up with the SAME file should return original full paths.
		got, ok := cache.Lookup("/test/file1.bin")
		require.True(t, ok)
		assert.Equal(t, "/api/v1.0/origin/data/test/file1.bin", got.ObjectServers[0].Path)
		assert.Equal(t, "/test/file1.bin", got.ObjectServers[1].Path)

		// Looking up with a DIFFERENT file should return reconstituted paths
		// with the new file's federation path.
		got2, ok := cache.Lookup("/test/file2.bin")
		require.True(t, ok)
		assert.Equal(t, "/api/v1.0/origin/data/test/file2.bin", got2.ObjectServers[0].Path)
		assert.Equal(t, "/test/file2.bin", got2.ObjectServers[1].Path)

		// Original response should NOT be mutated.
		assert.Equal(t, "/api/v1.0/origin/data/test/file1.bin", resp.ObjectServers[0].Path)
		assert.Equal(t, "/test/file1.bin", resp.ObjectServers[1].Path)
	})

	t.Run("LookupOrLoadReconstitutes", func(t *testing.T) {
		cache := NewDirRespCache(5 * time.Minute)
		resp := server_structs.DirectorResponse{
			XPelNsHdr: server_structs.XPelNs{Namespace: "/ns"},
			ObjectServers: []*url.URL{
				{Scheme: "https", Host: "origin.example.com", Path: "/prefix/ns/obj1.bin"},
			},
		}

		got, err := cache.LookupOrLoad(context.Background(), "/ns/obj1.bin", func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
			return resp, "/ns", nil
		})
		require.NoError(t, err)

		// Returned response should have full reconstituted path.
		require.Len(t, got.ObjectServers, 1)
		assert.Equal(t, "/prefix/ns/obj1.bin", got.ObjectServers[0].Path)

		// Subsequent lookup for a different file should return reconstituted
		// paths with the new file's federation path.
		cached, ok := cache.Lookup("/ns/obj2.bin")
		require.True(t, ok)
		assert.Equal(t, "/prefix/ns/obj2.bin", cached.ObjectServers[0].Path)
	})

	t.Run("EmptyObjectPathNoOp", func(t *testing.T) {
		cache := NewDirRespCache(5 * time.Minute)
		resp := server_structs.DirectorResponse{
			XPelNsHdr: server_structs.XPelNs{Namespace: "/test"},
			ObjectServers: []*url.URL{
				{Scheme: "https", Host: "origin.example.com", Path: "/some/path"},
			},
		}

		cache.Store("/test", "", resp)
		got, ok := cache.Lookup("/test/file.txt")
		require.True(t, ok)
		// With empty objectPath, nothing was stripped, so reconstitution
		// appends the lookup path to the stored path.
		assert.Equal(t, "/some/path/test/file.txt", got.ObjectServers[0].Path)
	})
}
