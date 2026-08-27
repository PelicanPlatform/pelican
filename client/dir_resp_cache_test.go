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
	"net/http"
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

// testFederation stands in for the discovery endpoint every entry in these
// tests was learned from; cross-federation behavior is covered separately.
const testFederation = "https://fed.example.com"

// testFlavor is the ordinary read flavor: a plain GET, routed to caches,
// with no query.  Tests that care about flavor isolation build their own.
var testFlavor = NewDirRespFlavor(http.MethodGet, false, "")

func TestDirRespCacheLookup(t *testing.T) {
	cache := NewDirRespCache(5 * time.Minute)

	t.Run("Miss", func(t *testing.T) {
		_, ok := cache.Lookup(testFederation, testFlavor, "/no/such/path")
		assert.False(t, ok)
	})

	t.Run("ExactMatch", func(t *testing.T) {
		resp := makeDirResp("/test")
		cache.Store(testFederation, testFlavor, "/test", "", resp)

		got, ok := cache.Lookup(testFederation, testFlavor, "/test")
		require.True(t, ok)
		assert.Equal(t, "/test", got.XPelNsHdr.Namespace)
	})

	t.Run("PrefixMatch", func(t *testing.T) {
		resp := makeDirResp("/data/project")
		cache.Store(testFederation, testFlavor, "/data/project", "", resp)

		got, ok := cache.Lookup(testFederation, testFlavor, "/data/project/subdir/file.txt")
		require.True(t, ok)
		assert.Equal(t, "/data/project", got.XPelNsHdr.Namespace)
	})

	t.Run("LongestPrefixWins", func(t *testing.T) {
		cache.Store(testFederation, testFlavor, "/a", "", makeDirResp("/a"))
		cache.Store(testFederation, testFlavor, "/a/b", "", makeDirResp("/a/b"))
		cache.Store(testFederation, testFlavor, "/a/b/c", "", makeDirResp("/a/b/c"))

		got, ok := cache.Lookup(testFederation, testFlavor, "/a/b/c/d/e.txt")
		require.True(t, ok)
		assert.Equal(t, "/a/b/c", got.XPelNsHdr.Namespace,
			"should match the longest prefix")

		got, ok = cache.Lookup(testFederation, testFlavor, "/a/b/x.txt")
		require.True(t, ok)
		assert.Equal(t, "/a/b", got.XPelNsHdr.Namespace)

		got, ok = cache.Lookup(testFederation, testFlavor, "/a/x.txt")
		require.True(t, ok)
		assert.Equal(t, "/a", got.XPelNsHdr.Namespace)
	})

	t.Run("NoPartialSegmentMatch", func(t *testing.T) {
		cache2 := NewDirRespCache(5 * time.Minute)
		cache2.Store(testFederation, testFlavor, "/abc", "", makeDirResp("/abc"))

		// "/abcdef" should NOT match "/abc" because "abc" is not a path prefix of "abcdef"
		// (there's no "/" separator).  The lookup walks up path.Dir so:
		// /abcdef → / (no /abc match for /abcdef since path.Dir(/abcdef)=/ directly)
		_, ok := cache2.Lookup(testFederation, testFlavor, "/abcdef")
		assert.False(t, ok, "should not match partial segment")
	})

	t.Run("FoobarNotCoveredByFoo", func(t *testing.T) {
		cache2 := NewDirRespCache(5 * time.Minute)
		cache2.Store(testFederation, testFlavor, "/foo", "", makeDirResp("/foo"))

		// "/foobar" is a different path segment — it must NOT match "/foo".
		_, ok := cache2.Lookup(testFederation, testFlavor, "/foobar")
		assert.False(t, ok, "/foobar should not be covered by /foo")

		// "/foobar/baz" should also not match.
		_, ok = cache2.Lookup(testFederation, testFlavor, "/foobar/baz")
		assert.False(t, ok, "/foobar/baz should not be covered by /foo")

		// But "/foo/bar" SHOULD match (different segment under /foo).
		got, ok := cache2.Lookup(testFederation, testFlavor, "/foo/bar")
		assert.True(t, ok, "/foo/bar should be covered by /foo")
		assert.Equal(t, "/foo", got.XPelNsHdr.Namespace)
	})
}

func TestDirRespCacheExpiry(t *testing.T) {
	cache := NewDirRespCache(50 * time.Millisecond)
	cache.Store(testFederation, testFlavor, "/test", "", makeDirResp("/test"))

	// Should be present immediately
	_, ok := cache.Lookup(testFederation, testFlavor, "/test/file.txt")
	require.True(t, ok)

	// Wait for expiry
	time.Sleep(60 * time.Millisecond)

	_, ok = cache.Lookup(testFederation, testFlavor, "/test/file.txt")
	assert.False(t, ok, "entry should have expired")
}

func TestDirRespCacheInvalidate(t *testing.T) {
	cache := NewDirRespCache(5 * time.Minute)
	cache.Store(testFederation, testFlavor, "/test", "", makeDirResp("/test"))

	_, ok := cache.Lookup(testFederation, testFlavor, "/test/file.txt")
	require.True(t, ok)

	cache.Invalidate(testFederation, testFlavor, "/test")

	_, ok = cache.Lookup(testFederation, testFlavor, "/test/file.txt")
	assert.False(t, ok)
}

func TestDirRespCacheInvalidateAll(t *testing.T) {
	cache := NewDirRespCache(5 * time.Minute)
	cache.Store(testFederation, testFlavor, "/a", "", makeDirResp("/a"))
	cache.Store(testFederation, testFlavor, "/b", "", makeDirResp("/b"))

	assert.Equal(t, 2, cache.Len())

	cache.InvalidateAll()

	assert.Equal(t, 0, cache.Len())
	_, ok := cache.Lookup(testFederation, testFlavor, "/a/file")
	assert.False(t, ok)
}

func TestDirRespCacheCleanExpired(t *testing.T) {
	cache := NewDirRespCache(50 * time.Millisecond)
	cache.Store(testFederation, testFlavor, "/expired", "", makeDirResp("/expired"))

	time.Sleep(60 * time.Millisecond)

	cache.Store(testFederation, testFlavor, "/fresh", "", makeDirResp("/fresh"))
	assert.Equal(t, 2, cache.Len())

	cache.cleanExpired()
	assert.Equal(t, 1, cache.Len())

	_, ok := cache.Lookup(testFederation, testFlavor, "/fresh/file")
	assert.True(t, ok)
}

func TestDirRespCacheOverwrite(t *testing.T) {
	cache := NewDirRespCache(5 * time.Minute)

	resp1 := makeDirResp("/test")
	resp2 := makeDirResp("/test-updated")
	resp2.XPelNsHdr.Namespace = "/test" // same namespace

	cache.Store(testFederation, testFlavor, "/test", "", resp1)
	cache.Store(testFederation, testFlavor, "/test", "", resp2)

	got, ok := cache.Lookup(testFederation, testFlavor, "/test/file")
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
		{"/foo/bar", "/foo", true}, // proper child segment
		{"/a", "/a/b", false},      // prefix longer than path
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
	cache.Store(testFederation, testFlavor, "/data", "", resp)

	var loaderCalled atomic.Int32
	got, err := cache.LookupOrLoad(context.Background(), testFederation, testFlavor, "/data/file.txt", func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
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

	got, err := cache.LookupOrLoad(context.Background(), testFederation, testFlavor, "/data/subdir/file.txt", func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
		return resp, "/data", nil
	})
	require.NoError(t, err)
	assert.Equal(t, resp.ObjectServers[0].Host, got.ObjectServers[0].Host)

	// The result should now be cached.
	cached, ok := cache.Lookup(testFederation, testFlavor, "/data/other.txt")
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
			results[idx], errs[idx] = cache.LookupOrLoad(context.Background(), testFederation, testFlavor, "/ns/file.txt", func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
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
		_, _ = cache.LookupOrLoad(context.Background(), testFederation, testFlavor, "/slow/file.txt", func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
			close(loaderStarted)
			time.Sleep(5 * time.Second)
			return makeDirResp("/slow"), "/slow", nil
		})
	}()

	// Wait for the loader to start, then try a second caller with a cancelled context.
	<-loaderStarted
	cancel()
	_, err := cache.LookupOrLoad(ctx, testFederation, testFlavor, "/slow/file.txt", func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
		t.Fatal("loader should not be called for second waiter")
		return server_structs.DirectorResponse{}, "", nil
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestLookupOrLoadNoPartialSegment(t *testing.T) {
	cache := NewDirRespCache(5 * time.Minute)
	cache.Store(testFederation, testFlavor, "/foo", "", makeDirResp("/foo"))

	var loaderCalled atomic.Int32
	resp := makeDirResp("/foobar")

	// LookupOrLoad for /foobar/file.txt should NOT match /foo and must invoke the loader.
	got, err := cache.LookupOrLoad(context.Background(), testFederation, testFlavor, "/foobar/file.txt", func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
		loaderCalled.Add(1)
		return resp, "/foobar", nil
	})
	require.NoError(t, err)
	assert.Equal(t, int32(1), loaderCalled.Load(), "loader must be called because /foo does not cover /foobar")
	assert.Equal(t, "/foobar", got.XPelNsHdr.Namespace)

	// Verify /foo/bar/file.txt still hits the /foo cache entry without calling the loader.
	var loaderCalled2 atomic.Int32
	got2, err := cache.LookupOrLoad(context.Background(), testFederation, testFlavor, "/foo/bar/file.txt", func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
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

	_, err := cache.LookupOrLoad(context.Background(), testFederation, testFlavor, "/fail/file.txt", func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
		return server_structs.DirectorResponse{}, "", expectedErr
	})
	require.ErrorIs(t, err, expectedErr)

	// Nothing should be cached on error.
	_, ok := cache.Lookup(testFederation, testFlavor, "/fail/file.txt")
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

		cache.Store(testFederation, testFlavor, "/test", "/test/file1.bin", resp)

		// Looking up with the SAME file should return original full paths.
		got, ok := cache.Lookup(testFederation, testFlavor, "/test/file1.bin")
		require.True(t, ok)
		assert.Equal(t, "/api/v1.0/origin/data/test/file1.bin", got.ObjectServers[0].Path)
		assert.Equal(t, "/test/file1.bin", got.ObjectServers[1].Path)

		// Looking up with a DIFFERENT file should return reconstituted paths
		// with the new file's federation path.
		got2, ok := cache.Lookup(testFederation, testFlavor, "/test/file2.bin")
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

		got, err := cache.LookupOrLoad(context.Background(), testFederation, testFlavor, "/ns/obj1.bin", func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
			return resp, "/ns", nil
		})
		require.NoError(t, err)

		// Returned response should have full reconstituted path.
		require.Len(t, got.ObjectServers, 1)
		assert.Equal(t, "/prefix/ns/obj1.bin", got.ObjectServers[0].Path)

		// Subsequent lookup for a different file should return reconstituted
		// paths with the new file's federation path.
		cached, ok := cache.Lookup(testFederation, testFlavor, "/ns/obj2.bin")
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

		cache.Store(testFederation, testFlavor, "/test", "", resp)
		got, ok := cache.Lookup(testFederation, testFlavor, "/test/file.txt")
		require.True(t, ok)
		// With empty objectPath, nothing was stripped, so reconstitution
		// appends the lookup path to the stored path.
		assert.Equal(t, "/some/path/test/file.txt", got.ObjectServers[0].Path)
	})
}

// TestDirRespCacheIsolatesFederations pins the scoping that keeps one
// federation's answer from being handed to another.  A TransferEngine is shared
// process-wide and namespace paths are not globally unique, so two federations
// presenting the same path is ordinary, not adversarial -- but answering the
// second with the first's object servers would send its credentials to a host
// the user never named.
func TestDirRespCacheIsolatesFederations(t *testing.T) {
	const otherFederation = "https://other-fed.example.com"

	t.Run("LookupDoesNotCrossFederations", func(t *testing.T) {
		cache := NewDirRespCache(5 * time.Minute)
		cache.Store(testFederation, testFlavor, "/shared", "", makeDirResp("/shared"))

		_, ok := cache.Lookup(otherFederation, testFlavor, "/shared/object.txt")
		assert.False(t, ok, "an entry learned from one federation must not answer for another")

		got, ok := cache.Lookup(testFederation, testFlavor, "/shared/object.txt")
		require.True(t, ok, "the federation that stored the entry still gets it")
		assert.Equal(t, "/shared", got.XPelNsHdr.Namespace)
	})

	t.Run("SamePathInTwoFederationsKeepsBothEntries", func(t *testing.T) {
		cache := NewDirRespCache(5 * time.Minute)
		mine := makeDirResp("/shared")
		theirs := makeDirResp("/shared")
		theirs.ObjectServers = []*url.URL{{Host: "cache.other-fed.example.com"}}

		cache.Store(testFederation, testFlavor, "/shared", "", mine)
		cache.Store(otherFederation, testFlavor, "/shared", "", theirs)

		got, ok := cache.Lookup(testFederation, testFlavor, "/shared/object.txt")
		require.True(t, ok)
		require.Len(t, got.ObjectServers, 1)
		assert.Equal(t, "/shared.example.com", got.ObjectServers[0].Host,
			"storing another federation's entry must not overwrite this one")

		got, ok = cache.Lookup(otherFederation, testFlavor, "/shared/object.txt")
		require.True(t, ok)
		require.Len(t, got.ObjectServers, 1)
		assert.Equal(t, "cache.other-fed.example.com", got.ObjectServers[0].Host)
	})

	t.Run("LoadsAreNotCoalescedAcrossFederations", func(t *testing.T) {
		cache := NewDirRespCache(5 * time.Minute)
		var calls int32
		loader := func(namespace string) DirRespLoader {
			return func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
				atomic.AddInt32(&calls, 1)
				return makeDirResp(namespace), namespace, nil
			}
		}

		_, err := cache.LookupOrLoad(context.Background(), testFederation, testFlavor, "/shared/object.txt", loader("/shared"))
		require.NoError(t, err)
		_, err = cache.LookupOrLoad(context.Background(), otherFederation, testFlavor, "/shared/object.txt", loader("/shared"))
		require.NoError(t, err)

		assert.Equal(t, int32(2), atomic.LoadInt32(&calls),
			"each federation must be asked its own question")
	})

	t.Run("UnattributableEntriesAreNotCached", func(t *testing.T) {
		cache := NewDirRespCache(5 * time.Minute)
		cache.Store("", testFlavor, "/shared", "", makeDirResp("/shared"))
		assert.Equal(t, 0, cache.Len(), "an entry with no federation could answer for any of them")

		_, ok := cache.Lookup("", testFlavor, "/shared/object.txt")
		assert.False(t, ok)
	})
}

// A director response answers exactly one question.  These tests pin the
// separations that keep one flavor's answer from being served to another:
// a writer must never be handed the caches a read was told to use (that
// both addresses the write to servers that reject it and discloses the
// write credential to every one of them), and a ?directread read must not
// be served the cache-routed answer it was explicitly avoiding.
func TestDirRespCacheFlavorIsolation(t *testing.T) {
	readFlavor := NewDirRespFlavor(http.MethodGet, false, "")
	writeFlavor := NewDirRespFlavor(http.MethodPut, false, "")
	directReadFlavor := NewDirRespFlavor(http.MethodGet, false, "directread")
	cacheModeFlavor := NewDirRespFlavor(http.MethodGet, true, "")

	t.Run("WriteDoesNotSeeReadEntry", func(t *testing.T) {
		cache := NewDirRespCache(5 * time.Minute)
		cache.Store(testFederation, readFlavor, "/ns", "", makeDirResp("/ns"))

		_, ok := cache.Lookup(testFederation, writeFlavor, "/ns/file.txt")
		assert.False(t, ok, "an upload must not be answered with a download's object servers")

		_, ok = cache.Lookup(testFederation, readFlavor, "/ns/file.txt")
		assert.True(t, ok, "the read entry itself still answers reads")
	})

	t.Run("ReadDoesNotSeeWriteEntry", func(t *testing.T) {
		cache := NewDirRespCache(5 * time.Minute)
		cache.Store(testFederation, writeFlavor, "/ns", "", makeDirResp("/ns"))

		_, ok := cache.Lookup(testFederation, readFlavor, "/ns/file.txt")
		assert.False(t, ok, "a download must not be answered with an upload's origins")
	})

	t.Run("DirectReadIsItsOwnFlavor", func(t *testing.T) {
		cache := NewDirRespCache(5 * time.Minute)
		cache.Store(testFederation, readFlavor, "/ns", "", makeDirResp("/ns"))

		_, ok := cache.Lookup(testFederation, directReadFlavor, "/ns/lease.json")
		assert.False(t, ok, "?directread asks for origins and must not get the cache-routed answer")
	})

	t.Run("CacheModeIsItsOwnFlavor", func(t *testing.T) {
		cache := NewDirRespCache(5 * time.Minute)
		cache.Store(testFederation, readFlavor, "/ns", "", makeDirResp("/ns"))

		_, ok := cache.Lookup(testFederation, cacheModeFlavor, "/ns/file.txt")
		assert.False(t, ok, "cache-mode routing queries a different director endpoint")
	})

	t.Run("QueryOrderDoesNotSplitEntries", func(t *testing.T) {
		cache := NewDirRespCache(5 * time.Minute)
		stored := NewDirRespFlavor(http.MethodGet, false, "directread&pack=auto")
		cache.Store(testFederation, stored, "/ns", "", makeDirResp("/ns"))

		reordered := NewDirRespFlavor(http.MethodGet, false, "pack=auto&directread")
		_, ok := cache.Lookup(testFederation, reordered, "/ns/file.txt")
		assert.True(t, ok, "the same parameters in another order are the same question")
	})
}

// Concurrent misses are coalesced per flavor: a reader and a writer racing
// on one path must each get their own director query, not share one answer.
func TestDirRespCacheSingleflightIsPerFlavor(t *testing.T) {
	cache := NewDirRespCache(5 * time.Minute)
	readFlavor := NewDirRespFlavor(http.MethodGet, false, "")
	writeFlavor := NewDirRespFlavor(http.MethodPut, false, "")

	release := make(chan struct{})
	var readCalls, writeCalls atomic.Int32

	loader := func(counter *atomic.Int32, host string) DirRespLoader {
		return func(ctx context.Context) (server_structs.DirectorResponse, string, error) {
			counter.Add(1)
			<-release // hold both in flight at once
			return server_structs.DirectorResponse{
				XPelNsHdr:     server_structs.XPelNs{Namespace: "/ns"},
				ObjectServers: []*url.URL{{Host: host}},
			}, "/ns", nil
		}
	}

	var wg sync.WaitGroup
	var readResp, writeResp server_structs.DirectorResponse
	var readErr, writeErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		readResp, readErr = cache.LookupOrLoad(context.Background(), testFederation, readFlavor, "/ns/file.txt", loader(&readCalls, "cache.example.com"))
	}()
	go func() {
		defer wg.Done()
		writeResp, writeErr = cache.LookupOrLoad(context.Background(), testFederation, writeFlavor, "/ns/file.txt", loader(&writeCalls, "origin.example.com"))
	}()

	// Both loaders must be running: if the flavors shared a singleflight
	// key, only one would have started and this would deadlock on release.
	require.Eventually(t, func() bool {
		return readCalls.Load() == 1 && writeCalls.Load() == 1
	}, 5*time.Second, 10*time.Millisecond, "each flavor should issue its own director query")
	close(release)
	wg.Wait()

	require.NoError(t, readErr)
	require.NoError(t, writeErr)
	require.Len(t, readResp.ObjectServers, 1)
	require.Len(t, writeResp.ObjectServers, 1)
	assert.Equal(t, "cache.example.com", readResp.ObjectServers[0].Host)
	assert.Equal(t, "origin.example.com", writeResp.ObjectServers[0].Host, "the writer must keep its own answer")
}

// A director may answer differently once it sees a credential, so a
// response obtained with one token must not be handed to a caller bearing a
// different token -- or none.  The credential is carried as a digest so that
// cache keys, which reach debug logs, never contain the token itself.
func TestDirRespCacheCredentialScoping(t *testing.T) {
	base := NewDirRespFlavor(http.MethodGet, false, "")
	alice := base.WithCredential("alice-token")
	bob := base.WithCredential("bob-token")

	t.Run("AnotherTokenDoesNotSeeIt", func(t *testing.T) {
		cache := NewDirRespCache(5 * time.Minute)
		cache.Store(testFederation, alice, "/ns", "", makeDirResp("/ns"))

		_, ok := cache.Lookup(testFederation, bob, "/ns/file.txt")
		assert.False(t, ok, "one caller's authenticated answer must not serve another's token")

		_, ok = cache.Lookup(testFederation, base, "/ns/file.txt")
		assert.False(t, ok, "an authenticated answer must not serve an anonymous lookup")

		_, ok = cache.Lookup(testFederation, alice, "/ns/file.txt")
		assert.True(t, ok, "the same credential reuses its own answer")
	})

	t.Run("SameTokenSharesAcrossObjects", func(t *testing.T) {
		cache := NewDirRespCache(5 * time.Minute)
		cache.Store(testFederation, alice, "/ns", "/ns/first.txt", makeDirResp("/ns"))

		// This is the property that keeps a token-protected namespace from
		// spending a director round trip on every object.
		_, ok := cache.Lookup(testFederation, alice, "/ns/second.txt")
		assert.True(t, ok)
	})

	t.Run("KeyDoesNotContainTheToken", func(t *testing.T) {
		const secret = "super-secret-bearer-token"
		rendered := base.WithCredential(secret).String()
		assert.NotContains(t, rendered, secret, "the token must not appear in a cache key")
		assert.NotEmpty(t, base.WithCredential(secret).Credential)
		assert.Empty(t, base.WithCredential("").Credential, "no token means no credential scoping")
	})
}

// TestLookupOrLoadLoaderOutlivesCancelledCaller pins the property that makes
// what a loader closes over matter.
//
// LookupOrLoad runs its loader on a goroutine with cancellation detached, so a
// caller that gives up does not waste a query other waiters want. The
// consequence is that the loader can still be running after the call that
// created it has returned -- so anything it reads must be a value snapshotted
// beforehand, never a field of a variable the caller may since have
// reassigned. NewTransferJob's `tj` is a named return, and a nil-returning
// error path there once turned exactly this into a segfault.
//
// If someone later makes the loader inherit the caller's cancellation, this
// test fails and the hazard is gone; if they keep the detachment, it stays
// documented.
func TestLookupOrLoadLoaderOutlivesCancelledCaller(t *testing.T) {
	cache := NewDirRespCache(5 * time.Minute)

	loaderStarted := make(chan struct{})
	release := make(chan struct{})
	loaderFinished := make(chan struct{})
	var loaderCtxErr error

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_, _ = cache.LookupOrLoad(ctx, testFederation, testFlavor, "/outlive/file.txt",
			func(loaderCtx context.Context) (server_structs.DirectorResponse, string, error) {
				close(loaderStarted)
				<-release
				// Recorded rather than asserted here: this runs on a
				// different goroutine than the test body.
				loaderCtxErr = loaderCtx.Err()
				close(loaderFinished)
				return makeDirResp("/outlive"), "/outlive", nil
			})
	}()

	<-loaderStarted
	// The originating caller gives up while the loader is mid-flight.
	cancel()
	close(release)

	select {
	case <-loaderFinished:
	case <-time.After(10 * time.Second):
		t.Fatal("loader did not run to completion after its caller was cancelled")
	}

	assert.NoError(t, loaderCtxErr,
		"the loader's context must not be cancelled along with its caller's")

	// And the work it did is still usable by everyone else.
	resp, ok := cache.Lookup(testFederation, testFlavor, "/outlive/file.txt")
	assert.True(t, ok, "the completed load should have been stored")
	assert.NotNil(t, resp)
}
