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

package origin_serve_test

import (
	"bytes"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// ---------------------------------------------------------------------------
// e2eBackend — an instrumented HTTP object store standing in for the remote
// provider (the thing whose egress the storage cache exists to avoid).
// Serves OPTIONS/HEAD/GET so the origin's httpsv2 backend detects plain-HTTP
// mode; counts data (GET) and metadata (HEAD) requests separately.
// ---------------------------------------------------------------------------

type e2eBackendObject struct {
	content []byte
	etag    string
	mod     time.Time
}

type e2eBackend struct {
	mu      sync.Mutex
	objects map[string]e2eBackendObject
	gets    int
	heads   int
	srv     *httptest.Server
}

func newE2EBackend(t *testing.T) *e2eBackend {
	b := &e2eBackend{objects: make(map[string]e2eBackendObject)}
	b.srv = httptest.NewServer(http.HandlerFunc(b.handle))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *e2eBackend) put(p, content, etag string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.objects[path.Clean("/"+p)] = e2eBackendObject{content: []byte(content), etag: etag, mod: time.Now()}
}

func (b *e2eBackend) counts() (gets, heads int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.gets, b.heads
}

func (b *e2eBackend) handle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodOptions:
		// No DAV/PROPFIND advertised: the origin treats us as plain HTTP.
		w.Header().Set("Allow", "OPTIONS, GET, HEAD")
		w.WriteHeader(http.StatusOK)
		return
	case http.MethodGet, http.MethodHead:
		b.mu.Lock()
		obj, ok := b.objects[path.Clean(r.URL.Path)]
		if ok {
			if r.Method == http.MethodGet {
				b.gets++
			} else {
				b.heads++
			}
		}
		b.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("ETag", obj.etag)
		http.ServeContent(w, r, path.Base(r.URL.Path), obj.mod, bytes.NewReader(obj.content))
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

// countCacheFiles tallies the .data and .meta files under the storage cache
// directory on real disk.
func countCacheFiles(t *testing.T, cacheDir string) (dataFiles, metaFiles int) {
	t.Helper()
	err := filepath.WalkDir(cacheDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		switch {
		case strings.HasSuffix(p, ".data"):
			dataFiles++
		case strings.HasSuffix(p, ".meta"):
			metaFiles++
		}
		return nil
	})
	require.NoError(t, err)
	return
}

// TestStorageCacheFedE2E spins up a complete federation (director, registry,
// origin, caches) with an httpsv2 origin whose remote backend is an
// instrumented HTTP server, and the origin storage cache enabled.  It then
// performs real client downloads through federation discovery and direct
// reads, asserting:
//
//  1. the cold read pulls the object from the backend into the cache;
//  2. a warm read serves the same bytes with ZERO additional backend
//     traffic (no GET, no HEAD — the freshness window elides even
//     revalidation);
//  3. mutating the backend object does not change what a fresh cache serves
//     (standard HTTP freshness semantics), proving the bytes come from the
//     origin's local disk rather than the provider.
func TestStorageCacheFedE2E(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	backend := newE2EBackend(t)
	cacheDir := t.TempDir()

	cfg := fmt.Sprintf(`
Origin:
  StorageType: httpsv2
  HttpServiceUrl: %q
  StorageCacheLocation: %q
  Exports:
    - StoragePrefix: /<SHOULD BE OVERRIDDEN>
      FederationPrefix: /test
      Capabilities: ["PublicReads", "Reads", "DirectReads"]
`, backend.srv.URL, cacheDir)

	// The fed harness rewrites StoragePrefix to a fresh temp directory; for
	// an httpsv2 origin that prefix is simply the path prepended on the
	// backend, so register the object under it via the setup hook.
	const objContent = "storage cache e2e payload -- hello from the provider"
	var exportPrefix string
	ft := fed_test_utils.NewFedTest(t, cfg, func(storageDir string) {
		exportPrefix = storageDir
		backend.put(path.Join(storageDir, "cached.txt"), objContent, `"sc-e2e-v1"`)
	})

	fedUrl := fmt.Sprintf("pelican://%s:%s/test/cached.txt?directread",
		param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()))

	download := func(name string) string {
		dest := filepath.Join(t.TempDir(), name)
		tr, err := client.DoGet(ft.Ctx, fedUrl, dest, false)
		require.NoError(t, err)
		require.Len(t, tr, 1)
		require.NoError(t, tr[0].Error)
		data, err := os.ReadFile(dest)
		require.NoError(t, err)
		return string(data)
	}

	// 1. Cold read: the origin fetches from the backend and installs the
	// object in its storage cache.
	require.Equal(t, objContent, download("cold.txt"))
	coldGets, coldHeads := backend.counts()
	require.GreaterOrEqual(t, coldGets, 1, "cold read must fetch data from the backend")

	// The copy is deliberately detached from the client: ServeContent writes
	// exactly Content-Length bytes, so the download completes as soon as the
	// last byte is readable, which is strictly before the fetch goroutine
	// installs the sidecar that marks the entry complete.  Wait for the entry
	// to land rather than assuming the client's completion implies it -- from
	// outside the process there is no other signal, and asserting immediately
	// is a race the client wins on a loaded machine.
	require.Eventually(t, func() bool {
		dataFiles, metaFiles := countCacheFiles(t, cacheDir)
		return dataFiles == 1 && metaFiles == 1
	}, 30*time.Second, 20*time.Millisecond, "cold read should leave one cached object and one sidecar")

	// 2. Warm read: identical bytes, and the backend sees no traffic at all —
	// the entry is fresh, so even the revalidation HEAD is skipped.
	require.Equal(t, objContent, download("warm.txt"))
	warmGets, warmHeads := backend.counts()
	assert.Equal(t, coldGets, warmGets, "warm read must not fetch data from the backend")
	assert.Equal(t, coldHeads, warmHeads, "warm read must not even stat the backend")

	// 3. Mutate the object at the provider.  The origin's copy is still
	// fresh, so it keeps serving the validated bytes without contacting the
	// backend — proof the response comes from local disk.
	backend.put(path.Join(exportPrefix, "cached.txt"), "mutated at the provider", `"sc-e2e-v2"`)
	require.Equal(t, objContent, download("fresh.txt"))
	finalGets, finalHeads := backend.counts()
	assert.Equal(t, coldGets, finalGets)
	assert.Equal(t, coldHeads, finalHeads)
}
