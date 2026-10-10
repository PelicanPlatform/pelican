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

package local_cache

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// stubFedCache is a persistent cache, served over HTTP, in front of a stub
// director that sends every request for the public namespace /test to one
// stub origin -- a federation for the cache's own tests that needs neither
// XRootD nor a registry.
type stubFedCache struct {
	pc *PersistentCache
	// cacheURL serves the cache's object handler.
	cacheURL string
}

// newStubFedCache starts a stub federation whose origin is the given handler,
// and a cache in front of it.  The origin handler must return once its
// request's context ends: the cache is closed, and its transfers cancelled,
// before the origin server is.
func newStubFedCache(t *testing.T, origin http.Handler) *stubFedCache {
	t.Helper()
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	InitIssuerKeyForTests(t) // must follow ResetTestState, which clears the issuer key dir
	// The stubs are TLS servers with self-signed certificates.
	require.NoError(t, param.TLSSkipVerify.Set(true))

	ctx, cancel := context.WithCancel(context.Background())
	egrp, _ := errgroup.WithContext(ctx)
	// Registered first so that it runs last.
	t.Cleanup(func() {
		cancel()
		_ = egrp.Wait()
	})

	originSrv := httptest.NewTLSServer(origin)
	t.Cleanup(originSrv.Close)

	directorSrv := httptest.NewUnstartedServer(nil)
	directorURL := "https://" + directorSrv.Listener.Addr().String()
	directorSrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "pelican/7.99.0")
		if r.URL.Path == "/.well-known/pelican-configuration" {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(pelican_url.FederationDiscovery{
				DiscoveryEndpoint: directorURL,
				DirectorEndpoint:  directorURL,
			}); err != nil {
				t.Errorf("failed to write the discovery document: %v", err)
			}
			return
		}
		objectPath := strings.TrimPrefix(r.URL.Path, "/api/v1.0/director/origin")
		if !strings.HasPrefix(objectPath, "/test/") {
			http.Error(w, "no origin for "+objectPath, http.StatusNotFound)
			return
		}
		target := originSrv.URL + objectPath
		w.Header().Set(string(server_structs.XPelicanNamespaceHeaderName), "namespace=/test, require-token=false")
		w.Header().Set("Link", "<"+target+`>; rel="duplicate"; pri=1; depth=1`)
		w.Header().Set("Location", target)
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	directorSrv.StartTLS()
	t.Cleanup(directorSrv.Close)

	config.SetFederation(pelican_url.FederationDiscovery{
		DiscoveryEndpoint: directorURL,
		DirectorEndpoint:  directorURL,
	})

	tmpDir := t.TempDir()
	pc, err := NewPersistentCache(ctx, egrp, PersistentCacheConfig{
		Mode:        CacheModeServer,
		BaseDir:     tmpDir,
		StorageDirs: []StorageDirConfig{{Path: tmpDir}},
		DeferConfig: true,
	})
	require.NoError(t, err)
	// Without a federation token, every transfer first waits two seconds
	// for one; the stub origin accepts anything.
	pc.SetFedToken("stub-federation-token")
	require.NoError(t, pc.ac.updateConfig([]server_structs.NamespaceAd{{
		Path: "/test",
		Caps: server_structs.Capabilities{PublicReads: true, Reads: true},
	}}))

	cacheSrv := httptest.NewServer(http.HandlerFunc(pc.serveObject))
	t.Cleanup(cacheSrv.Close)
	// Runs before the servers close: closing the cache cancels its
	// transfers, which lets every origin handler return, and wakes every
	// reader still waiting, which lets every cache handler return.
	t.Cleanup(func() { _ = pc.Close() })

	return &stubFedCache{pc: pc, cacheURL: cacheSrv.URL}
}

// blockState returns the shared block state of the version of objectPath
// the cache last recorded.
func (e *stubFedCache) blockState(t *testing.T, objectPath string) *ObjectBlockState {
	t.Helper()
	objectHash := e.pc.db.ObjectHash(e.pc.normalizePath(objectPath))
	etag, found, err := e.pc.db.GetLatestETag(objectHash)
	require.NoError(t, err)
	require.True(t, found, "no version of %s recorded", objectPath)
	state, err := e.pc.storage.GetSharedBlockState(e.pc.db.InstanceHash(etag, objectHash))
	require.NoError(t, err)
	return state
}

// stallingOrigin serves an object of the given size and entity tag, but
// only its first stallAt bytes: a request for anything after them gets its
// headers and whatever part of the range lies before stallAt, and then
// nothing more until its context ends, as from a stalled origin.
type stallingOrigin struct {
	size, stallAt int64
	etag          string
	// cacheControl, if set, is sent as the response's Cache-Control.
	cacheControl string
	// stalled counts the requests stalled now.
	stalled atomic.Int32
}

func newStallingOrigin(size, stallAt int64, etag string) *stallingOrigin {
	return &stallingOrigin{size: size, stallAt: stallAt, etag: etag}
}

// stallingOriginByte is the byte at offset off of a stallingOrigin's object.
func stallingOriginByte(off int64) byte { return byte(off % 251) }

func (o *stallingOrigin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "not supported", http.StatusMethodNotAllowed)
		return
	}
	start, end := int64(0), o.size-1
	if rg := r.Header.Get("Range"); rg != "" {
		if _, err := fmt.Sscanf(rg, "bytes=%d-%d", &start, &end); err != nil {
			_, _ = fmt.Sscanf(rg, "bytes=%d-", &start)
			end = o.size - 1
		}
		end = min(end, o.size-1)
	}
	w.Header().Set("ETag", o.etag)
	if o.cacheControl != "" {
		w.Header().Set("Cache-Control", o.cacheControl)
	}
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Length", fmt.Sprint(end-start+1))
	status := http.StatusOK
	if start != 0 || end != o.size-1 {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, o.size))
		status = http.StatusPartialContent
	}
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	body := make([]byte, 0, max(0, min(end+1, o.stallAt)-start))
	for off := start; off <= end && off < o.stallAt; off++ {
		body = append(body, stallingOriginByte(off))
	}
	_, _ = w.Write(body)
	if end < o.stallAt {
		return
	}
	w.(http.Flusher).Flush()
	o.stalled.Add(1)
	defer o.stalled.Add(-1)
	<-r.Context().Done()
}
