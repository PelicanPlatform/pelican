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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

const (
	// slowOriginByteInterval is how long the slow origin waits between the
	// single bytes it dribbles out. With slowOriginObjectSize below it means a
	// fetch from that origin cannot possibly finish inside the test: the
	// transfer is still holding its scheduler slot when every assertion runs.
	slowOriginByteInterval = 100 * time.Millisecond
	// slowOriginObjectSize is the advertised size of every object on the slow
	// origin: 4 KiB at one byte per 100 ms is ~7 minutes of dribbling, which
	// the test aborts long before it completes.
	slowOriginObjectSize = 4 * 1024

	// slowRequestCount is how many distinct slow objects are requested at
	// once. Distinct paths matter: each one becomes its own cache-miss fetch
	// that must independently clear scheduler admission, instead of coalescing
	// onto a single in-flight download.
	slowRequestCount = 10
)

// TestSchedulerShedPerOriginIsolation proves the central promise of the cache's
// fair scheduler — one misbehaving origin cannot deny service to the others —
// without standing up a federation.
//
// Two stub origins are put behind a stub director:
//
//   - the slow origin accepts every request and then dribbles one byte per
//     100 ms, so a fetch from it holds a worker slot indefinitely;
//   - the healthy origin answers immediately with a small object.
//
// Because the scheduler tags admissions by the upstream host (see
// deriveSchedulerTag), and the two stubs listen on different loopback ports,
// they land on two independent tags whose caps are enforced separately:
//
//	Cache.WorkerCount                        2
//	Cache.Throttle.PerOriginStarvingPercent  25 → starving cap = ceil(2 * 25/100) = 1
//	Cache.Throttle.PerOriginActivePercent    25 → active cap   = ceil(2 * 25/100) = 1
//	Cache.Throttle.PerOriginPendingSize      1
//	Cache.Throttle.PendingBufferSize         16
//	Cache.Throttle.EMAWindow                 1s
//
// So the slow origin's tag may hold one in-flight fetch plus one queued one,
// and the remaining eight of a ten-way burst arrive to find its FIFO full and
// are shed with a 429. The global pending buffer (16) is never the binding
// limit, which is what makes the shed reason a per-origin one
// (origin_unresponsive while the in-flight fetch has yet to produce a first
// byte, origin_slow once it has) rather than cache_overloaded.
//
// The isolation property is the second assertion: while those slow fetches are
// still dribbling, a request for an object on the healthy origin is admitted
// under its own tag and served in full. The third assertion closes the loop
// through the scheduler's own bookkeeping: every rejection is attributed to the
// slow origin's tag and none to the healthy one's.
func TestSchedulerShedPerOriginIsolation(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	InitIssuerKeyForTests(t) // must follow ResetTestState, which clears the issuer key dir

	ctx, cancel := context.WithCancel(context.Background())
	egrp, _ := errgroup.WithContext(ctx)
	// Registered first so it runs last: the origin stubs and the cache have to
	// be torn down before the errgroup is drained.
	t.Cleanup(func() {
		cancel()
		_ = egrp.Wait()
	})

	// The transfers here fail on purpose (they are shed, or aborted at
	// teardown), so keep the log volume down to what a failure needs.
	require.NoError(t, param.Logging_Level.Set("error"))

	// Clamp the fair scheduler. NewPersistentCache reads these once, at
	// construction time, so they must all be set before it is called.
	require.NoError(t, param.Cache_WorkerCount.Set(2))
	require.NoError(t, param.Cache_Throttle_PerOriginStarvingPercent.Set(25))
	require.NoError(t, param.Cache_Throttle_PerOriginActivePercent.Set(25))
	require.NoError(t, param.Cache_Throttle_PendingBufferSize.Set(16))
	require.NoError(t, param.Cache_Throttle_PerOriginPendingSize.Set(1))
	require.NoError(t, param.Cache_Throttle_EMAWindow.Set(time.Second))
	// The stub director and origins are httptest TLS servers with self-signed
	// certificates; federation discovery is hard-wired to https, so the
	// transport has to tolerate them.
	require.NoError(t, param.TLSSkipVerify.Set(true))

	// release aborts every in-flight slow response. Its cleanup is registered
	// at the end of setup so that it runs *before* the httptest servers are
	// closed -- Server.Close waits for outstanding handlers to return.
	release := make(chan struct{})

	// The slow origin: accepts everything, then dribbles.
	slowSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(slowOriginObjectSize))
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("ETag", `"slow-origin-etag"`)
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		flusher, canFlush := w.(http.Flusher)
		for sent := 0; sent < slowOriginObjectSize; sent++ {
			select {
			case <-release:
				return
			case <-r.Context().Done():
				return
			case <-time.After(slowOriginByteInterval):
			}
			if _, err := w.Write([]byte{'s'}); err != nil {
				return
			}
			if canFlush {
				flusher.Flush()
			}
		}
	}))
	t.Cleanup(slowSrv.Close)

	// The healthy origin: a small object, served instantly. ServeContent
	// handles HEAD, Range and the size/ETag headers the way a real origin
	// would.
	healthyPayload := bytes.Repeat([]byte("healthy-origin-payload\n"), 64) // ~1.4 KiB, a single block
	healthyModTime := time.Now().Add(-time.Hour)
	healthySrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"healthy-origin-etag"`)
		http.ServeContent(w, r, "obj.bin", healthyModTime, bytes.NewReader(healthyPayload))
	}))
	t.Cleanup(healthySrv.Close)

	slowHost := mustHost(t, slowSrv.URL)
	healthyHost := mustHost(t, healthySrv.URL)

	// The stub director. It answers federation discovery (pointing at itself)
	// and routes object requests to one of the two origins by path prefix. The
	// client accepts either a Link header or a bare Location on a 307; sending
	// both keeps the stub honest against either code path.
	//
	// It is created unstarted so its own URL is known before any handler can
	// run, which keeps the closure below race-free.
	directorSrv := httptest.NewUnstartedServer(nil)
	directorURL := "https://" + directorSrv.Listener.Addr().String()
	directorSrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The Server header is how the client tells a real director from an
		// ingress proxy standing in for one that is rebooting.
		w.Header().Set("Server", "pelican/7.99.0")

		if r.URL.Path == "/.well-known/pelican-configuration" {
			w.Header().Set("Content-Type", "application/json")
			// t.Errorf rather than require: this runs on a server goroutine,
			// where a FailNow would abandon the test instead of failing it.
			if encErr := json.NewEncoder(w).Encode(pelican_url.FederationDiscovery{
				DiscoveryEndpoint: directorURL,
				DirectorEndpoint:  directorURL,
			}); encErr != nil {
				t.Errorf("failed to write the discovery document: %v", encErr)
			}
			return
		}

		// A cache fetching on behalf of a client asks the director's origin
		// endpoint (see useEmbeddedCacheMode), so strip that prefix to recover
		// the federation path.
		objectPath := strings.TrimPrefix(r.URL.Path, "/api/v1.0/director/origin")
		var target, namespace string
		switch {
		case strings.HasPrefix(objectPath, "/slow/"):
			target, namespace = slowSrv.URL+objectPath, "/slow"
		case strings.HasPrefix(objectPath, "/healthy/"):
			target, namespace = healthySrv.URL+objectPath, "/healthy"
		default:
			http.Error(w, "no origin for "+objectPath, http.StatusNotFound)
			return
		}
		// The namespace header is not optional: the client refuses a redirect it
		// cannot attribute to a namespace. require-token=false keeps these
		// objects public, which also leaves the origin URLs on the scheme the
		// Link header names rather than forcing them to https.
		w.Header().Set(string(server_structs.XPelicanNamespaceHeaderName),
			"namespace="+namespace+", require-token=false")
		w.Header().Set("Link", "<"+target+`>; rel="duplicate"; pri=1; depth=1`)
		w.Header().Set("Location", target)
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	directorSrv.StartTLS()
	t.Cleanup(directorSrv.Close)

	// Point the cache at the stub director so upstream resolution stays offline.
	config.SetFederation(pelican_url.FederationDiscovery{
		DiscoveryEndpoint: directorURL,
		DirectorEndpoint:  directorURL,
	})

	// Build a real persistent cache in server mode -- the mode that wires a
	// TagScheduler onto the transfer engine. DeferConfig skips the initial
	// director namespace fetch; the namespaces are injected below instead.
	tmpDir := t.TempDir()
	pc, err := NewPersistentCache(ctx, egrp, PersistentCacheConfig{
		Mode:        CacheModeServer,
		BaseDir:     tmpDir,
		StorageDirs: []StorageDirConfig{{Path: tmpDir}},
		DeferConfig: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	require.NotNil(t, pc.scheduler, "server-mode cache must construct a fair scheduler")

	// Public namespaces so the tokenless GETs below authorize.
	require.NoError(t, pc.ac.updateConfig([]server_structs.NamespaceAd{
		{Path: "/slow", Caps: server_structs.Capabilities{PublicReads: true, Reads: true}},
		{Path: "/healthy", Caps: server_structs.Capabilities{PublicReads: true, Reads: true}},
	}))

	// Serve the cache's object handler over real HTTP.
	cacheSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pc.serveObject(w, r)
	}))
	t.Cleanup(cacheSrv.Close)

	// Everything is built, so this is the last cleanup registered and hence
	// the first to run: unblock the dribbling handlers so the server closes
	// and the errgroup drains promptly.
	t.Cleanup(func() { close(release) })

	// The requests that are admitted stream (slowly) for as long as the test
	// runs; this context lets them be abandoned at the end instead of waited
	// for.
	reqCtx, reqCancel := context.WithCancel(ctx)
	defer reqCancel()
	httpClient := &http.Client{}

	type shedResult struct {
		status     int
		retryAfter string
		// reason and detail are the "error" and "detail" fields of an error
		// (non-200) JSON body.
		reason string
		detail string
		err    error
	}
	results := make(chan shedResult, slowRequestCount)

	// Phase 1: burst the slow origin.
	for i := 0; i < slowRequestCount; i++ {
		go func(i int) {
			objURL := fmt.Sprintf("%s/slow/obj-%d.bin", cacheSrv.URL, i)
			req, reqErr := http.NewRequestWithContext(reqCtx, http.MethodGet, objURL, nil)
			if reqErr != nil {
				results <- shedResult{err: reqErr}
				return
			}
			resp, doErr := httpClient.Do(req)
			if doErr != nil {
				results <- shedResult{err: doErr}
				return
			}
			defer resp.Body.Close()
			res := shedResult{
				status:     resp.StatusCode,
				retryAfter: resp.Header.Get("Retry-After"),
			}
			if resp.StatusCode != http.StatusOK {
				// The reason is the whole point of the 429 body; parse it. Any
				// other error status gets the same treatment so a failure of
				// this test reports what the cache actually said.
				body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
				if readErr != nil {
					results <- shedResult{err: readErr}
					return
				}
				var parsedBody struct {
					Error  string `json:"error"`
					Detail string `json:"detail"`
				}
				if jsonErr := json.Unmarshal(body, &parsedBody); jsonErr != nil {
					results <- shedResult{err: fmt.Errorf("HTTP %d body %q is not JSON: %w", resp.StatusCode, string(body), jsonErr)}
					return
				}
				res.reason = parsedBody.Error
				res.detail = parsedBody.Detail
			}
			results <- res
		}(i)
	}

	// Collect the sheds. With one active plus one pending slot on the slow
	// origin's tag, eight of the ten requests must be rejected; wait for a
	// clear majority of them rather than for all ten goroutines, because the
	// admitted ones do not return until the test tears down.
	const wantSheds = slowRequestCount - 2
	var sheds []shedResult
	var otherStatuses []string
	var transportErrs []error
	collectDeadline := time.After(20 * time.Second)
collect:
	for len(sheds) < wantSheds {
		select {
		case res := <-results:
			switch {
			case res.err != nil:
				transportErrs = append(transportErrs, res.err)
			case res.status == http.StatusTooManyRequests:
				sheds = append(sheds, res)
			default:
				otherStatuses = append(otherStatuses,
					fmt.Sprintf("%d (%s: %s)", res.status, res.reason, res.detail))
			}
		case <-collectDeadline:
			break collect
		}
	}
	t.Logf("slow-origin burst: %d sheds, other statuses %v, transport errors %v",
		len(sheds), otherStatuses, transportErrs)

	require.Empty(t, transportErrs, "every burst request must complete at the HTTP layer")
	require.NotEmpty(t, sheds,
		"a %d-way burst against an origin capped at one active and one pending transfer must be shed", slowRequestCount)
	perOriginReasons := map[string]int{}
	for _, shed := range sheds {
		assert.Equal(t, "60", shed.retryAfter, "every 429 must carry the documented Retry-After header")
		// Compare against the constants rather than fresh literals: the
		// scheduler, the cache's HTTP layer and the client's parser must all
		// agree on the spelling, and a rename should break here.
		assert.Contains(t,
			[]string{string(client.ShedOriginUnresponsive), string(client.ShedOriginSlow)},
			shed.reason,
			"a shed caused by one origin's own cap must blame that origin, not the cache")
		perOriginReasons[shed.reason]++
	}
	t.Logf("shed reasons: %v", perOriginReasons)

	// Phase 2: the isolation property. The slow origin's fetches are still
	// dribbling (4 KiB at one byte per 100 ms cannot have finished), yet the
	// healthy origin has its own tag, its own caps, and a free worker.
	// Bounded so that a cache which wrongly makes this request wait behind the
	// slow origin fails the test promptly instead of hanging it.
	healthyCtx, healthyCancel := context.WithTimeout(reqCtx, 20*time.Second)
	defer healthyCancel()
	healthyReq, err := http.NewRequestWithContext(healthyCtx, http.MethodGet, cacheSrv.URL+"/healthy/obj.bin", nil)
	require.NoError(t, err)
	healthyResp, err := httpClient.Do(healthyReq)
	require.NoError(t, err, "a healthy origin must remain reachable while another origin is being shed")
	healthyBody, err := io.ReadAll(healthyResp.Body)
	require.NoError(t, err)
	require.NoError(t, healthyResp.Body.Close())
	require.Equal(t, http.StatusOK, healthyResp.StatusCode,
		"healthy-origin GET was not served (body: %s)", string(healthyBody))
	assert.Equal(t, healthyPayload, healthyBody, "healthy-origin GET must return the whole object")

	// Phase 3: the scheduler's own books agree with what the clients saw.
	snap := pc.scheduler.Snapshot(ctx)
	t.Logf("scheduler snapshot: global=%+v tags=%+v", snap.Global, snap.Tags)

	slowStats, ok := snap.Tags[slowHost]
	require.True(t, ok, "expected a scheduler tag for the slow origin %q; tags=%+v", slowHost, snap.Tags)
	assert.Greater(t, slowStats.Rejects, uint64(0), "the slow origin's tag must own the rejections")

	healthyStats, ok := snap.Tags[healthyHost]
	require.True(t, ok, "expected a scheduler tag for the healthy origin %q; tags=%+v", healthyHost, snap.Tags)
	assert.Zero(t, healthyStats.Rejects, "the healthy origin must not be charged for the slow origin's congestion")
	assert.Greater(t, healthyStats.Admits, uint64(0), "the healthy origin's fetch must have been admitted")

	for tag, stats := range snap.Tags {
		if tag == slowHost {
			continue
		}
		assert.Zero(t, stats.Rejects, "tag %q must have no rejections; only %q was over its cap", tag, slowHost)
	}
	assert.Greater(t, snap.Global.TotalRejectsPerTag, uint64(0),
		"the rejections must come from the per-origin cap, not the global pending buffer")
	assert.Zero(t, snap.Global.TotalRejectsGlobal,
		"the global pending buffer (16) must never have been the binding limit")
}

// mustHost returns the host:port of a server URL, which is also the tag the
// scheduler files that server's transfers under (see deriveSchedulerTag).
func mustHost(t *testing.T, rawURL string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	require.NoError(t, err)
	return parsed.Host
}
