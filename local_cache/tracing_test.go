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
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/tracing"
	"github.com/pelicanplatform/pelican/tracing/tracingtest"
)

const (
	tracedObject  = "/test/traced.bin"
	tracedETag    = `"traced-v1"`
	tracedTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	tracedSpanID  = "00f067aa0ba902b7"
	// tracedToken is a recognisable fake bearer token that must never
	// appear in a span.
	tracedToken = "fake-bearer-token-must-not-leak-7d3c1f"
	// tracedFedToken is a recognisable fake federation token, which the
	// cache appends to origin URLs as access_token=, that must never appear
	// in a span.
	tracedFedToken = "fake-federation-token-must-not-leak-2b9e"
)

var (
	tracedBody   = bytes.Repeat([]byte("pelican-trace-"), 70) // 980 bytes: stored inline
	tracedDigest = func() string {
		sum := md5.Sum(tracedBody)
		return "md5=" + base64.StdEncoding.EncodeToString(sum[:])
	}()
)

// tracedRequest is what a stub server saw of one request.
type tracedRequest struct {
	method      string
	path        string
	traceparent string
	// secrets is the request's query string and Authorization header.
	secrets string
}

// requestLog records the requests a stub server received.
type requestLog struct {
	mu       sync.Mutex
	requests []tracedRequest
}

func (l *requestLog) record(r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.requests = append(l.requests, tracedRequest{
		method:      r.Method,
		path:        r.URL.Path,
		traceparent: r.Header.Get("traceparent"),
		secrets:     r.URL.RawQuery + " " + r.Header.Get("Authorization"),
	})
}

func (l *requestLog) seen() []tracedRequest {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]tracedRequest(nil), l.requests...)
}

// tracedOrigin serves one small object for any path: GET and HEAD with
// ranges and conditionals (http.ServeContent), and a Depth-0 PROPFIND.  When
// gated, a GET waits until the gate is opened (or its request ends) before it
// answers.
type tracedOrigin struct {
	requestLog
	gate     chan struct{}
	gateOnce sync.Once
	// failGets, if set, is the status every GET is answered with, with
	// the full request URI -- query and all -- echoed in the body.
	failGets atomic.Int32
	// gets counts GETs received; blocked counts GETs waiting at the gate.
	gets, blocked atomic.Int32
}

func newTracedOrigin(gated bool) *tracedOrigin {
	o := &tracedOrigin{gate: make(chan struct{})}
	if !gated {
		o.open()
	}
	return o
}

func (o *tracedOrigin) open() { o.gateOnce.Do(func() { close(o.gate) }) }

func (o *tracedOrigin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.record(r)
	switch r.Method {
	case "PROPFIND":
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.WriteHeader(http.StatusMultiStatus)
		_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>`+
			`<D:multistatus xmlns:D="DAV:"><D:response><D:href>%s</D:href><D:propstat><D:prop>`+
			`<D:resourcetype/><D:getcontentlength>%d</D:getcontentlength><D:getetag>%s</D:getetag>`+
			`<D:getlastmodified>Mon, 02 Jan 2006 15:04:05 GMT</D:getlastmodified>`+
			`</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>`,
			r.URL.Path, len(tracedBody), tracedETag)
		return
	case http.MethodGet:
		o.gets.Add(1)
		o.blocked.Add(1)
		select {
		case <-o.gate:
		case <-r.Context().Done():
		}
		o.blocked.Add(-1)
		if r.Context().Err() != nil {
			return
		}
		if status := int(o.failGets.Load()); status != 0 {
			http.Error(w, "origin failure for "+r.URL.RequestURI(), status)
			return
		}
	case http.MethodHead:
	default:
		http.Error(w, "not supported", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("ETag", tracedETag)
	// A HEAD of an uncached object asks the origin for checksums.
	w.Header().Set("Digest", tracedDigest)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(tracedBody))
}

// tracedFed is a stub federation like newStubFedCache's, whose director
// records the requests it receives and routes every prefix it is given, each
// as a public namespace the cache also knows.
type tracedFed struct {
	*stubFedCache
	director *requestLog
}

func newTracedFed(t *testing.T, origin http.Handler, prefixes ...string) *tracedFed {
	t.Helper()
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	InitIssuerKeyForTests(t) // must follow ResetTestState, which clears the issuer key dir
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

	director := &requestLog{}
	directorSrv := httptest.NewUnstartedServer(nil)
	directorURL := "https://" + directorSrv.Listener.Addr().String()
	directorSrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		director.record(r)
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
		for _, prefix := range prefixes {
			if !strings.HasPrefix(objectPath, prefix+"/") {
				continue
			}
			target := originSrv.URL + objectPath
			w.Header().Set(string(server_structs.XPelicanNamespaceHeaderName), "namespace="+prefix+", require-token=false")
			w.Header().Set("Link", "<"+target+`>; rel="duplicate"; pri=1; depth=1`)
			w.Header().Set("Location", target)
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		http.Error(w, "no origin for "+objectPath, http.StatusNotFound)
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
	pc.SetFedToken("stub-federation-token")
	var ads []server_structs.NamespaceAd
	for _, prefix := range prefixes {
		ads = append(ads, server_structs.NamespaceAd{
			Path: prefix,
			Caps: server_structs.Capabilities{PublicReads: true, Reads: true},
		})
	}
	require.NoError(t, pc.ac.updateConfig(ads))

	cacheSrv := httptest.NewServer(http.HandlerFunc(pc.serveObject))
	t.Cleanup(cacheSrv.Close)
	t.Cleanup(func() { _ = pc.Close() })

	return &tracedFed{stubFedCache: &stubFedCache{pc: pc, cacheURL: cacheSrv.URL}, director: director}
}

// ginCacheURL serves the cache's object handler through gin, as the cache's
// TCP routes do, so that the response status reaches the server span.
func ginCacheURL(t *testing.T, pc *PersistentCache) string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.NoRoute(func(c *gin.Context) { pc.serveObject(c.Writer, c.Request) })
	srv := httptest.NewServer(engine)
	t.Cleanup(srv.Close)
	return srv.URL
}

// getResult is the outcome of one request to the cache.
type getResult struct {
	status int
	header http.Header
	body   []byte
	err    error
}

// doGet sends a request to the cache.  It does not touch the test, so it may
// run on any goroutine; check its result on the test's own.
func doGet(ctx context.Context, method, url string, header http.Header) getResult {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return getResult{err: err}
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return getResult{err: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return getResult{status: resp.StatusCode, header: resp.Header, body: body, err: err}
}

// tracedGet sends a request to the cache and returns its status and body.
// Call it only from the test's goroutine.
func tracedGet(t *testing.T, ctx context.Context, method, url string, header http.Header) (int, []byte) {
	t.Helper()
	res := doGet(ctx, method, url, header)
	require.NoError(t, res.err)
	return res.status, res.body
}

// waitSpans waits until exactly n spans of the given name have ended, and
// returns them.
func waitSpans(t *testing.T, exporter *tracetest.InMemoryExporter, name string, n int) []tracetest.SpanStub {
	t.Helper()
	require.Eventually(t, func() bool { return len(tracingtest.SpansNamed(exporter, name)) >= n },
		10*time.Second, 5*time.Millisecond, "waiting for %d %q spans; have %v", n, name, tracingtest.Names(exporter))
	spans := tracingtest.SpansNamed(exporter, name)
	require.Len(t, spans, n, "spans named %q", name)
	return spans
}

// noActiveDownloads reports whether every download the cache started has
// finished (its entry leaves activeDownloads once its completion is done).
func noActiveDownloads(pc *PersistentCache) bool {
	pc.activeDownloadsMu.RLock()
	defer pc.activeDownloadsMu.RUnlock()
	return len(pc.activeDownloads) == 0
}

// waitJoined waits until one request is waiting on the download of
// objectPath that another started.
func waitJoined(t *testing.T, pc *PersistentCache, objectPath string) {
	t.Helper()
	objectHash := pc.db.ObjectHash(pc.normalizePath(objectPath))
	require.Eventually(t, func() bool {
		pc.activeDownloadsMu.RLock()
		defer pc.activeDownloadsMu.RUnlock()
		dl := pc.activeDownloads[objectHash]
		if dl == nil {
			return false
		}
		dl.mu.Lock()
		defer dl.mu.Unlock()
		return len(dl.waiters) == 1
	}, 10*time.Second, 5*time.Millisecond, "the second request must join the first one's fetch")
}

// cacheSpans returns the spans this package records.
func cacheSpans(exporter *tracetest.InMemoryExporter) []string {
	var names []string
	for _, n := range tracingtest.Names(exporter) {
		if strings.HasPrefix(n, "cache.") {
			names = append(names, n)
		}
	}
	return names
}

func hasLinkTo(span tracetest.SpanStub, target trace.SpanContext) bool {
	for _, l := range span.Links {
		if l.SpanContext.SpanID() == target.SpanID() && l.SpanContext.TraceID() == target.TraceID() {
			return true
		}
	}
	return false
}

func hasEvent(span tracetest.SpanStub, name string) bool {
	for _, ev := range span.Events {
		if ev.Name == name {
			return true
		}
	}
	return false
}

// requireNoSecrets fails the test if any recorded span holds one of secrets
// in its status, attributes, events or links.
func requireNoSecrets(t *testing.T, exporter *tracetest.InMemoryExporter, secrets ...string) {
	t.Helper()
	spans := exporter.GetSpans()
	require.NotEmpty(t, spans)
	for _, secret := range secrets {
		for _, s := range spans {
			assert.NotContains(t, s.Status.Description, secret, "span %q status", s.Name)
			for _, kv := range s.Attributes {
				assert.NotContains(t, kv.Value.Emit(), secret, "span %q attribute %s", s.Name, kv.Key)
			}
			for _, ev := range s.Events {
				assert.NotContains(t, ev.Name, secret, "span %q event name", s.Name)
				for _, kv := range ev.Attributes {
					assert.NotContains(t, kv.Value.Emit(), secret, "span %q event %q attribute %s", s.Name, ev.Name, kv.Key)
				}
			}
			for _, l := range s.Links {
				for _, kv := range l.Attributes {
					assert.NotContains(t, kv.Value.Emit(), secret, "span %q link attribute %s", s.Name, kv.Key)
				}
			}
		}
	}
}

// requireNoTraceparent fails the test if any request in log carried a
// traceparent.
func requireNoTraceparent(t *testing.T, who string, log *requestLog) {
	t.Helper()
	seen := log.seen()
	require.NotEmpty(t, seen, "the %s received no requests", who)
	for _, r := range seen {
		assert.Empty(t, r.traceparent, "the %s's %s %s carried a traceparent", who, r.method, r.path)
	}
}

func TestTracingMissThenHit(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceCache))
	origin := newTracedOrigin(false)
	env := newStubFedCache(t, origin)
	url := ginCacheURL(t, env.pc)

	status, body := tracedGet(t, context.Background(), http.MethodGet, url+tracedObject, nil)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, tracedBody, body)

	serve := waitSpans(t, exporter, spanServeObject, 1)[0]
	fetch := waitSpans(t, exporter, spanFetchOrigin, 1)[0]
	resolve := tracingtest.RequireSpan(t, exporter, spanResolveObject)

	assert.Equal(t, string(tracing.ServiceCache), tracingtest.ServiceName(serve))
	assert.Equal(t, trace.SpanKindServer, serve.SpanKind)
	attrs := tracingtest.Attributes(serve)
	assert.Equal(t, int64(http.StatusOK), attrs["http.response.status_code"])
	assert.Equal(t, "miss", attrs[string(attrCacheResult)])
	assert.Equal(t, tracedObject, attrs[string(tracing.AttrObjectPath)])
	assert.Equal(t, false, attrs[string(attrRangeRequest)])
	assert.Equal(t, int64(len(tracedBody)), attrs[string(tracing.AttrTransferBytes)])
	assert.NotContains(t, attrs, string(attrSharedFetch))
	assert.NotContains(t, attrs, string(tracing.AttrJobID))

	tracingtest.RequireParent(t, serve, resolve)
	assert.Equal(t, "download", tracingtest.Attributes(resolve)[string(attrCacheDecision)])
	assert.Equal(t, string(tracing.ServiceCache), tracingtest.ServiceName(resolve))

	tracingtest.RequireParent(t, resolve, fetch)
	assert.Equal(t, string(tracing.ServiceCache), tracingtest.ServiceName(fetch))
	assert.Equal(t, tracedObject, tracingtest.Attributes(fetch)[string(tracing.AttrObjectPath)])
	assert.Equal(t, codes.Unset, fetch.Status.Code)

	// The embedded client's transfer runs under the fetch, and is reported
	// as the cache.
	var transfers []tracetest.SpanStub
	for _, s := range tracingtest.SpansNamed(exporter, "client.transfer") {
		if s.Parent.SpanID() == fetch.SpanContext.SpanID() {
			transfers = append(transfers, s)
		}
	}
	require.Len(t, transfers, 1, "the origin fetch's client.transfer must be a child of %s; spans: %v",
		spanFetchOrigin, tracingtest.Names(exporter))
	assert.Equal(t, string(tracing.ServiceCache), tracingtest.ServiceName(transfers[0]))

	// The second GET is a hit, decided without a fetch.
	require.Eventually(t, func() bool { return noActiveDownloads(env.pc) }, 10*time.Second, 5*time.Millisecond)
	exporter.Reset()
	status, body = tracedGet(t, context.Background(), http.MethodGet, url+tracedObject, nil)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, tracedBody, body)

	serve = waitSpans(t, exporter, spanServeObject, 1)[0]
	resolve = tracingtest.RequireSpan(t, exporter, spanResolveObject)
	tracingtest.RequireParent(t, serve, resolve)
	attrs = tracingtest.Attributes(serve)
	assert.Equal(t, "hit", attrs[string(attrCacheResult)])
	assert.Equal(t, int64(http.StatusOK), attrs["http.response.status_code"])
	assert.Equal(t, "cached", tracingtest.Attributes(resolve)[string(attrCacheDecision)])
	assert.Empty(t, tracingtest.SpansNamed(exporter, spanFetchOrigin))
	assert.Equal(t, int32(1), origin.gets.Load(), "a hit must not fetch from the origin")

	// A range request on the hit.
	exporter.Reset()
	status, body = tracedGet(t, context.Background(), http.MethodGet, url+tracedObject, http.Header{"Range": {"bytes=0-9"}})
	require.Equal(t, http.StatusPartialContent, status)
	require.Equal(t, tracedBody[:10], body)
	serve = waitSpans(t, exporter, spanServeObject, 1)[0]
	attrs = tracingtest.Attributes(serve)
	assert.Equal(t, true, attrs[string(attrRangeRequest)])
	assert.Equal(t, int64(http.StatusPartialContent), attrs["http.response.status_code"])
	assert.Equal(t, "hit", attrs[string(attrCacheResult)])

	// A conditional GET that matches is answered 304, as a hit.
	exporter.Reset()
	status, body = tracedGet(t, context.Background(), http.MethodGet, url+tracedObject, http.Header{"If-None-Match": {tracedETag}})
	require.Equal(t, http.StatusNotModified, status)
	require.Empty(t, body)
	serve = waitSpans(t, exporter, spanServeObject, 1)[0]
	attrs = tracingtest.Attributes(serve)
	assert.Equal(t, int64(http.StatusNotModified), attrs["http.response.status_code"])
	assert.Equal(t, "hit", attrs[string(attrCacheResult)])
	assert.NotContains(t, attrs, string(tracing.AttrTransferBytes), "a 304 carries no object data")
	assert.Equal(t, codes.Unset, serve.Status.Code)
	assert.Equal(t, int32(1), origin.gets.Load())
}

func TestTracingIncomingTraceparentAndJobID(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceCache))
	env := newStubFedCache(t, newTracedOrigin(false))
	url := ginCacheURL(t, env.pc)

	status, _ := tracedGet(t, context.Background(), http.MethodGet, url+tracedObject, http.Header{
		"Traceparent":     {"00-" + tracedTraceID + "-" + tracedSpanID + "-01"},
		"X-Pelican-JobId": {"job-1234"},
	})
	require.Equal(t, http.StatusOK, status)

	serve := waitSpans(t, exporter, spanServeObject, 1)[0]
	assert.Equal(t, tracedTraceID, serve.SpanContext.TraceID().String())
	assert.Equal(t, tracedSpanID, serve.Parent.SpanID().String())
	assert.True(t, serve.Parent.IsRemote())
	assert.Equal(t, "job-1234", tracingtest.Attributes(serve)[string(tracing.AttrJobID)])

	fetch := waitSpans(t, exporter, spanFetchOrigin, 1)[0]
	assert.Equal(t, tracedTraceID, fetch.SpanContext.TraceID().String())
}

// TestTracingPlainWriterHasNoStatus covers the unix-socket listener's plain
// net/http writer, which cannot report the status it sent: the span is still
// recorded, without http.response.status_code, and is never marked failed.
func TestTracingPlainWriterHasNoStatus(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceCache))
	origin := newTracedOrigin(false)
	env := newStubFedCache(t, origin)

	status, _ := tracedGet(t, context.Background(), http.MethodGet, env.cacheURL+tracedObject, nil)
	require.Equal(t, http.StatusOK, status)
	serve := waitSpans(t, exporter, spanServeObject, 1)[0]
	attrs := tracingtest.Attributes(serve)
	assert.NotContains(t, attrs, "http.response.status_code")
	assert.Equal(t, "miss", attrs[string(attrCacheResult)])

	// Nor, without a status, can a failure be told from a client error.
	origin.failGets.Store(http.StatusInternalServerError)
	exporter.Reset()
	status, _ = tracedGet(t, context.Background(), http.MethodGet, env.cacheURL+"/test/failing.bin", nil)
	require.GreaterOrEqual(t, status, 500)
	serve = waitSpans(t, exporter, spanServeObject, 1)[0]
	assert.NotContains(t, tracingtest.Attributes(serve), "http.response.status_code")
	assert.Equal(t, codes.Unset, serve.Status.Code)
	assert.True(t, hasEvent(serve, "exception"), "the error is still attached")
}

// TestTracingClientErrorsAreNotFailures checks that a 4xx response leaves
// cache.serve_object's status unset, with the error attached, while a 5xx
// marks it failed.
func TestTracingClientErrorsAreNotFailures(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceCache))
	origin := newTracedOrigin(false)
	env := newStubFedCache(t, origin)
	url := ginCacheURL(t, env.pc)

	for _, tc := range []struct {
		originStatus int
		failed       bool
	}{
		{http.StatusNotFound, false},
		{http.StatusForbidden, false},
		{http.StatusInternalServerError, true},
	} {
		origin.failGets.Store(int32(tc.originStatus))
		exporter.Reset()
		status, _ := tracedGet(t, context.Background(), http.MethodGet, url+fmt.Sprintf("/test/status-%d.bin", tc.originStatus), nil)
		serve := waitSpans(t, exporter, spanServeObject, 1)[0]
		assert.Equal(t, int64(status), tracingtest.Attributes(serve)["http.response.status_code"])
		assert.True(t, hasEvent(serve, "exception"), "origin %d: the error must be attached", tc.originStatus)
		if tc.failed {
			assert.GreaterOrEqual(t, status, 500, "origin %d", tc.originStatus)
			assert.Equal(t, codes.Error, serve.Status.Code, "origin %d answered %d", tc.originStatus, status)
		} else {
			assert.Less(t, status, 500, "origin %d", tc.originStatus)
			assert.Equal(t, codes.Unset, serve.Status.Code, "origin %d answered %d", tc.originStatus, status)
		}
		require.Eventually(t, func() bool { return noActiveDownloads(env.pc) }, 10*time.Second, 5*time.Millisecond)
	}
}

// TestTracingDenied checks a request the cache itself refuses: the decision
// is denied, the response 403, and the span is not failed but carries the
// error -- and not the token.
func TestTracingDenied(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceCache))
	origin := newTracedOrigin(false)
	env := newStubFedCache(t, origin)
	require.NoError(t, env.pc.ac.updateConfig([]server_structs.NamespaceAd{
		{Path: "/test", Caps: server_structs.Capabilities{PublicReads: true, Reads: true}},
		{Path: "/protected", Caps: server_structs.Capabilities{Reads: true}},
	}))
	url := ginCacheURL(t, env.pc)

	status, _ := tracedGet(t, context.Background(), http.MethodGet, url+"/protected/obj.bin", http.Header{
		"Authorization": {"Bearer " + tracedToken},
	})
	require.Equal(t, http.StatusForbidden, status)

	serve := waitSpans(t, exporter, spanServeObject, 1)[0]
	resolve := tracingtest.RequireSpan(t, exporter, spanResolveObject)
	tracingtest.RequireParent(t, serve, resolve)
	assert.Equal(t, "denied", tracingtest.Attributes(resolve)[string(attrCacheDecision)])
	assert.Equal(t, int64(http.StatusForbidden), tracingtest.Attributes(serve)["http.response.status_code"])
	assert.Equal(t, codes.Unset, serve.Status.Code)
	assert.True(t, hasEvent(serve, "exception"), "the refusal must be attached")
	assert.Empty(t, tracingtest.SpansNamed(exporter, spanFetchOrigin))
	assert.Zero(t, origin.gets.Load())
	requireNoSecrets(t, exporter, tracedToken)
}

func TestTracingSharedFetch(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceCache))
	origin := newTracedOrigin(true)
	defer origin.open()
	env := newStubFedCache(t, origin)
	url := ginCacheURL(t, env.pc)

	results := make(chan getResult, 2)
	get := func() { results <- doGet(context.Background(), http.MethodGet, url+tracedObject, nil) }
	go get()
	require.Eventually(t, func() bool { return origin.blocked.Load() == 1 }, 10*time.Second, 5*time.Millisecond,
		"the first request's fetch must reach the origin")
	go get()
	waitJoined(t, env.pc, tracedObject)

	origin.open()
	for range 2 {
		res := <-results
		require.NoError(t, res.err)
		require.Equal(t, http.StatusOK, res.status)
		require.Equal(t, tracedBody, res.body)
	}

	fetch := waitSpans(t, exporter, spanFetchOrigin, 1)[0]
	serves := waitSpans(t, exporter, spanServeObject, 2)
	resolves := waitSpans(t, exporter, spanResolveObject, 2)
	assert.Equal(t, int32(1), origin.gets.Load(), "the two requests must share one fetch")
	require.NotEqual(t, serves[0].SpanContext.TraceID(), serves[1].SpanContext.TraceID(),
		"two requests are two traces")

	// The join is recorded on cache.resolve_object, and only there.
	var joiner, initiator tracetest.SpanStub
	for _, r := range resolves {
		if tracingtest.Attributes(r)[string(attrSharedFetch)] == true {
			joiner = r
		} else {
			initiator = r
		}
	}
	require.NotEmpty(t, joiner.Name, "one request must be marked as having joined a shared fetch")
	require.NotEmpty(t, initiator.Name, "the request that started the fetch is not a joiner")
	assert.Equal(t, initiator.SpanContext.TraceID(), fetch.SpanContext.TraceID(),
		"the fetch belongs to the trace of the request that started it")
	tracingtest.RequireParent(t, initiator, fetch)
	assert.True(t, hasLinkTo(joiner, fetch.SpanContext), "the joiner's resolve span links to the fetch")
	assert.False(t, hasLinkTo(initiator, fetch.SpanContext))
	for _, s := range serves {
		assert.NotContains(t, tracingtest.Attributes(s), string(attrSharedFetch))
		assert.Empty(t, s.Links)
	}
}

// TestTracingSharedFetchOfAnUnsampledRequest checks a request that joins a
// fetch started by a request whose trace was sampled out: the fetch span was
// never recorded, so there is nothing to link to, but the join is still
// recorded.
func TestTracingSharedFetchOfAnUnsampledRequest(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceCache),
		tracingtest.WithTrustRemoteSampling(true))
	origin := newTracedOrigin(true)
	defer origin.open()
	env := newStubFedCache(t, origin)
	url := ginCacheURL(t, env.pc)

	results := make(chan getResult, 2)
	go func() {
		results <- doGet(context.Background(), http.MethodGet, url+tracedObject, http.Header{
			"Traceparent": {"00-11111111111111111111111111111111-2222222222222222-00"},
		})
	}()
	require.Eventually(t, func() bool { return origin.blocked.Load() == 1 }, 10*time.Second, 5*time.Millisecond,
		"the unsampled request's fetch must reach the origin")
	go func() {
		results <- doGet(context.Background(), http.MethodGet, url+tracedObject, http.Header{
			"Traceparent": {"00-" + tracedTraceID + "-" + tracedSpanID + "-01"},
		})
	}()
	waitJoined(t, env.pc, tracedObject)

	origin.open()
	for range 2 {
		res := <-results
		require.NoError(t, res.err)
		require.Equal(t, http.StatusOK, res.status)
	}
	require.Eventually(t, func() bool { return noActiveDownloads(env.pc) }, 10*time.Second, 5*time.Millisecond)

	serve := waitSpans(t, exporter, spanServeObject, 1)[0]
	assert.Equal(t, tracedTraceID, serve.SpanContext.TraceID().String())
	resolve := tracingtest.RequireSpan(t, exporter, spanResolveObject)
	tracingtest.RequireParent(t, serve, resolve)
	assert.Equal(t, true, tracingtest.Attributes(resolve)[string(attrSharedFetch)])
	assert.Empty(t, resolve.Links, "the fetch was never recorded, so it must not be linked")
	assert.Empty(t, tracingtest.SpansNamed(exporter, spanFetchOrigin))
	for _, s := range exporter.GetSpans() {
		assert.Equal(t, tracedTraceID, s.SpanContext.TraceID().String(), "span %q is not of the sampled trace", s.Name)
	}
}

// TestTracingFetchOutlivesRequest checks that carrying the request's span
// into the fetch did not carry the request's cancellation: a fetch whose
// request has gone still completes, and its span ends without an error.
func TestTracingFetchOutlivesRequest(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceCache))
	origin := newTracedOrigin(true)
	defer origin.open()
	env := newStubFedCache(t, origin)
	url := ginCacheURL(t, env.pc)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan getResult, 1)
	go func() { done <- doGet(ctx, http.MethodGet, url+tracedObject, nil) }()
	require.Eventually(t, func() bool { return origin.blocked.Load() == 1 }, 10*time.Second, 5*time.Millisecond,
		"the fetch must reach the origin")
	cancel()
	require.ErrorIs(t, (<-done).err, context.Canceled)

	origin.open()
	fetch := waitSpans(t, exporter, spanFetchOrigin, 1)[0]
	assert.Equal(t, codes.Unset, fetch.Status.Code, "the fetch must not fail with its request: %s", fetch.Status.Description)
	assert.Empty(t, fetch.Events)
	serve := waitSpans(t, exporter, spanServeObject, 1)[0]
	assert.Equal(t, serve.SpanContext.TraceID(), fetch.SpanContext.TraceID())

	require.Eventually(t, func() bool { return noActiveDownloads(env.pc) }, 10*time.Second, 5*time.Millisecond)
	exporter.Reset()
	status, body := tracedGet(t, context.Background(), http.MethodGet, url+tracedObject, nil)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, tracedBody, body)
	serve = waitSpans(t, exporter, spanServeObject, 1)[0]
	assert.Equal(t, "hit", tracingtest.Attributes(serve)[string(attrCacheResult)])
	assert.Equal(t, int32(1), origin.gets.Load())
}

// TestTracingHeaderTimeout checks the 504 the cache sends when the client's
// X-Pelican-Timeout runs out before the object arrives: the span is failed
// by its status code, and the download carries on and completes.
func TestTracingHeaderTimeout(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceCache))
	origin := newTracedOrigin(true)
	defer origin.open()
	env := newStubFedCache(t, origin)
	url := ginCacheURL(t, env.pc)

	status, _ := tracedGet(t, context.Background(), http.MethodGet, url+tracedObject, http.Header{
		"X-Pelican-Timeout": {"400ms"},
	})
	require.Equal(t, http.StatusGatewayTimeout, status)
	serve := waitSpans(t, exporter, spanServeObject, 1)[0]
	assert.Equal(t, int64(http.StatusGatewayTimeout), tracingtest.Attributes(serve)["http.response.status_code"])
	assert.Equal(t, codes.Error, serve.Status.Code)
	assert.NotContains(t, tracingtest.Attributes(serve), string(attrCacheResult))

	origin.open()
	fetch := waitSpans(t, exporter, spanFetchOrigin, 1)[0]
	assert.Equal(t, codes.Unset, fetch.Status.Code, "the download must complete: %s", fetch.Status.Description)
	assert.Equal(t, serve.SpanContext.TraceID(), fetch.SpanContext.TraceID())
	require.Eventually(t, func() bool { return noActiveDownloads(env.pc) }, 10*time.Second, 5*time.Millisecond)

	exporter.Reset()
	status, body := tracedGet(t, context.Background(), http.MethodGet, url+tracedObject, nil)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, tracedBody, body)
	serve = waitSpans(t, exporter, spanServeObject, 1)[0]
	assert.Equal(t, "hit", tracingtest.Attributes(serve)[string(attrCacheResult)])
	assert.Equal(t, int32(1), origin.gets.Load())
}

// TestTracingRangeOnMiss checks that a range request for an uncached object
// is resolved by a stat, and that the fill which then fetches the blocks the
// reader needs is recorded under the request that started it.  This is the
// first request a Pelican client makes to a cache (its probe), so without it
// a miss shows a slow cache.serve_object with nothing beneath it.
func TestTracingRangeOnMiss(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceCache))
	env := newStubFedCache(t, newTracedOrigin(false))
	url := ginCacheURL(t, env.pc)

	status, body := tracedGet(t, context.Background(), http.MethodGet, url+tracedObject, http.Header{"Range": {"bytes=0-9"}})
	require.Equal(t, http.StatusPartialContent, status)
	require.Equal(t, tracedBody[:10], body)

	serve := waitSpans(t, exporter, spanServeObject, 1)[0]
	resolve := tracingtest.RequireSpan(t, exporter, spanResolveObject)
	tracingtest.RequireParent(t, serve, resolve)
	assert.Equal(t, "range_init", tracingtest.Attributes(resolve)[string(attrCacheDecision)])
	assert.Equal(t, true, tracingtest.Attributes(serve)[string(attrRangeRequest)])
	assert.Equal(t, int64(http.StatusPartialContent), tracingtest.Attributes(serve)["http.response.status_code"])

	// The fill outlives the request by design, so wait for its span.
	fetch := waitSpans(t, exporter, spanFetchOrigin, 1)[0]
	tracingtest.RequireParent(t, serve, fetch)
	assert.Equal(t, tracedObject, tracingtest.Attributes(fetch)[string(tracing.AttrObjectPath)])
	assert.Equal(t, string(tracing.ServiceCache), tracingtest.ServiceName(fetch))
	transfers := tracingtest.SpansNamed(exporter, "client.transfer")
	require.NotEmpty(t, transfers, "the fill's transfer is recorded")
	for _, transfer := range transfers {
		assert.Equal(t, serve.SpanContext.TraceID(), transfer.SpanContext.TraceID())
		assert.Equal(t, string(tracing.ServiceCache), tracingtest.ServiceName(transfer))
	}
}

// TestTracingRevalidate checks the decision for a stale cached object.
func TestTracingRevalidate(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceCache))
	env := newStubFedCache(t, newTracedOrigin(false))
	// The origin sends no Cache-Control, so the default freshness applies.
	require.NoError(t, param.LocalCache_DefaultMaxAge.Set(time.Nanosecond))
	url := ginCacheURL(t, env.pc)

	status, _ := tracedGet(t, context.Background(), http.MethodGet, url+tracedObject, nil)
	require.Equal(t, http.StatusOK, status)
	waitSpans(t, exporter, spanServeObject, 1)
	require.Eventually(t, func() bool { return noActiveDownloads(env.pc) }, 10*time.Second, 5*time.Millisecond)

	exporter.Reset()
	status, body := tracedGet(t, context.Background(), http.MethodGet, url+tracedObject, nil)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, tracedBody, body)
	serve := waitSpans(t, exporter, spanServeObject, 1)[0]
	resolve := tracingtest.RequireSpan(t, exporter, spanResolveObject)
	tracingtest.RequireParent(t, serve, resolve)
	assert.Equal(t, "revalidate", tracingtest.Attributes(resolve)[string(attrCacheDecision)])
}

// TestTracingPropagatesToOrigin checks that the cache's fetch from the
// origin carries the trace of the request that caused it.  The traceparent
// is injected by the client package's instrumentation, given the context
// the cache passes it.
func TestTracingPropagatesToOrigin(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceCache))
	origin := newTracedOrigin(false)
	env := newStubFedCache(t, origin)
	url := ginCacheURL(t, env.pc)

	status, _ := tracedGet(t, context.Background(), http.MethodGet, url+tracedObject, http.Header{
		"Traceparent": {"00-" + tracedTraceID + "-" + tracedSpanID + "-01"},
	})
	require.Equal(t, http.StatusOK, status)
	waitSpans(t, exporter, spanFetchOrigin, 1)

	var gets int
	for _, r := range origin.seen() {
		if r.method != http.MethodGet {
			continue
		}
		gets++
		parts := strings.Split(r.traceparent, "-")
		require.Len(t, parts, 4, "the origin's GET must carry a traceparent; got %q", r.traceparent)
		assert.Equal(t, tracedTraceID, parts[1])
	}
	assert.Equal(t, 1, gets)
}

func TestTracingOnlyGetAndHead(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceCache))
	origin := newTracedOrigin(false)
	env := newStubFedCache(t, origin)
	url := ginCacheURL(t, env.pc)

	// PUT and PROPFIND are proxied and create no cache spans, whatever
	// the proxy answers.
	tracedGet(t, context.Background(), http.MethodPut, url+tracedObject, nil)
	tracedGet(t, context.Background(), "PROPFIND", url+tracedObject, http.Header{"Depth": {"1"}})
	assert.Empty(t, cacheSpans(exporter))

	// HEAD of an uncached object stats the origin and starts no download.
	status, _ := tracedGet(t, context.Background(), http.MethodHead, url+tracedObject, nil)
	require.Equal(t, http.StatusOK, status)
	serve := waitSpans(t, exporter, spanServeObject, 1)[0]
	attrs := tracingtest.Attributes(serve)
	assert.Equal(t, http.MethodHead, attrs["http.request.method"])
	assert.Equal(t, int64(http.StatusOK), attrs["http.response.status_code"])
	assert.Equal(t, tracedObject, attrs[string(tracing.AttrObjectPath)])
	assert.Empty(t, tracingtest.SpansNamed(exporter, spanFetchOrigin))
	assert.Zero(t, origin.gets.Load(), "a HEAD must not download")

	// HEAD of a cached object.
	status, _ = tracedGet(t, context.Background(), http.MethodGet, url+tracedObject, nil)
	require.Equal(t, http.StatusOK, status)
	require.Eventually(t, func() bool { return noActiveDownloads(env.pc) }, 10*time.Second, 5*time.Millisecond)
	exporter.Reset()
	status, _ = tracedGet(t, context.Background(), http.MethodHead, url+tracedObject, nil)
	require.Equal(t, http.StatusOK, status)
	serve = waitSpans(t, exporter, spanServeObject, 1)[0]
	attrs = tracingtest.Attributes(serve)
	assert.Equal(t, http.MethodHead, attrs["http.request.method"])
	assert.Equal(t, int64(http.StatusOK), attrs["http.response.status_code"])
}

// TestTracingBackgroundGetRecordsNothing checks that a download the cache
// starts with no traced request behind it -- prestaging, here -- records no
// span of any service and sends no traceparent anywhere.
func TestTracingBackgroundGetRecordsNothing(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceCache))
	origin := newTracedOrigin(false)
	env := newTracedFed(t, origin, "/test")

	rc, err := env.pc.Get(context.Background(), "/test/background.bin", "")
	require.NoError(t, err)
	body, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	require.Equal(t, tracedBody, body)
	require.Eventually(t, func() bool { return noActiveDownloads(env.pc) }, 10*time.Second, 5*time.Millisecond)

	assert.Equal(t, int32(1), origin.gets.Load())
	tracingtest.RequireNoSpans(t, exporter)
	requireNoTraceparent(t, "origin", &origin.requestLog)
	requireNoTraceparent(t, "director", env.director)
}

// TestTracingMonitoringPathRecordsNothing checks that a GET of health-test
// traffic that misses and is fetched from the origin records no span of any
// service and sends no traceparent anywhere.
func TestTracingMonitoringPathRecordsNothing(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceCache))
	origin := newTracedOrigin(false)
	env := newTracedFed(t, origin, "/test", server_utils.MonitoringBaseNs)
	url := ginCacheURL(t, env.pc)

	status, body := tracedGet(t, context.Background(), http.MethodGet, url+server_utils.MonitoringBaseNs+"/selfTest/obj", nil)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, tracedBody, body)
	require.Eventually(t, func() bool { return noActiveDownloads(env.pc) }, 10*time.Second, 5*time.Millisecond)

	assert.Equal(t, int32(1), origin.gets.Load(), "the object must have been fetched")
	tracingtest.RequireNoSpans(t, exporter)
	requireNoTraceparent(t, "origin", &origin.requestLog)
	requireNoTraceparent(t, "director", env.director)
}

func TestTracingDisabled(t *testing.T) {
	tracingtest.Disabled(t)
	origin := newTracedOrigin(false)
	env := newStubFedCache(t, origin)
	url := ginCacheURL(t, env.pc)

	for range 2 {
		status, body := tracedGet(t, context.Background(), http.MethodGet, url+tracedObject, http.Header{
			"Traceparent": {"00-" + tracedTraceID + "-" + tracedSpanID + "-01"},
		})
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, tracedBody, body)
		require.Eventually(t, func() bool { return noActiveDownloads(env.pc) }, 10*time.Second, 5*time.Millisecond)
	}
	assert.Equal(t, int32(1), origin.gets.Load(), "the second GET must be a hit")
	assert.False(t, tracing.Enabled())
	requireNoTraceparent(t, "origin", &origin.requestLog)
}

// TestTracingRecordsNoToken checks that neither the client's token nor the
// federation token the cache appends to origin URLs reaches a span, on a
// successful download or a failed one.
func TestTracingRecordsNoToken(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceCache))
	origin := newTracedOrigin(false)
	env := newStubFedCache(t, origin)
	env.pc.SetFedToken(tracedFedToken)
	url := ginCacheURL(t, env.pc)

	for _, failGets := range []int{0, http.StatusInternalServerError} {
		origin.failGets.Store(int32(failGets))
		exporter.Reset()
		objectPath := fmt.Sprintf("/test/token-%d.bin", failGets)
		status, _ := tracedGet(t, context.Background(), http.MethodGet, url+objectPath+"?authz="+tracedToken, http.Header{
			"Authorization": {"Bearer " + tracedToken},
		})
		if failGets == 0 {
			require.Equal(t, http.StatusOK, status)
		} else {
			require.GreaterOrEqual(t, status, 500)
		}
		serve := waitSpans(t, exporter, spanServeObject, 1)[0]
		require.Eventually(t, func() bool { return noActiveDownloads(env.pc) }, 10*time.Second, 5*time.Millisecond)
		if failGets != 0 {
			assert.True(t, hasEvent(serve, "exception"), "the failure must be attached to the span")
		}
		requireNoSecrets(t, exporter, tracedToken, tracedFedToken)
	}

	// The tokens were in play: the origin was sent the federation token.
	var sentFedToken bool
	for _, r := range origin.seen() {
		if strings.Contains(r.secrets, tracedFedToken) {
			sentFedToken = true
		}
	}
	assert.True(t, sentFedToken, "the origin was never sent the federation token")
}
