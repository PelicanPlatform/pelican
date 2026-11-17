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

package origin_serve

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/net/webdav"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/tracing"
	"github.com/pelicanplatform/pelican/tracing/tracingtest"
)

// tracingTestObject is the content of the object the tests download.
var tracingTestObject = []byte(strings.Repeat("pelican tracing test object\n", 40))

// fakeTracingToken is a recognisable credential that must never show up in a
// span.  It is not a valid JWT, so it authorizes nothing.
const fakeTracingToken = "pelican-fake-token-DO-NOT-RECORD-7f3c9a"

// startTracingOrigin stands up the origin's export handlers (no federation, no
// XRootD) over the given exports and storage type, and returns its base URL.
// configure, when given, sets further parameters after the reset.
func startTracingOrigin(t *testing.T, storageType string, exports []server_utils.OriginExport, configure ...func()) string {
	t.Helper()
	return startTracingOriginMounted(t, false, storageType, exports, configure...)
}

// startTracingOriginMounted is startTracingOrigin with the choice of mounting:
// directorEnabled mounts the exports under server_structs.OriginDataRoutePrefix,
// as when the director runs in the same process.
func startTracingOriginMounted(t *testing.T, directorEnabled bool, storageType string, exports []server_utils.OriginExport, configure ...func()) string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	require.NoError(t, param.Origin_StorageType.Set(storageType))
	for _, f := range configure {
		f()
	}

	ResetHandlers()
	t.Cleanup(ResetHandlers)
	require.NoError(t, InitializeHandlers(t.Context(), exports))
	require.NoError(t, InitAuthConfig(t.Context(), &errgroup.Group{}, exports))

	engine := gin.New()
	require.NoError(t, RegisterHandlers(engine, directorEnabled))
	server := httptest.NewServer(engine)
	t.Cleanup(server.Close)
	return server.URL
}

// posixTracingExports serves /public (public reads, holding obj.bin) and
// /protected (token required, holding secret.bin) from temp directories.
func posixTracingExports(t *testing.T) []server_utils.OriginExport {
	t.Helper()
	publicDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(publicDir, "obj.bin"), tracingTestObject, 0o644))
	protectedDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(protectedDir, "secret.bin"), tracingTestObject, 0o644))
	return []server_utils.OriginExport{
		{
			FederationPrefix: "/public",
			StoragePrefix:    publicDir,
			Capabilities:     server_structs.Capabilities{PublicReads: true, Reads: true},
		},
		{
			FederationPrefix: "/protected",
			StoragePrefix:    protectedDir,
			IssuerUrls:       []string{"https://issuer.invalid"},
			Capabilities:     server_structs.Capabilities{Reads: true},
		},
	}
}

// startPosixTracingOrigin serves posixTracingExports.
func startPosixTracingOrigin(t *testing.T) string {
	t.Helper()
	return startTracingOrigin(t, string(server_structs.OriginStoragePosixv2), posixTracingExports(t))
}

type tracingResponse struct {
	status int
	header http.Header
	body   []byte
}

func doTracingRequest(t *testing.T, method, url string, header http.Header) tracingResponse {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	require.NoError(t, err)
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return tracingResponse{status: resp.StatusCode, header: resp.Header, body: body}
}

// requireNoSecret fails if any attribute, event or status of any recorded
// span contains secret.
func requireNoSecret(t *testing.T, exporter *tracetest.InMemoryExporter, secret string) {
	t.Helper()
	for _, s := range exporter.GetSpans() {
		require.NotContains(t, s.Name, secret)
		require.NotContains(t, s.Status.Description, secret, "status of span %q", s.Name)
		for _, kv := range s.Attributes {
			require.NotContains(t, kv.Value.Emit(), secret, "attribute %s of span %q", kv.Key, s.Name)
		}
		for _, ev := range s.Events {
			require.NotContains(t, ev.Name, secret, "event of span %q", s.Name)
			for _, kv := range ev.Attributes {
				require.NotContains(t, kv.Value.Emit(), secret, "event attribute %s of span %q", kv.Key, s.Name)
			}
		}
	}
}

func TestOriginTracingPublicGet(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceOrigin))
	base := startPosixTracingOrigin(t)

	resp := doTracingRequest(t, http.MethodGet, base+"/public/obj.bin", nil)
	require.Equal(t, http.StatusOK, resp.status)
	require.Equal(t, tracingTestObject, resp.body)

	server := tracingtest.RequireSpan(t, exporter, spanServeObject)
	assert.Equal(t, string(tracing.ServiceOrigin), tracingtest.ServiceName(server))
	assert.Equal(t, trace.SpanKindServer, server.SpanKind)
	assert.False(t, server.Parent.IsValid(), "with no traceparent the server span is a root")
	attrs := tracingtest.Attributes(server)
	assert.Equal(t, int64(http.StatusOK), attrs["http.response.status_code"])
	assert.Equal(t, http.MethodGet, attrs["http.request.method"])
	assert.Equal(t, "/public/obj.bin", attrs["pelican.object.path"])
	assert.Equal(t, "/public", attrs["pelican.namespace"])
	assert.Equal(t, string(server_structs.OriginStoragePosixv2), attrs["pelican.origin.storage_type"])
	assert.Equal(t, int64(len(tracingTestObject)), attrs["pelican.transfer.bytes"])
	assert.NotContains(t, attrs, "pelican.job_id", "no job ID was sent")
	assert.Equal(t, codes.Unset, server.Status.Code)

	authz := tracingtest.RequireSpan(t, exporter, spanAuthorize)
	tracingtest.RequireParent(t, server, authz)
	assert.Equal(t, string(tracing.ServiceOrigin), tracingtest.ServiceName(authz))
	authzAttrs := tracingtest.Attributes(authz)
	assert.Equal(t, true, authzAttrs["pelican.origin.authorized"])
	assert.Equal(t, int64(0), authzAttrs["pelican.origin.token_count"])
	assert.False(t, authz.EndTime.After(server.EndTime))

	read := tracingtest.RequireSpan(t, exporter, spanRead)
	tracingtest.RequireParent(t, server, read)
	assert.NotContains(t, tracingtest.Attributes(read), "pelican.origin.storage_type",
		"the storage type is on the parent span only")
	assert.False(t, read.StartTime.Before(authz.EndTime), "authorization finishes before the read starts")

	assert.Len(t, exporter.GetSpans(), 3, "recorded spans: %v", tracingtest.Names(exporter))
}

func TestOriginTracingJoinsIncomingTraceparent(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceOrigin))
	base := startPosixTracingOrigin(t)

	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	const parentSpanID = "00f067aa0ba902b7"
	resp := doTracingRequest(t, http.MethodGet, base+"/public/obj.bin", http.Header{
		"Traceparent":     {"00-" + traceID + "-" + parentSpanID + "-01"},
		"X-Pelican-Jobid": {"job-1234"},
	})
	require.Equal(t, http.StatusOK, resp.status)

	server := tracingtest.RequireSpan(t, exporter, spanServeObject)
	assert.Equal(t, traceID, server.SpanContext.TraceID().String())
	assert.Equal(t, parentSpanID, server.Parent.SpanID().String())
	assert.True(t, server.Parent.IsRemote())
	assert.Equal(t, "job-1234", tracingtest.Attributes(server)["pelican.job_id"])

	for _, s := range exporter.GetSpans() {
		assert.Equal(t, traceID, s.SpanContext.TraceID().String(), "span %q is in another trace", s.Name)
	}
	tracingtest.RequireParent(t, server, tracingtest.RequireSpan(t, exporter, spanRead))
	tracingtest.RequireParent(t, server, tracingtest.RequireSpan(t, exporter, spanAuthorize))
}

func TestOriginTracingDeniedRequest(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceOrigin))
	base := startPosixTracingOrigin(t)

	t.Run("invalid-token", func(t *testing.T) {
		exporter.Reset()
		// The token goes in both places a client can put one.
		resp := doTracingRequest(t, http.MethodGet, base+"/protected/secret.bin?authz="+fakeTracingToken, http.Header{
			"Authorization": {"Bearer " + fakeTracingToken},
		})
		require.Equal(t, http.StatusUnauthorized, resp.status)
		require.NotEmpty(t, resp.body, "the 401 carries an error body")

		server := tracingtest.RequireSpan(t, exporter, spanServeObject)
		attrs := tracingtest.Attributes(server)
		assert.Equal(t, int64(http.StatusUnauthorized), attrs["http.response.status_code"])
		assert.Equal(t, "/protected/secret.bin", attrs["url.path"], "the query string is not recorded")
		assert.NotContains(t, attrs, "pelican.transfer.bytes", "an error body is not object data")
		assert.Equal(t, codes.Unset, server.Status.Code, "a 4xx is not a server failure")

		authz := tracingtest.RequireSpan(t, exporter, spanAuthorize)
		tracingtest.RequireParent(t, server, authz)
		authzAttrs := tracingtest.Attributes(authz)
		assert.Equal(t, false, authzAttrs["pelican.origin.authorized"])
		assert.Equal(t, int64(2), authzAttrs["pelican.origin.token_count"])

		assert.Empty(t, tracingtest.SpansNamed(exporter, spanRead), "a denied request never reads storage")
		requireNoSecret(t, exporter, fakeTracingToken)
	})

	t.Run("no-token", func(t *testing.T) {
		exporter.Reset()
		resp := doTracingRequest(t, http.MethodGet, base+"/protected/secret.bin", nil)
		require.Equal(t, http.StatusUnauthorized, resp.status)

		server := tracingtest.RequireSpan(t, exporter, spanServeObject)
		attrs := tracingtest.Attributes(server)
		assert.Equal(t, int64(http.StatusUnauthorized), attrs["http.response.status_code"])
		assert.NotContains(t, attrs, "pelican.transfer.bytes")
		authzAttrs := tracingtest.Attributes(tracingtest.RequireSpan(t, exporter, spanAuthorize))
		assert.Equal(t, false, authzAttrs["pelican.origin.authorized"])
		assert.Equal(t, int64(0), authzAttrs["pelican.origin.token_count"])
		assert.Empty(t, tracingtest.SpansNamed(exporter, spanRead))
	})
}

func TestOriginTracingHead(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceOrigin))
	base := startPosixTracingOrigin(t)

	resp := doTracingRequest(t, http.MethodHead, base+"/public/obj.bin", nil)
	require.Equal(t, http.StatusOK, resp.status)

	server := tracingtest.RequireSpan(t, exporter, spanServeObject)
	attrs := tracingtest.Attributes(server)
	assert.Equal(t, http.MethodHead, attrs["http.request.method"])
	assert.Equal(t, int64(http.StatusOK), attrs["http.response.status_code"])
	assert.NotContains(t, attrs, "pelican.transfer.bytes", "a HEAD moves no object data")
	tracingtest.RequireParent(t, server, tracingtest.RequireSpan(t, exporter, spanAuthorize))
	assert.Empty(t, tracingtest.SpansNamed(exporter, spanRead), "HEAD has no read span")
}

// TestOriginTracingTransferBytes checks that pelican.transfer.bytes counts
// object data only: the bytes of a range, and nothing for a 304 or an HTML
// directory listing.
func TestOriginTracingTransferBytes(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceOrigin))
	base := startPosixTracingOrigin(t)

	t.Run("range", func(t *testing.T) {
		exporter.Reset()
		resp := doTracingRequest(t, http.MethodGet, base+"/public/obj.bin", http.Header{"Range": {"bytes=10-109"}})
		require.Equal(t, http.StatusPartialContent, resp.status)
		require.Equal(t, tracingTestObject[10:110], resp.body)

		attrs := tracingtest.Attributes(tracingtest.RequireSpan(t, exporter, spanServeObject))
		assert.Equal(t, int64(http.StatusPartialContent), attrs["http.response.status_code"])
		assert.Equal(t, int64(100), attrs["pelican.transfer.bytes"])
	})

	t.Run("not-modified", func(t *testing.T) {
		first := doTracingRequest(t, http.MethodHead, base+"/public/obj.bin", nil)
		etag := first.header.Get("Etag")
		require.NotEmpty(t, etag)

		exporter.Reset()
		resp := doTracingRequest(t, http.MethodGet, base+"/public/obj.bin", http.Header{"If-None-Match": {etag}})
		require.Equal(t, http.StatusNotModified, resp.status)

		server := tracingtest.RequireSpan(t, exporter, spanServeObject)
		attrs := tracingtest.Attributes(server)
		assert.Equal(t, int64(http.StatusNotModified), attrs["http.response.status_code"])
		assert.NotContains(t, attrs, "pelican.transfer.bytes", "a 304 has no body")
		tracingtest.RequireParent(t, server, tracingtest.RequireSpan(t, exporter, spanRead))
	})

	t.Run("html-listing", func(t *testing.T) {
		exporter.Reset()
		resp := doTracingRequest(t, http.MethodGet, base+"/public/", http.Header{"Accept": {"text/html"}})
		require.Equal(t, http.StatusOK, resp.status)
		require.Contains(t, string(resp.body), "obj.bin", "the listing is served")

		attrs := tracingtest.Attributes(tracingtest.RequireSpan(t, exporter, spanServeObject))
		assert.Equal(t, int64(http.StatusOK), attrs["http.response.status_code"])
		assert.NotContains(t, attrs, "pelican.transfer.bytes", "a listing is not object data")
	})
}

// TestOriginTracingObjectPathIsServedPath checks that pelican.object.path
// names the object the handler serves -- the routed export's prefix joined
// with the cleaned wildcard -- even when the URL's dot-segments would resolve
// into another export.  It asserts on the attribute only.
func TestOriginTracingObjectPathIsServedPath(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceOrigin))
	base := startPosixTracingOrigin(t)

	_ = doTracingRequest(t, http.MethodGet, base+"/protected/../public/obj.bin", nil)

	attrs := tracingtest.Attributes(tracingtest.RequireSpan(t, exporter, spanServeObject))
	require.Equal(t, "/protected/../public/obj.bin", attrs["url.path"], "the request reached the origin uncleaned")
	assert.Equal(t, "/protected", attrs["pelican.namespace"])
	assert.Equal(t, "/protected/public/obj.bin", attrs["pelican.object.path"])
}

// TestOriginTracingColocated checks the mounting used when the director runs
// in the same process: the routes live under OriginDataRoutePrefix, but the
// span names the federation path.
func TestOriginTracingColocated(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceOrigin))
	base := startTracingOriginMounted(t, true, string(server_structs.OriginStoragePosixv2), posixTracingExports(t))

	resp := doTracingRequest(t, http.MethodGet, base+server_structs.OriginDataRoutePrefix+"/public/obj.bin", nil)
	require.Equal(t, http.StatusOK, resp.status)
	require.Equal(t, tracingTestObject, resp.body)

	server := tracingtest.RequireSpan(t, exporter, spanServeObject)
	attrs := tracingtest.Attributes(server)
	assert.Equal(t, "/public/obj.bin", attrs["pelican.object.path"])
	assert.Equal(t, "/public", attrs["pelican.namespace"])
	assert.Equal(t, int64(len(tracingTestObject)), attrs["pelican.transfer.bytes"])
	tracingtest.RequireParent(t, server, tracingtest.RequireSpan(t, exporter, spanRead))
}

// panicFileSystem is a webdav.FileSystem whose every operation panics.
type panicFileSystem struct{}

func (panicFileSystem) Mkdir(context.Context, string, os.FileMode) error { panic("test: Mkdir") }
func (panicFileSystem) OpenFile(context.Context, string, int, os.FileMode) (webdav.File, error) {
	panic("test: OpenFile")
}
func (panicFileSystem) RemoveAll(context.Context, string) error           { panic("test: RemoveAll") }
func (panicFileSystem) Rename(context.Context, string, string) error      { panic("test: Rename") }
func (panicFileSystem) Stat(context.Context, string) (os.FileInfo, error) { panic("test: Stat") }

// panicBackend is an always-available backend over panicFileSystem.
type panicBackend struct{}

func (panicBackend) CheckAvailability() error                    { return nil }
func (panicBackend) FileSystem() webdav.FileSystem               { return panicFileSystem{} }
func (panicBackend) Checksummer() server_utils.OriginChecksummer { return nil }

// TestOriginTracingPanic checks that a panic in the traced chain, which the
// engine's gin.Recovery answers with a 500, still ends and exports the spans.
func TestOriginTracingPanic(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceOrigin))
	gin.SetMode(gin.TestMode)

	engine := gin.New()
	// The same middleware as gin.Recovery(), without the stack trace on stderr.
	engine.Use(gin.RecoveryWithWriter(io.Discard))

	// A backend that panics when the handler opens the object.
	handlerGroup := engine.Group("/handler")
	handlerGroup.Use(tracingMiddleware("/handler", "panic-test"))
	handlerGroup.Any("/*path", exportRequestHandler(panicBackend{},
		&webdav.Handler{Prefix: "/handler", FileSystem: panicFileSystem{}, LockSystem: webdav.NewMemLS()},
		"/handler", "/handler"))

	// A middleware that panics before the handler runs.
	middlewareGroup := engine.Group("/middleware")
	middlewareGroup.Use(tracingMiddleware("/middleware", "panic-test"))
	middlewareGroup.Use(func(*gin.Context) { panic("test: middleware") })
	middlewareGroup.Any("/*path", func(c *gin.Context) { c.Status(http.StatusOK) })

	server := httptest.NewServer(engine)
	t.Cleanup(server.Close)

	t.Run("in-backend", func(t *testing.T) {
		exporter.Reset()
		resp := doTracingRequest(t, http.MethodGet, server.URL+"/handler/obj.bin", nil)
		require.Equal(t, http.StatusInternalServerError, resp.status)

		serve := tracingtest.RequireSpan(t, exporter, spanServeObject)
		assert.Equal(t, int64(http.StatusInternalServerError), tracingtest.Attributes(serve)["http.response.status_code"])
		assert.Equal(t, codes.Error, serve.Status.Code)
		assert.NotContains(t, tracingtest.Attributes(serve), "pelican.transfer.bytes")
		read := tracingtest.RequireSpan(t, exporter, spanRead)
		tracingtest.RequireParent(t, serve, read)
	})

	t.Run("in-middleware", func(t *testing.T) {
		exporter.Reset()
		resp := doTracingRequest(t, http.MethodGet, server.URL+"/middleware/obj.bin", nil)
		require.Equal(t, http.StatusInternalServerError, resp.status)

		serve := tracingtest.RequireSpan(t, exporter, spanServeObject)
		assert.Equal(t, int64(http.StatusInternalServerError), tracingtest.Attributes(serve)["http.response.status_code"])
		assert.Equal(t, codes.Error, serve.Status.Code)
		assert.Empty(t, tracingtest.SpansNamed(exporter, spanRead))
	})
}

// TestOriginTracingUntracedRequests checks that writes, other WebDAV methods
// and health-test traffic produce no spans, and that an authorized GET does.
func TestOriginTracingUntracedRequests(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceOrigin))

	key := generateTestKey(t)
	issuerURL := startTestIssuer(t, key)
	monitoringDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(monitoringDir, "monitoring", "selfTest"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(monitoringDir, "monitoring", "selfTest", "self-test.txt"), tracingTestObject, 0o644))

	base := startTracingOrigin(t, string(server_structs.OriginStoragePosixv2), []server_utils.OriginExport{
		{
			FederationPrefix: "/data",
			StoragePrefix:    t.TempDir(),
			IssuerUrls:       []string{issuerURL},
			Capabilities:     server_structs.Capabilities{Reads: true, Writes: true, Listings: true},
		},
		{
			// An export whose namespace covers the health-test objects.
			FederationPrefix: "/pelican",
			StoragePrefix:    monitoringDir,
			Capabilities:     server_structs.Capabilities{PublicReads: true, Reads: true},
		},
	})
	tok := createTestToken(t, key, issuerURL, "alice", nil,
		"storage.create:/ storage.read:/", "https://wlcg.cern.ch/jwt/v1/any")
	const traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

	t.Run("put", func(t *testing.T) {
		exporter.Reset()
		req, err := http.NewRequest(http.MethodPut, base+"/data/new.bin", strings.NewReader("uploaded"))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Traceparent", traceparent)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		tracingtest.RequireNoSpans(t, exporter)
	})

	t.Run("monitoring-get", func(t *testing.T) {
		exporter.Reset()
		resp := doTracingRequest(t, http.MethodGet, base+server_utils.MonitoringBaseNs+"/selfTest/self-test.txt", nil)
		require.Equal(t, http.StatusOK, resp.status)
		require.Equal(t, tracingTestObject, resp.body)
		tracingtest.RequireNoSpans(t, exporter)
	})

	t.Run("monitoring-head", func(t *testing.T) {
		exporter.Reset()
		resp := doTracingRequest(t, http.MethodHead, base+server_utils.MonitoringBaseNs+"/selfTest/self-test.txt", nil)
		require.Equal(t, http.StatusOK, resp.status)
		tracingtest.RequireNoSpans(t, exporter)
	})

	t.Run("authorized-get", func(t *testing.T) {
		exporter.Reset()
		resp := doTracingRequest(t, http.MethodGet, base+"/data/new.bin", http.Header{
			"Authorization": {"Bearer " + tok},
		})
		require.Equal(t, http.StatusOK, resp.status)
		require.Equal(t, "uploaded", string(resp.body))

		server := tracingtest.RequireSpan(t, exporter, spanServeObject)
		authzAttrs := tracingtest.Attributes(tracingtest.RequireSpan(t, exporter, spanAuthorize))
		assert.Equal(t, true, authzAttrs["pelican.origin.authorized"])
		assert.Equal(t, int64(1), authzAttrs["pelican.origin.token_count"])
		tracingtest.RequireParent(t, server, tracingtest.RequireSpan(t, exporter, spanRead))
		requireNoSecret(t, exporter, tok)
	})

	for _, tc := range []struct {
		method string
		path   string
		header http.Header
	}{
		{"PROPFIND", "/data/", http.Header{"Depth": {"1"}}},
		{http.MethodOptions, "/data/new.bin", nil},
		{http.MethodDelete, "/data/new.bin", nil},
	} {
		t.Run(strings.ToLower(tc.method), func(t *testing.T) {
			exporter.Reset()
			header := http.Header{
				"Authorization": {"Bearer " + tok},
				"Traceparent":   {traceparent},
			}
			for k, v := range tc.header {
				header[k] = v
			}
			resp := doTracingRequest(t, tc.method, base+tc.path, header)
			require.NotZero(t, resp.status)
			tracingtest.RequireNoSpans(t, exporter)
		})
	}
}

func TestOriginTracingServedObjectPath(t *testing.T) {
	for _, tc := range []struct {
		prefix, wildcard, want string
	}{
		{"/public", "/obj.bin", "/public/obj.bin"},
		{"/public", "/dir/", "/public/dir"},
		{"/public", "/", "/public"},
		{"/public", "", "/public"},
		{"/protected", "/../public/x", "/protected/public/x"},
		{"/a", "/b/../../c", "/a/c"},
		{"/pelican", "/monitoring/selfTest/x", "/pelican/monitoring/selfTest/x"},
		{"/pelican/monitoring", "/directorTest/x", "/pelican/monitoring/directorTest/x"},
	} {
		assert.Equal(t, tc.want, servedObjectPath(tc.prefix, tc.wildcard), "%s + %s", tc.prefix, tc.wildcard)
	}

	withETag := http.Header{"Etag": {`"x"`}}
	assert.True(t, isObjectData(http.MethodGet, http.StatusOK, withETag))
	assert.True(t, isObjectData(http.MethodGet, http.StatusPartialContent, withETag))
	assert.False(t, isObjectData(http.MethodGet, http.StatusOK, http.Header{}), "a listing has no ETag")
	assert.False(t, isObjectData(http.MethodHead, http.StatusOK, withETag))
	assert.False(t, isObjectData(http.MethodGet, http.StatusNotModified, withETag))
	assert.False(t, isObjectData(http.MethodGet, http.StatusUnauthorized, http.Header{}))
}

// httpsUpstream is a plain-HTTP upstream for the httpsv2 backend that records
// the traceparent header of each GET it serves.
type httpsUpstream struct {
	mu           sync.Mutex
	traceparents []string
	requests     int // number of HEAD and GET requests seen
}

func (u *httpsUpstream) record(r *http.Request) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.requests++
	if r.Method == http.MethodGet {
		u.traceparents = append(u.traceparents, r.Header.Get("Traceparent"))
	}
}

func (u *httpsUpstream) snapshot() (traceparents []string, requests int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.traceparents...), u.requests
}

func startHTTPSTracingOrigin(t *testing.T) (string, *httpsUpstream) {
	t.Helper()
	upstream := &httpsUpstream{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodOptions:
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
			w.WriteHeader(http.StatusOK)
		case http.MethodHead, http.MethodGet:
			upstream.record(r)
			if r.URL.Path != "/store/obj.bin" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(tracingTestObject)))
			w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodGet {
				_, _ = w.Write(tracingTestObject)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(server.Close)

	exports := []server_utils.OriginExport{{
		FederationPrefix: "/remote",
		StoragePrefix:    "/store",
		Capabilities:     server_structs.Capabilities{PublicReads: true, Reads: true},
	}}
	base := startTracingOrigin(t, string(server_structs.OriginStorageHTTPSv2), exports, func() {
		require.NoError(t, param.Origin_HttpServiceUrl.Set(server.URL))
	})
	return base, upstream
}

func TestOriginTracingHTTPSBackendPropagates(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceOrigin))
	base, upstream := startHTTPSTracingOrigin(t)

	resp := doTracingRequest(t, http.MethodGet, base+"/remote/obj.bin", nil)
	require.Equal(t, http.StatusOK, resp.status)
	require.Equal(t, tracingTestObject, resp.body)

	server := tracingtest.RequireSpan(t, exporter, spanServeObject)
	assert.Equal(t, string(server_structs.OriginStorageHTTPSv2), tracingtest.Attributes(server)["pelican.origin.storage_type"])
	assert.Equal(t, int64(len(tracingTestObject)), tracingtest.Attributes(server)["pelican.transfer.bytes"])
	read := tracingtest.RequireSpan(t, exporter, spanRead)
	tracingtest.RequireParent(t, server, read)

	gets := tracingtest.SpansNamed(exporter, http.MethodGet)
	require.NotEmpty(t, gets, "the upstream GET is recorded; spans: %v", tracingtest.Names(exporter))
	for _, get := range gets {
		tracingtest.RequireParent(t, read, get)
		assert.Equal(t, trace.SpanKindClient, get.SpanKind)
		assert.Equal(t, string(tracing.ServiceOrigin), tracingtest.ServiceName(get))
		assert.Equal(t, int64(http.StatusOK), tracingtest.Attributes(get)["http.response.status_code"])
	}

	traceparents, _ := upstream.snapshot()
	require.Len(t, traceparents, len(gets))
	traceID := server.SpanContext.TraceID().String()
	for i, tp := range traceparents {
		parts := strings.Split(tp, "-")
		require.Len(t, parts, 4, "upstream GET carried traceparent %q", tp)
		assert.Equal(t, traceID, parts[1])
		assert.Equal(t, gets[i].SpanContext.SpanID().String(), parts[2],
			"the upstream sees the client span as its parent")
	}
}

// stableHeaders drops the headers that legitimately differ between two
// otherwise identical responses.
func stableHeaders(h http.Header) http.Header {
	c := h.Clone()
	c.Del("Date")
	return c
}

// requireSameResponse fails unless two responses are identical apart from
// their Date header.
func requireSameResponse(t *testing.T, name string, a, b tracingResponse) {
	t.Helper()
	assert.Equal(t, a.status, b.status, name)
	assert.Equal(t, a.body, b.body, name)
	assert.Equal(t, stableHeaders(a.header), stableHeaders(b.header), name)
}

// TestOriginTracingDisabled sends each request to one origin twice, once with
// tracing off and once with it on (the middleware checks per request), and
// checks that tracing changes nothing a client or upstream can observe, and
// that nothing is recorded or sent while it is off.
func TestOriginTracingDisabled(t *testing.T) {
	// offThenOn sends one request with tracing disabled and then enabled, and
	// returns both responses.
	offThenOn := func(t *testing.T, send func() tracingResponse) (off, on tracingResponse) {
		t.Helper()
		tracingtest.Disabled(t)
		off = send()
		exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceOrigin))
		on = send()
		require.NotEmpty(t, exporter.GetSpans(), "the enabled request is traced")
		return off, on
	}

	t.Run("posix", func(t *testing.T) {
		base := startPosixTracingOrigin(t)
		for _, tc := range []struct {
			name, method, path string
			header             http.Header
			status             int
		}{
			{"public", http.MethodGet, "/public/obj.bin", http.Header{"X-Pelican-Jobid": {"job-1"}}, http.StatusOK},
			{"range", http.MethodGet, "/public/obj.bin", http.Header{"Range": {"bytes=5-50"}}, http.StatusPartialContent},
			{"denied", http.MethodGet, "/protected/secret.bin", http.Header{"Authorization": {"Bearer " + fakeTracingToken}}, http.StatusUnauthorized},
			{"head", http.MethodHead, "/public/obj.bin", nil, http.StatusOK},
		} {
			t.Run(tc.name, func(t *testing.T) {
				off, on := offThenOn(t, func() tracingResponse {
					return doTracingRequest(t, tc.method, base+tc.path, tc.header)
				})
				require.Equal(t, tc.status, off.status)
				requireSameResponse(t, tc.name, off, on)
			})
		}
	})

	t.Run("httpsv2", func(t *testing.T) {
		base, upstream := startHTTPSTracingOrigin(t)
		var offRequests, onRequests int
		off, on := offThenOn(t, func() tracingResponse {
			_, before := upstream.snapshot()
			r := doTracingRequest(t, http.MethodGet, base+"/remote/obj.bin", nil)
			_, after := upstream.snapshot()
			if tracing.Enabled() {
				onRequests = after - before
			} else {
				offRequests = after - before
			}
			return r
		})
		require.Equal(t, http.StatusOK, off.status)
		requireSameResponse(t, "remote", off, on)
		assert.Equal(t, offRequests, onRequests, "tracing adds no upstream requests")

		traceparents, _ := upstream.snapshot()
		require.NotEmpty(t, traceparents)
		sawEmpty, sawSet := false, false
		for _, tp := range traceparents {
			if tp == "" {
				sawEmpty = true
			} else {
				sawSet = true
			}
		}
		assert.True(t, sawEmpty, "no traceparent is sent upstream while tracing is disabled")
		assert.True(t, sawSet, "a traceparent is sent upstream while tracing is enabled")
		// The disabled request came first, so its upstream GETs are first.
		assert.Empty(t, traceparents[0])
	})
}

// TestOriginTracingSampledOut checks that a request the sampler drops gets
// the same response, records nothing, and adds no trace ID to the request
// log line, while a sampled request's log line carries its trace ID.
func TestOriginTracingSampledOut(t *testing.T) {
	base := startPosixTracingOrigin(t)

	logger := log.StandardLogger()
	if logger.GetLevel() < log.InfoLevel {
		prev := logger.GetLevel()
		logger.SetLevel(log.InfoLevel)
		t.Cleanup(func() { logger.SetLevel(prev) })
	}
	hook := &logtest.Hook{}
	orig := logger.Hooks
	hooks := make(log.LevelHooks, len(orig))
	for level, hs := range orig {
		hooks[level] = append([]log.Hook(nil), hs...)
	}
	hooks.Add(hook)
	logger.ReplaceHooks(hooks)
	t.Cleanup(func() { logger.ReplaceHooks(orig) })

	// requestLogged returns the "Request received" line of the last request.
	requestLogged := func(t *testing.T) *log.Entry {
		t.Helper()
		var found *log.Entry
		for _, e := range hook.AllEntries() {
			if e.Message == "Request received" {
				found = e
			}
		}
		require.NotNil(t, found, "the request was logged")
		return found
	}

	sampledOut := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceOrigin), tracingtest.WithSamplePercentage(0))
	hook.Reset()
	dropped := doTracingRequest(t, http.MethodGet, base+"/public/obj.bin", nil)
	require.Equal(t, http.StatusOK, dropped.status)
	require.Equal(t, tracingTestObject, dropped.body)
	tracingtest.RequireNoSpans(t, sampledOut)
	assert.NotContains(t, requestLogged(t).Data, "trace_id")
	assert.NotContains(t, requestLogged(t).Data, "span_id")

	// The same request, sampled, as a control on the log capture.
	sampled := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceOrigin))
	hook.Reset()
	kept := doTracingRequest(t, http.MethodGet, base+"/public/obj.bin", nil)
	requireSameResponse(t, "sampled-out vs sampled", dropped, kept)
	server := tracingtest.RequireSpan(t, sampled, spanServeObject)
	assert.Equal(t, server.SpanContext.TraceID().String(), requestLogged(t).Data["trace_id"])
}
