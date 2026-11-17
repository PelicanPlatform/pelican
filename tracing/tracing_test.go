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

package tracing_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/tracing"
	"github.com/pelicanplatform/pelican/tracing/tracingtest"
)

const (
	incomingTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	incomingSpanID  = "00f067aa0ba902b7"
	sampledParent   = "00-" + incomingTraceID + "-" + incomingSpanID + "-01"
)

// headerRecorder is an httptest server that remembers the traceparent header
// of every request it receives.
type headerRecorder struct {
	*httptest.Server
	mu           sync.Mutex
	traceparents []string
}

func newHeaderRecorder(t *testing.T, status int) *headerRecorder {
	hr := &headerRecorder{}
	hr.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hr.mu.Lock()
		hr.traceparents = append(hr.traceparents, r.Header.Get("traceparent"))
		hr.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte("hello, world"))
	}))
	t.Cleanup(hr.Close)
	return hr
}

func (hr *headerRecorder) received() []string {
	hr.mu.Lock()
	defer hr.mu.Unlock()
	return append([]string(nil), hr.traceparents...)
}

func doGet(t *testing.T, ctx context.Context, c *http.Client, url string) *http.Response {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)
	resp, err := c.Do(req)
	require.NoError(t, err)
	return resp
}

func TestDisabled(t *testing.T) {
	tracingtest.Disabled(t)
	require.False(t, tracing.Enabled())

	ctx := context.Background()
	gotCtx, span := tracing.Start(ctx, "nothing")
	assert.False(t, span.IsRecording())
	assert.False(t, span.SpanContext().IsValid())
	assert.Equal(t, ctx, gotCtx)
	span.End()

	_, span = tracing.StartWithService(ctx, tracing.ServiceCache, "nothing")
	assert.False(t, span.IsRecording())

	srv := newHeaderRecorder(t, http.StatusOK)
	c := srv.Client()
	assert.Same(t, c, tracing.Client(c))
	assert.Equal(t, c.Transport, tracing.Transport(c.Transport))

	req := httptest.NewRequest(http.MethodGet, "/obj", nil)
	req.Header.Set("traceparent", sampledParent)
	gotReq, serverSpan := tracing.StartServer(req, tracing.ServiceOrigin, "origin.serve_object")
	assert.Same(t, req, gotReq)
	assert.False(t, serverSpan.IsRecording())
	tracing.EndServer(serverSpan, http.StatusOK)

	resp := doGet(t, gotCtx, tracing.Client(c), srv.URL+"/obj")
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, []string{""}, srv.received(), "no traceparent may be sent while tracing is disabled")

	assert.Nil(t, tracing.LogFields(gotCtx))
	assert.Empty(t, tracing.TraceID(gotCtx))
	assert.NoError(t, tracing.Flush(ctx))
	assert.NoError(t, tracing.Shutdown(ctx))
	tracing.OfferEndpoint("http://127.0.0.1:1") // ignored, must not panic
}

func TestStartRecordsWithServiceResource(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceDirector))
	require.True(t, tracing.Enabled())

	ctx, span := tracing.Start(context.Background(), "director.redirect",
		trace.WithAttributes(tracing.JobID("job-1")))
	require.True(t, span.IsRecording())
	fields := tracing.LogFields(ctx)
	require.NotNil(t, fields)
	assert.Equal(t, span.SpanContext().TraceID().String(), fields["trace_id"])
	assert.Equal(t, span.SpanContext().SpanID().String(), fields["span_id"])
	assert.Equal(t, span.SpanContext().TraceID().String(), tracing.TraceID(ctx))
	span.End()

	stub := tracingtest.RequireSpan(t, exporter, "director.redirect")
	assert.Equal(t, string(tracing.ServiceDirector), tracingtest.ServiceName(stub))
	assert.Equal(t, "job-1", tracingtest.Attributes(stub)["pelican.job_id"])
	res := tracingtest.ResourceAttributes(stub)
	assert.Equal(t, config.GetVersion(), res["service.version"])
	assert.NotEmpty(t, res["host.name"])
	assert.Equal(t, res["host.name"], res["service.instance.id"])
}

func TestServiceInheritance(t *testing.T) {
	exporter := tracingtest.Setup(t) // default service: client

	// A span under a cache span is reported as the cache, even though it is
	// started by code (the client package) that does not know about the cache.
	cacheCtx, cacheSpan := tracing.StartWithService(context.Background(), tracing.ServiceCache, "cache.fetch_origin")
	childCtx, child := tracing.Start(cacheCtx, "client.transfer")
	_, grandchild := tracing.Start(childCtx, "client.download_object")
	grandchild.End()
	child.End()
	cacheSpan.End()

	// With no span in the context, the process default is used.
	_, root := tracing.Start(context.Background(), "client.transfer.root")
	root.End()

	cache := tracingtest.RequireSpan(t, exporter, "cache.fetch_origin")
	transfer := tracingtest.RequireSpan(t, exporter, "client.transfer")
	download := tracingtest.RequireSpan(t, exporter, "client.download_object")
	assert.Equal(t, string(tracing.ServiceCache), tracingtest.ServiceName(cache))
	assert.Equal(t, string(tracing.ServiceCache), tracingtest.ServiceName(transfer))
	assert.Equal(t, string(tracing.ServiceCache), tracingtest.ServiceName(download))
	tracingtest.RequireParent(t, cache, transfer)
	tracingtest.RequireParent(t, transfer, download)

	other := tracingtest.RequireSpan(t, exporter, "client.transfer.root")
	assert.Equal(t, string(tracing.ServiceClient), tracingtest.ServiceName(other))
	assert.False(t, other.Parent.IsValid())
}

func TestStartServerJoinsIncomingTrace(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceServer))

	req := httptest.NewRequest(http.MethodGet, "https://origin.example.org:8443/ns/obj?authz=secret-token&x=1", nil)
	req.Header.Set("traceparent", sampledParent)
	req.Header.Set("User-Agent", "pelican-client/7.0.0")
	req.Header.Set("Authorization", "Bearer secret-token")

	gotReq, span := tracing.StartServer(req, tracing.ServiceOrigin, "origin.serve_object")
	require.NotSame(t, req, gotReq)
	require.True(t, span.IsRecording())
	assert.Equal(t, span.SpanContext(), trace.SpanContextFromContext(gotReq.Context()))

	// A span started under the server span inherits its service.
	_, child := tracing.Start(gotReq.Context(), "origin.read")
	child.End()
	tracing.EndServer(span, http.StatusPartialContent)

	stub := tracingtest.RequireSpan(t, exporter, "origin.serve_object")
	assert.Equal(t, trace.SpanKindServer, stub.SpanKind)
	assert.Equal(t, incomingTraceID, stub.SpanContext.TraceID().String())
	assert.Equal(t, incomingSpanID, stub.Parent.SpanID().String())
	assert.True(t, stub.Parent.IsRemote())
	assert.Equal(t, string(tracing.ServiceOrigin), tracingtest.ServiceName(stub))
	assert.Equal(t, codes.Unset, stub.Status.Code)

	attrs := tracingtest.Attributes(stub)
	assert.Equal(t, "GET", attrs["http.request.method"])
	assert.Equal(t, "/ns/obj", attrs["url.path"])
	assert.Equal(t, "https", attrs["url.scheme"])
	assert.Equal(t, "origin.example.org", attrs["server.address"])
	assert.Equal(t, int64(8443), attrs["server.port"])
	assert.Equal(t, "pelican-client/7.0.0", attrs["user_agent.original"])
	assert.Equal(t, int64(http.StatusPartialContent), attrs["http.response.status_code"])
	for k, v := range attrs {
		if s, ok := v.(string); ok {
			assert.NotContains(t, s, "secret-token", "attribute %s leaks the token", k)
			assert.NotContains(t, s, "x=1", "attribute %s records the query", k)
		}
	}

	child2 := tracingtest.RequireSpan(t, exporter, "origin.read")
	assert.Equal(t, string(tracing.ServiceOrigin), tracingtest.ServiceName(child2))
	tracingtest.RequireParent(t, stub, child2)
}

func TestEndServerStatus(t *testing.T) {
	exporter := tracingtest.Setup(t)

	for _, tc := range []struct {
		status int
		code   codes.Code
	}{
		{http.StatusOK, codes.Unset},
		{http.StatusNotFound, codes.Unset},
		{http.StatusForbidden, codes.Unset},
		{http.StatusInternalServerError, codes.Error},
		{http.StatusBadGateway, codes.Error},
	} {
		exporter.Reset()
		req := httptest.NewRequest(http.MethodGet, "/obj", nil)
		_, span := tracing.StartServer(req, tracing.ServiceCache, "cache.serve_object")
		tracing.EndServer(span, tc.status)
		stub := tracingtest.RequireSpan(t, exporter, "cache.serve_object")
		assert.Equal(t, tc.code, stub.Status.Code, "status %d", tc.status)
		assert.False(t, stub.Parent.IsValid())
	}
}

func TestSamplerIgnoresRemoteSampledFlag(t *testing.T) {
	t.Run("untrusted", func(t *testing.T) {
		exporter := tracingtest.Setup(t, tracingtest.WithSamplePercentage(0))
		req := httptest.NewRequest(http.MethodGet, "/obj", nil)
		req.Header.Set("traceparent", sampledParent)
		gotReq, span := tracing.StartServer(req, tracing.ServiceDirector, "director.redirect")
		assert.False(t, span.IsRecording())
		// The trace still propagates so downstream services and logs share it.
		assert.Equal(t, incomingTraceID, tracing.TraceID(gotReq.Context()))
		tracing.EndServer(span, http.StatusTemporaryRedirect)
		tracingtest.RequireNoSpans(t, exporter)
	})

	t.Run("trusted", func(t *testing.T) {
		exporter := tracingtest.Setup(t, tracingtest.WithSamplePercentage(0), tracingtest.WithTrustRemoteSampling(true))
		req := httptest.NewRequest(http.MethodGet, "/obj", nil)
		req.Header.Set("traceparent", sampledParent)
		_, span := tracing.StartServer(req, tracing.ServiceDirector, "director.redirect")
		assert.True(t, span.IsRecording())
		tracing.EndServer(span, http.StatusTemporaryRedirect)
		tracingtest.RequireSpan(t, exporter, "director.redirect")
	})

	t.Run("local-root-at-zero", func(t *testing.T) {
		exporter := tracingtest.Setup(t, tracingtest.WithSamplePercentage(0))
		_, span := tracing.Start(context.Background(), "client.transfer")
		assert.False(t, span.IsRecording())
		span.End()
		tracingtest.RequireNoSpans(t, exporter)
	})
}

func TestClientRoundTrip(t *testing.T) {
	exporter := tracingtest.Setup(t)
	srv := newHeaderRecorder(t, http.StatusOK)
	base := srv.Client()
	c := tracing.Client(base)
	require.NotSame(t, base, c)
	assert.Equal(t, base.Timeout, c.Timeout)

	ctx, parent := tracing.Start(context.Background(), "client.attempt")
	target := strings.Replace(srv.URL, "http://", "http://user:pass@", 1) + "/ns/obj?authz=secret-token#frag"
	resp := doGet(t, ctx, c, target)

	// The span covers the body: it has not ended before the body is closed.
	assert.Empty(t, tracingtest.SpansNamed(exporter, "GET"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "hello, world", string(body))
	require.NoError(t, resp.Body.Close())
	parent.End()

	received := srv.received()
	require.Len(t, received, 1)
	assert.Contains(t, received[0], parent.SpanContext().TraceID().String())

	stub := tracingtest.RequireSpan(t, exporter, "GET")
	assert.Equal(t, trace.SpanKindClient, stub.SpanKind)
	tracingtest.RequireParent(t, tracingtest.RequireSpan(t, exporter, "client.attempt"), stub)
	// The traceparent sent names the client span as the parent.
	assert.Contains(t, received[0], stub.SpanContext.SpanID().String())

	attrs := tracingtest.Attributes(stub)
	assert.Equal(t, srv.URL+"/ns/obj", attrs["url.full"])
	assert.Equal(t, "GET", attrs["http.request.method"])
	assert.Equal(t, "127.0.0.1", attrs["server.address"])
	assert.NotZero(t, attrs["server.port"])
	assert.Equal(t, int64(http.StatusOK), attrs["http.response.status_code"])
	assert.Equal(t, codes.Unset, stub.Status.Code)
}

func TestClientSpanEndsAtEOF(t *testing.T) {
	exporter := tracingtest.Setup(t)
	srv := newHeaderRecorder(t, http.StatusNotFound)
	ctx, parent := tracing.Start(context.Background(), "parent")
	defer parent.End()

	resp := doGet(t, ctx, tracing.Client(srv.Client()), srv.URL+"/missing")
	_, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	// Reading to EOF ends the span before Close.
	stub := tracingtest.RequireSpan(t, exporter, "GET")
	assert.Equal(t, codes.Error, stub.Status.Code)
	assert.Equal(t, int64(http.StatusNotFound), tracingtest.Attributes(stub)["http.response.status_code"])
	require.NoError(t, resp.Body.Close())
	assert.Len(t, tracingtest.SpansNamed(exporter, "GET"), 1, "the span must end exactly once")
}

func TestClientWithoutSpanIsUntouched(t *testing.T) {
	exporter := tracingtest.Setup(t)
	srv := newHeaderRecorder(t, http.StatusOK)

	resp := doGet(t, context.Background(), tracing.Client(srv.Client()), srv.URL+"/obj")
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())

	require.Equal(t, []string{""}, srv.received())
	tracingtest.RequireNoSpans(t, exporter)
}

func TestClientNilTransport(t *testing.T) {
	tracingtest.Setup(t)
	c := tracing.Client(&http.Client{Timeout: time.Minute})
	require.NotNil(t, c.Transport)
	assert.Equal(t, time.Minute, c.Timeout)
	// Wrapping twice does not double-wrap.
	assert.Equal(t, c.Transport, tracing.Transport(c.Transport))
	assert.Nil(t, tracing.Client(nil))
}

func TestClientTransportError(t *testing.T) {
	exporter := tracingtest.Setup(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL + "/obj?access_token=secret-token"
	srv.Close()

	ctx, parent := tracing.Start(context.Background(), "parent")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)
	_, err = tracing.Client(&http.Client{}).Do(req)
	require.Error(t, err)
	parent.End()

	stub := tracingtest.RequireSpan(t, exporter, "GET")
	assert.Equal(t, codes.Error, stub.Status.Code)
	assert.NotContains(t, stub.Status.Description, "secret-token")
	require.Len(t, stub.Events, 1)
	assert.Equal(t, "exception", stub.Events[0].Name)
	assert.NotEmpty(t, tracingtest.Attributes(stub)["error.type"])
}

func TestCarrySpan(t *testing.T) {
	tracingtest.Setup(t)

	src, cancel := context.WithCancel(context.Background())
	src, span := tracing.Start(src, "request")
	defer span.End()

	dst := tracing.CarrySpan(context.Background(), src)
	cancel()
	assert.Error(t, src.Err())
	assert.NoError(t, dst.Err(), "cancellation must not be carried")
	assert.Equal(t, span.SpanContext(), trace.SpanContextFromContext(dst))

	// Without a span in src, dst comes back unchanged.
	plain := context.WithValue(context.Background(), struct{}{}, "v")
	assert.Equal(t, plain, tracing.CarrySpan(plain, context.Background()))
}

func TestScrub(t *testing.T) {
	jwt := "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl"
	for _, tc := range []struct {
		in, want string
	}{
		{"Authorization: Bearer abc.def-ghi", "Authorization: Bearer REDACTED"},
		{"header was bearer%20abc123&x=1", "header was bearer%20REDACTED&x=1"},
		{"GET https://h/ns/obj?authz=abc123&x=1: 403", "GET https://h/ns/obj?authz=REDACTED&x=1: 403"},
		{"GET https://h/ns/obj?x=1&access_token=abc123", "GET https://h/ns/obj?x=1&access_token=REDACTED"},
		{"form body token=abc123", "form body token=REDACTED"},
		{"?AUTHZ=abc", "?AUTHZ=REDACTED"},
		{"my_token=keep", "my_token=keep"},
		{"token " + jwt + " leaked", "token REDACTED leaked"},
		{"nothing to scrub here", "nothing to scrub here"},
		// Opaque tokens in the shapes that are not query parameters.
		{`{"access_token":"abc123"}`, `{"access_token":"REDACTED"}`},
		{`{"access_token": "abc123", "x": 1}`, `{"access_token": "REDACTED", "x": 1}`},
		{"failed (authz=abc123)", "failed (authz=REDACTED)"},
		{"a=1,authz=abc123,b=2", "a=1,authz=REDACTED,b=2"},
		{"Authorization: Basic abc123", "Authorization: Basic REDACTED"},
		{`{"token" : "abc123"}`, `{"token" : "REDACTED"}`},
		{"client_secret=abc123&id_token=abc123", "client_secret=REDACTED&id_token=REDACTED"},
		// Prose that mentions a token, the way wrapped errors do, is kept.
		{"failed to get token: open /tmp/x: no such file or directory", "failed to get token: open /tmp/x: no such file or directory"},
		{"nonbasic authentication is not supported", "nonbasic authentication is not supported"},
		{"map[Authorization:[Bearer abc123]]", "map[Authorization:[Bearer REDACTED]]"},
		{"Failed to parse token: token is malformed", "Failed to parse token: token is malformed"},
		{"?scitoken=abc123", "?scitoken=REDACTED"},
		{"?bearer_token=abc123&x=1", "?bearer_token=REDACTED&x=1"},
		{"refresh_token=abc123", "refresh_token=REDACTED"},
		{"redirect=https%3A%2F%2Fh%2Fobj%3Fauthz%3Dabc123%26x%3D1", "redirect=https%3A%2F%2Fh%2Fobj%3Fauthz%3DREDACTED%26x%3D1"},
	} {
		got := tracing.Scrub(tc.in)
		assert.Equal(t, tc.want, got, "Scrub(%q)", tc.in)
		assert.NotContains(t, got, "abc123")
	}
}

func TestRecordError(t *testing.T) {
	exporter := tracingtest.Setup(t)

	// Nil errors and non-recording spans are ignored.
	tracing.RecordError(trace.SpanFromContext(context.Background()), errors.New("x"))
	_, span := tracing.Start(context.Background(), "op")
	tracing.RecordError(span, nil)
	tracing.RecordError(span, errors.Wrap(errors.New("Bearer secret-token rejected"), "GET https://h/obj?authz=secret-token"))
	span.End()

	stub := tracingtest.RequireSpan(t, exporter, "op")
	assert.Equal(t, codes.Error, stub.Status.Code)
	assert.NotContains(t, stub.Status.Description, "secret-token")
	assert.Contains(t, stub.Status.Description, "authz=REDACTED")
	require.Len(t, stub.Events, 1)
	for _, kv := range stub.Events[0].Attributes {
		assert.NotContains(t, kv.Value.Emit(), "secret-token")
	}
	// The type is the underlying error's, not the wrapper's.
	assert.Equal(t, "*errors.fundamental", tracingtest.Attributes(stub)["error.type"])
}

func TestNoteErrorLeavesStatusAlone(t *testing.T) {
	exporter := tracingtest.Setup(t)

	req := httptest.NewRequest(http.MethodGet, "/ns/obj", nil)
	_, span := tracing.StartServer(req, tracing.ServiceOrigin, "server")
	tracing.NoteError(span, nil)
	tracing.NoteError(span, errors.New("no such object; Bearer secret-token"))
	tracing.EndServer(span, http.StatusNotFound)

	stub := tracingtest.RequireSpan(t, exporter, "server")
	assert.Equal(t, codes.Unset, stub.Status.Code, "a 4xx is the client's error")
	require.Len(t, stub.Events, 1)
	assert.Equal(t, "exception", stub.Events[0].Name)
	for _, kv := range stub.Events[0].Attributes {
		assert.NotContains(t, kv.Value.Emit(), "secret-token")
	}
	assert.Equal(t, "*errors.fundamental", tracingtest.Attributes(stub)["error.type"])
}

func TestStartChildNeverStartsATrace(t *testing.T) {
	exporter := tracingtest.Setup(t)

	ctx, span := tracing.StartChild(context.Background(), "orphan")
	assert.Equal(t, context.Background(), ctx)
	assert.False(t, span.SpanContext().IsValid())
	span.End()
	tracingtest.RequireNoSpans(t, exporter)

	parentCtx, parent := tracing.StartWithService(context.Background(), tracing.ServiceCache, "parent")
	_, child := tracing.StartChild(parentCtx, "child")
	child.End()
	parent.End()
	childStub := tracingtest.RequireSpan(t, exporter, "child")
	tracingtest.RequireParent(t, tracingtest.RequireSpan(t, exporter, "parent"), childStub)
	assert.Equal(t, string(tracing.ServiceCache), tracingtest.ServiceName(childStub))

	assert.False(t, tracing.NoopSpan().IsRecording())
}

func TestDefaultService(t *testing.T) {
	tracingtest.Disabled(t)
	assert.Equal(t, tracing.Service(""), tracing.DefaultService())

	tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceCache))
	assert.Equal(t, tracing.ServiceCache, tracing.DefaultService())
}

func TestIsDownloadMethod(t *testing.T) {
	assert.True(t, tracing.IsDownloadMethod(http.MethodGet))
	assert.True(t, tracing.IsDownloadMethod(http.MethodHead))
	for _, m := range []string{http.MethodPut, http.MethodDelete, http.MethodOptions, "PROPFIND", "COPY", ""} {
		assert.False(t, tracing.IsDownloadMethod(m), m)
	}
}

func TestLogFieldsOnlyForRecordedTraces(t *testing.T) {
	tracingtest.Setup(t, tracingtest.WithSamplePercentage(0))
	ctx, span := tracing.Start(context.Background(), "sampled-out")
	defer span.End()
	require.True(t, span.SpanContext().IsValid())
	assert.Nil(t, tracing.LogFields(ctx), "a trace that is not exported gets no log fields")

	entry := log.NewEntry(log.New())
	assert.Same(t, entry, tracing.WithLogFields(entry, ctx))

	tracingtest.Setup(t)
	ctx, recorded := tracing.Start(context.Background(), "recorded")
	defer recorded.End()
	withFields := tracing.WithLogFields(entry, ctx)
	assert.Equal(t, recorded.SpanContext().TraceID().String(), withFields.Data["trace_id"])
	assert.Equal(t, recorded.SpanContext().SpanID().String(), withFields.Data["span_id"])
}

// A stop function shuts down the configuration it came from and nothing
// else, so a server that exits late cannot turn off a newer configuration.
func TestStopOnlyStopsItsOwnConfiguration(t *testing.T) {
	first, err := tracing.Configure(tracing.Options{Exporter: tracetest.NewInMemoryExporter(), Synchronous: true, SampleRatio: 1})
	require.NoError(t, err)
	exporter := tracingtest.Setup(t)

	require.NoError(t, first(context.Background()))
	require.True(t, tracing.Enabled(), "stopping a replaced configuration leaves the current one running")
	_, span := tracing.Start(context.Background(), "after-stale-stop")
	span.End()
	tracingtest.RequireSpan(t, exporter, "after-stale-stop")
}

// Over HTTP/1 Go hands back http.NoBody for a HEAD or a 304, which ends the
// span by itself.  Over HTTP/2 the body is an ordinary reader, so this test
// uses HTTP/2: it is the case the method and status checks exist for.
func TestClientSpanForBodylessResponseEndsAtOnce(t *testing.T) {
	exporter := tracingtest.Setup(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotModified)
		}
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	ctx, parent := tracing.Start(context.Background(), "parent")
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		req, err := http.NewRequestWithContext(ctx, method, srv.URL+"/obj", nil)
		require.NoError(t, err)
		resp, err := tracing.Client(srv.Client()).Do(req)
		require.NoError(t, err)
		require.Equal(t, 2, resp.ProtoMajor, "the test must run over HTTP/2")
		require.NotEqual(t, http.NoBody, resp.Body, "over HTTP/2 the body is not http.NoBody")
		// The span has ended although the body has not been closed yet.
		tracingtest.RequireSpan(t, exporter, method)
		require.NoError(t, resp.Body.Close())
	}
	parent.End()
}

func TestInitNoopWhenDisabled(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(config.ResetConfig)
	exporter := tracingtest.Setup(t)

	stop, err := tracing.Init(context.Background(), tracing.ServiceDirector)
	require.NoError(t, err)
	require.Nil(t, stop, "a disabled Init installs nothing, so there is nothing to stop")
	require.True(t, tracing.Enabled())

	_, span := tracing.Start(context.Background(), "still-test-state")
	span.End()
	stub := tracingtest.RequireSpan(t, exporter, "still-test-state")
	assert.Equal(t, string(tracing.ServiceClient), tracingtest.ServiceName(stub))
}

// otlpCollector counts OTLP/HTTP trace exports.
func otlpCollector(t *testing.T) (*httptest.Server, *atomic.Int32) {
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/traces" {
			posts.Add(1)
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, &posts
}

func initEnabled(t *testing.T, params map[param.Param]any) {
	config.ResetConfig()
	t.Cleanup(config.ResetConfig)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	require.NoError(t, param.Set(param.Tracing_Enabled, true))
	// ResetConfig clears the generated defaults, so set the 100% default here.
	require.NoError(t, param.Set(param.Tracing_SamplePercentage, 100))
	for p, v := range params {
		require.NoError(t, param.Set(p, v))
	}
	stop, err := tracing.Init(context.Background(), tracing.ServiceServer)
	require.NoError(t, err)
	require.NotNil(t, stop)
	require.True(t, tracing.Enabled())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = stop(ctx)
	})
}

func TestInitWithEndpoint(t *testing.T) {
	collector, posts := otlpCollector(t)
	initEnabled(t, map[param.Param]any{param.Tracing_Endpoint: collector.URL})

	_, span := tracing.Start(context.Background(), "exported")
	span.End()
	require.NoError(t, tracing.Flush(context.Background()))
	assert.Equal(t, int32(1), posts.Load())

	// Offers are ignored when an endpoint was configured.
	other, otherPosts := otlpCollector(t)
	tracing.OfferEndpoint(other.URL)
	_, span = tracing.Start(context.Background(), "exported-again")
	span.End()
	require.NoError(t, tracing.Flush(context.Background()))
	assert.Equal(t, int32(2), posts.Load())
	assert.Zero(t, otherPosts.Load())

	require.NoError(t, tracing.Shutdown(context.Background()))
	assert.False(t, tracing.Enabled())
}

func TestDeferredEndpoint(t *testing.T) {
	initEnabled(t, nil)

	_, span := tracing.Start(context.Background(), "before-endpoint")
	span.End()
	// Flushing with no endpoint holds the span and does not fail.
	require.NoError(t, tracing.Flush(context.Background()))

	first, firstPosts := otlpCollector(t)
	second, secondPosts := otlpCollector(t)
	tracing.OfferEndpoint("")
	tracing.OfferEndpoint(first.URL)
	tracing.OfferEndpoint(second.URL) // only the first offer counts

	// The held span is delivered once the endpoint is known.
	require.Eventually(t, func() bool { return firstPosts.Load() >= 1 }, 10*time.Second, 10*time.Millisecond)

	// Later spans go straight to the first endpoint.
	before := firstPosts.Load()
	_, span = tracing.Start(context.Background(), "after-endpoint")
	span.End()
	require.NoError(t, tracing.Flush(context.Background()))
	require.Eventually(t, func() bool { return firstPosts.Load() > before }, 10*time.Second, 10*time.Millisecond)
	assert.Zero(t, secondPosts.Load())
}

func TestDeferredEndpointFromLocalFederationParam(t *testing.T) {
	collector, posts := otlpCollector(t)
	initEnabled(t, map[param.Param]any{param.Federation_TracingEndpoint: collector.URL})

	_, span := tracing.Start(context.Background(), "exported")
	span.End()
	require.NoError(t, tracing.Flush(context.Background()))
	assert.Equal(t, int32(1), posts.Load())
}

func TestShutdownWithoutEndpointIsQuick(t *testing.T) {
	initEnabled(t, nil)

	for i := 0; i < 10; i++ {
		_, span := tracing.Start(context.Background(), "never-exported")
		span.End()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	require.NoError(t, tracing.Shutdown(ctx))
	assert.Less(t, time.Since(start), 2*time.Second)
	assert.False(t, tracing.Enabled())
}

func TestInitClampsSamplePercentage(t *testing.T) {
	initEnabled(t, map[param.Param]any{param.Tracing_SamplePercentage: 250})
	_, span := tracing.Start(context.Background(), "sampled")
	assert.True(t, span.IsRecording())
	span.End()

	initEnabled(t, map[param.Param]any{param.Tracing_SamplePercentage: -5})
	_, span = tracing.Start(context.Background(), "unsampled")
	assert.False(t, span.IsRecording())
	span.End()
}

func TestEndServerDeferred(t *testing.T) {
	exporter := tracingtest.Setup(t)
	newSpan := func(name string) trace.Span {
		_, span := tracing.StartServer(httptest.NewRequest(http.MethodGet, "/ns/obj", nil), tracing.ServiceOrigin, name)
		return span
	}

	// A normal return records the status the handler reports.
	func() {
		span := newSpan("normal")
		defer tracing.EndServerDeferred(span, fixedStatus(http.StatusNotFound))
	}()
	stub := tracingtest.RequireSpan(t, exporter, "normal")
	assert.EqualValues(t, http.StatusNotFound, tracingtest.Attributes(stub)["http.response.status_code"])
	assert.Equal(t, codes.Unset, stub.Status.Code)

	// A status of 0 means the writer cannot say: nothing is recorded.
	func() {
		span := newSpan("unknown-status")
		defer tracing.EndServerDeferred(span, fixedStatus(0))
	}()
	stub = tracingtest.RequireSpan(t, exporter, "unknown-status")
	assert.NotContains(t, tracingtest.Attributes(stub), "http.response.status_code")
	assert.Equal(t, codes.Unset, stub.Status.Code)

	// A panic ends the span as a 500, whatever the writer says, and carries
	// on with its original value.
	boom := errors.New("boom")
	require.PanicsWithValue(t, boom, func() {
		span := newSpan("panicking")
		defer tracing.EndServerDeferred(span, fixedStatus(http.StatusOK))
		panic(boom)
	})
	stub = tracingtest.RequireSpan(t, exporter, "panicking")
	assert.EqualValues(t, http.StatusInternalServerError, tracingtest.Attributes(stub)["http.response.status_code"])
	assert.Equal(t, codes.Error, stub.Status.Code)

	// A request that is not traced is left entirely alone, panic included:
	// the writer is not even asked for its status.
	require.PanicsWithValue(t, boom, func() {
		defer tracing.EndServerDeferred(tracing.NoopSpan(), nil)
		panic(boom)
	})
	func() {
		defer tracing.EndServerDeferred(tracing.NoopSpan(), nil)
	}()
}

// fixedStatus is a tracing.StatusReporter that reports one status.
type fixedStatus int

func (s fixedStatus) Status() int { return int(s) }
