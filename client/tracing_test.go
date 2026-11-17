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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/tracing"
	"github.com/pelicanplatform/pelican/tracing/tracingtest"
)

const tracedFedContents = "tracing test object contents"

// tracedFed is a federation for tracing tests: one TLS server answering
// discovery, the director, stat and the object server, and optionally a
// second object server that answers probes but fails every download.  It
// records the traceparent header of every request, by the role the request
// played.
type tracedFed struct {
	url     string
	failURL string

	mu           sync.Mutex
	traceparents map[string][]string
}

type tracedFedOptions struct {
	requireToken bool
	// failFirst lists a failing object server ahead of the working one.
	failFirst bool
	// hangUp makes the failing object server drop the connection on a
	// download instead of answering 500, so that the client's error quotes
	// the request URL.
	hangUp bool
}

func (f *tracedFed) record(role string, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.traceparents[role] = append(f.traceparents[role], r.Header.Get("traceparent"))
}

// headers returns the traceparent values recorded for role.
func (f *tracedFed) headers(role string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.traceparents[role]...)
}

// all returns every traceparent value recorded, by role.
func (f *tracedFed) all() map[string][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string][]string, len(f.traceparents))
	for k, v := range f.traceparents {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// isProbe reports whether r is the client's endpoint probe (objectCached).
func isProbe(r *http.Request) bool {
	return r.Method == http.MethodGet && r.Header.Get("Range") == "bytes=0-0"
}

func writeProbeResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-0/%d", len(tracedFedContents)))
	w.Header().Set("Content-Length", "1")
	w.WriteHeader(http.StatusPartialContent)
	_, _ = w.Write([]byte(tracedFedContents[:1]))
}

func newTracedFed(t *testing.T, opts tracedFedOptions) *tracedFed {
	t.Helper()
	f := &tracedFed{traceparents: make(map[string][]string)}

	if opts.failFirst {
		fail := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isProbe(r) {
				f.record("fail-probe", r)
				writeProbeResponse(w)
				return
			}
			f.record("fail-"+strings.ToLower(r.Method), r)
			if opts.hangUp {
				if conn, _, err := http.NewResponseController(w).Hijack(); err == nil {
					_ = conn.Close()
					return
				}
			}
			w.WriteHeader(http.StatusInternalServerError)
		}))
		t.Cleanup(fail.Close)
		f.failURL = fail.URL
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		self := "https://" + r.Host
		switch {
		case r.URL.Path == "/.well-known/pelican-configuration":
			f.record("discovery", r)
			_, _ = fmt.Fprintf(w, `{"director_endpoint": "%s"}`, self)

		case r.Method == "PROPFIND":
			f.record("propfind", r)
			w.Header().Set("Content-Type", "application/xml; charset=utf-8")
			w.WriteHeader(http.StatusMultiStatus)
			_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>%s</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype/>
        <D:getcontentlength>%d</D:getcontentlength>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>
`, r.URL.Path, len(tracedFedContents))

		case strings.HasPrefix(r.URL.Path, "/download/"):
			if isProbe(r) {
				f.record("probe", r)
				writeProbeResponse(w)
				return
			}
			w.Header().Set("Content-Length", fmt.Sprint(len(tracedFedContents)))
			if r.Method == http.MethodHead {
				f.record("checksum", r)
				w.WriteHeader(http.StatusOK)
				return
			}
			f.record("download", r)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(tracedFedContents))

		case strings.HasPrefix(r.URL.Path, "/test/"):
			f.record("director", r)
			links := []string{}
			if f.failURL != "" {
				links = append(links, fmt.Sprintf(`<%s/download%s>; rel="duplicate"; pri=1; depth=1`, f.failURL, r.URL.Path))
			}
			links = append(links, fmt.Sprintf(`<%s/download%s>; rel="duplicate"; pri=2; depth=1`, self, r.URL.Path))
			w.Header().Set("Link", strings.Join(links, ", "))
			w.Header().Set("Location", self+"/download"+r.URL.Path)
			w.Header().Set("X-Pelican-Namespace", fmt.Sprintf("namespace=/test, require-token=%t", opts.requireToken))
			w.WriteHeader(http.StatusTemporaryRedirect)

		default:
			t.Errorf("traced federation received an unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	f.url = srv.URL

	// Discovery results are cached process-wide; start from nothing so that
	// discovery is exercised.
	pelican_url.ResetState()
	t.Cleanup(pelican_url.ResetState)
	test_utils.InitClient(t, map[param.Param]any{param.TLSSkipVerify: true})
	return f
}

// objectURL returns the pelican:// URL of the object at objectPath.
func (f *tracedFed) objectURL(t *testing.T, objectPath string) *url.URL {
	t.Helper()
	u, err := url.Parse(f.url)
	require.NoError(t, err)
	remote, err := url.Parse("pelican://" + u.Host + objectPath)
	require.NoError(t, err)
	return remote
}

// download runs one download job through a fresh engine, the way the object
// commands do, and returns its results once the engine has retired the job.
func (f *tracedFed) download(t *testing.T, ctx context.Context, objectPath string, options ...TransferOption) []TransferResults {
	t.Helper()
	te, err := NewTransferEngine(ctx)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, te.Shutdown())
	}()
	tc, err := te.NewClient(options...)
	require.NoError(t, err)
	dest := filepath.Join(t.TempDir(), "object")
	tj, err := tc.NewTransferJob(ctx, f.objectURL(t, objectPath), dest, false, false)
	require.NoError(t, err)
	require.NoError(t, tc.Submit(tj))
	results, err := tc.Shutdown()
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	require.Equal(t, tracedFedContents, string(got))
	return results
}

// childrenOf returns the spans whose parent is parent, optionally only those
// named name.
func childrenOf(exporter *tracetest.InMemoryExporter, parent tracetest.SpanStub, name string) []tracetest.SpanStub {
	var found []tracetest.SpanStub
	for _, s := range exporter.GetSpans() {
		if s.Parent.SpanID() == parent.SpanContext.SpanID() && (name == "" || s.Name == name) {
			found = append(found, s)
		}
	}
	return found
}

// requireChild returns the single child of parent named name.
func requireChild(t *testing.T, exporter *tracetest.InMemoryExporter, parent tracetest.SpanStub, name string) tracetest.SpanStub {
	t.Helper()
	found := childrenOf(exporter, parent, name)
	require.Lenf(t, found, 1, "expected one %q child of %q; recorded spans: %v", name, parent.Name, tracingtest.Names(exporter))
	return found[0]
}

// traceIDOf returns the trace ID in a traceparent header value.
func traceIDOf(t *testing.T, traceparent string) string {
	t.Helper()
	parts := strings.Split(traceparent, "-")
	require.Lenf(t, parts, 4, "malformed traceparent %q", traceparent)
	return parts[1]
}

func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return ctx
}

func TestTracingDownloadSpanTree(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	exporter := tracingtest.Setup(t)
	fed := newTracedFed(t, tracedFedOptions{})
	ctx := testContext(t)

	results := fed.download(t, ctx, "/test/object.txt", WithAcquireToken(false))

	root := tracingtest.RequireSpan(t, exporter, spanTransfer)
	assert.False(t, root.Parent.IsValid(), "client.transfer must be the root here")
	rootAttrs := tracingtest.Attributes(root)
	assert.Equal(t, "/test/object.txt", rootAttrs["pelican.object.path"])
	assert.Equal(t, "/test", rootAttrs["pelican.namespace"])
	assert.Equal(t, false, rootAttrs["pelican.transfer.recursive"])
	assert.Equal(t, int64(1), rootAttrs["pelican.transfer.objects"])
	assert.Contains(t, rootAttrs["pelican.federation"], strings.TrimPrefix(fed.url, "https://"))
	assert.Equal(t, codes.Unset, root.Status.Code)

	discover := requireChild(t, exporter, root, spanDiscoverFed)
	requireChild(t, exporter, discover, http.MethodGet)

	director := requireChild(t, exporter, root, spanQueryDirector)
	directorAttrs := tracingtest.Attributes(director)
	assert.Equal(t, false, directorAttrs["pelican.director.with_token"])
	assert.Equal(t, strings.TrimPrefix(fed.url, "https://"), directorAttrs["pelican.director.endpoint"])
	requireChild(t, exporter, director, http.MethodGet)

	object := requireChild(t, exporter, root, spanDownloadObject)
	objectAttrs := tracingtest.Attributes(object)
	assert.Equal(t, "/test/object.txt", objectAttrs["pelican.object.path"])
	assert.Equal(t, int64(len(tracedFedContents)), objectAttrs["pelican.transfer.bytes"])
	assert.Equal(t, results[0].TransferredBytes, objectAttrs["pelican.transfer.bytes"])
	assert.Equal(t, int64(1), objectAttrs["pelican.transfer.attempts"])

	sorter := requireChild(t, exporter, object, spanSortAttempts)
	assert.Equal(t, int64(1), tracingtest.Attributes(sorter)["pelican.attempt.candidates"])

	attempt := requireChild(t, exporter, object, spanAttempt)
	attemptAttrs := tracingtest.Attributes(attempt)
	assert.Equal(t, int64(0), attemptAttrs["pelican.attempt.number"])
	assert.Equal(t, strings.TrimPrefix(fed.url, "https://"), attemptAttrs["pelican.attempt.endpoint"])
	assert.Equal(t, int64(len(tracedFedContents)), attemptAttrs["pelican.attempt.bytes"])
	ttfb, ok := attemptAttrs["pelican.attempt.time_to_first_byte_ms"].(float64)
	require.True(t, ok, "time to first byte missing from the attempt: %v", attemptAttrs)
	assert.Greater(t, ttfb, 0.0)
	assert.NotContains(t, attemptAttrs, "pelican.attempt.retryable")
	assert.Equal(t, codes.Unset, attempt.Status.Code)
	get := requireChild(t, exporter, attempt, http.MethodGet)
	assert.Equal(t, int64(http.StatusOK), tracingtest.Attributes(get)["http.response.status_code"])

	checksum := requireChild(t, exporter, object, spanVerifyChecksum)
	requireChild(t, exporter, checksum, http.MethodHead)

	// One trace, one service.
	for _, s := range exporter.GetSpans() {
		assert.Equal(t, root.SpanContext.TraceID(), s.SpanContext.TraceID(), "span %q is in another trace", s.Name)
		assert.Equal(t, string(tracing.ServiceClient), tracingtest.ServiceName(s), "span %q", s.Name)
	}

	// The servers saw the same trace.
	rootTraceID := root.SpanContext.TraceID().String()
	for _, role := range []string{"discovery", "director", "download", "checksum"} {
		headers := fed.headers(role)
		require.NotEmpty(t, headers, "no %s request was made", role)
		for _, h := range headers {
			require.NotEmpty(t, h, "the %s request carried no traceparent", role)
			assert.Equal(t, rootTraceID, traceIDOf(t, h), "the %s request is in another trace", role)
		}
	}
	// The download's traceparent names its own client span, so the server
	// span hangs under the attempt.
	assert.Contains(t, fed.headers("download")[0], get.SpanContext.SpanID().String())
}

func TestTracingFailedAttemptThenSuccess(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	exporter := tracingtest.Setup(t)
	fed := newTracedFed(t, tracedFedOptions{failFirst: true})
	ctx := testContext(t)

	results := fed.download(t, ctx, "/test/object.txt", WithAcquireToken(false))
	require.Len(t, results[0].Attempts, 2)

	object := tracingtest.RequireSpan(t, exporter, spanDownloadObject)
	assert.Equal(t, int64(2), tracingtest.Attributes(object)["pelican.transfer.attempts"])
	assert.Equal(t, codes.Unset, object.Status.Code)

	sorter := requireChild(t, exporter, object, spanSortAttempts)
	assert.Equal(t, int64(2), tracingtest.Attributes(sorter)["pelican.attempt.candidates"])
	// The probe of the second endpoint may be cancelled before it is sent
	// once the first answers, so only the first is certain.
	require.NotEmpty(t, childrenOf(exporter, sorter, http.MethodGet), "the endpoints are probed")

	attempts := childrenOf(exporter, object, spanAttempt)
	require.Len(t, attempts, 2)
	byNumber := map[int64]tracetest.SpanStub{}
	for _, a := range attempts {
		byNumber[tracingtest.Attributes(a)["pelican.attempt.number"].(int64)] = a
	}
	require.Contains(t, byNumber, int64(0))
	require.Contains(t, byNumber, int64(1))

	failed := byNumber[0]
	failedAttrs := tracingtest.Attributes(failed)
	assert.Equal(t, codes.Error, failed.Status.Code)
	assert.Equal(t, strings.TrimPrefix(fed.failURL, "https://"), failedAttrs["pelican.attempt.endpoint"])
	assert.Contains(t, failedAttrs, "pelican.attempt.retryable")
	assert.Equal(t, IsRetryable(results[0].Attempts[0].Error), failedAttrs["pelican.attempt.retryable"])
	assert.Equal(t, int64(0), failedAttrs["pelican.attempt.bytes"])
	failedGet := requireChild(t, exporter, failed, http.MethodGet)
	assert.Equal(t, int64(http.StatusInternalServerError), tracingtest.Attributes(failedGet)["http.response.status_code"])

	succeeded := byNumber[1]
	assert.Equal(t, codes.Unset, succeeded.Status.Code)
	assert.Equal(t, strings.TrimPrefix(fed.url, "https://"), tracingtest.Attributes(succeeded)["pelican.attempt.endpoint"])
	assert.NotContains(t, tracingtest.Attributes(succeeded), "pelican.attempt.retryable")
	assert.True(t, failed.EndTime.Before(succeeded.StartTime) || failed.EndTime.Equal(succeeded.StartTime),
		"the attempts are sequential")
}

func TestTracingServiceInheritedFromCaller(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	exporter := tracingtest.Setup(t)
	fed := newTracedFed(t, tracedFedOptions{})

	// The cache's contract: it hands NewTransferJob a context holding its own
	// span, and the client's spans join that trace under the cache's name.
	ctx, parent := tracing.StartWithService(testContext(t), tracing.ServiceCache, "cache.fetch_origin")
	fed.download(t, ctx, "/test/object.txt", WithAcquireToken(false))
	parent.End()

	parentStub := tracingtest.RequireSpan(t, exporter, "cache.fetch_origin")
	root := tracingtest.RequireSpan(t, exporter, spanTransfer)
	tracingtest.RequireParent(t, parentStub, root)

	for _, s := range exporter.GetSpans() {
		assert.Equal(t, parentStub.SpanContext.TraceID(), s.SpanContext.TraceID(), "span %q is in another trace", s.Name)
		assert.Equal(t, string(tracing.ServiceCache), tracingtest.ServiceName(s), "span %q", s.Name)
	}
	tracingtest.RequireSpan(t, exporter, spanDownloadObject)
	tracingtest.RequireSpan(t, exporter, spanAttempt)
}

func TestTracingDoGetUnderCallerSpan(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	exporter := tracingtest.Setup(t)
	fed := newTracedFed(t, tracedFedOptions{})

	ctx, caller := tracing.Start(testContext(t), "caller")
	// A directory destination makes PlanDownload stat the source.
	destDir := t.TempDir()
	results, err := DoGet(ctx, fed.objectURL(t, "/test/object.txt").String(), destDir, false, WithAcquireToken(false))
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
	caller.End()

	callerStub := tracingtest.RequireSpan(t, exporter, "caller")
	root := tracingtest.RequireSpan(t, exporter, spanTransfer)
	tracingtest.RequireParent(t, callerStub, root)
	requireChild(t, exporter, root, spanDownloadObject)

	stat := requireChild(t, exporter, callerStub, spanStat)
	assert.Equal(t, "/test/object.txt", tracingtest.Attributes(stat)["pelican.object.path"])
	requireChild(t, exporter, stat, "PROPFIND")
	for _, h := range fed.headers("propfind") {
		assert.Equal(t, callerStub.SpanContext.TraceID().String(), traceIDOf(t, h))
	}
}

func TestTracingStatWithoutParentIsNotTraced(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	exporter := tracingtest.Setup(t)
	fed := newTracedFed(t, tracedFedOptions{})
	ctx := testContext(t)

	te, err := NewTransferEngine(ctx)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, te.Shutdown())
	}()
	info, err := te.Stat(ctx, fed.objectURL(t, "/test/object.txt").String(), WithAcquireToken(false))
	require.NoError(t, err)
	assert.Equal(t, int64(len(tracedFedContents)), info.Size)

	tracingtest.RequireNoSpans(t, exporter)
	for role, headers := range fed.all() {
		for _, h := range headers {
			assert.Empty(t, h, "the %s request carried a traceparent", role)
		}
	}
}

func TestTracingDisabledSendsNoTraceparent(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	tracingtest.Disabled(t)
	fed := newTracedFed(t, tracedFedOptions{failFirst: true})
	ctx := testContext(t)

	fed.download(t, ctx, "/test/object.txt", WithAcquireToken(false))

	all := fed.all()
	require.NotEmpty(t, all["director"])
	require.NotEmpty(t, all["download"])
	for role, headers := range all {
		for _, h := range headers {
			assert.Empty(t, h, "the %s request carried a traceparent with tracing disabled", role)
		}
	}
}

func TestTracingRecordsNoToken(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	exporter := tracingtest.Setup(t)
	fed := newTracedFed(t, tracedFedOptions{requireToken: true, failFirst: true})
	ctx := testContext(t)

	const secret = "tracing-test-secret-token-0123456789"
	fed.download(t, ctx, "/test/object.txt", WithToken(secret), WithAcquireToken(false))

	tracingtest.RequireSpan(t, exporter, spanAcquireToken)
	directors := tracingtest.SpansNamed(exporter, spanQueryDirector)
	require.Len(t, directors, 2, "one anonymous and one credentialed director query")
	withToken := map[bool]bool{}
	for _, d := range directors {
		withToken[tracingtest.Attributes(d)["pelican.director.with_token"].(bool)] = true
	}
	assert.Equal(t, map[bool]bool{false: true, true: true}, withToken)
	require.Len(t, tracingtest.SpansNamed(exporter, spanAttempt), 2)

	assertNoSecretInSpans(t, exporter, secret)
}

// assertNoSecretInSpans checks that secret appears in no span name, status,
// attribute or event.
func assertNoSecretInSpans(t *testing.T, exporter *tracetest.InMemoryExporter, secret string) {
	t.Helper()
	spans := exporter.GetSpans()
	require.NotEmpty(t, spans)
	for _, s := range spans {
		assert.NotContains(t, s.Name, secret)
		assert.NotContains(t, s.Status.Description, secret, "status of span %q", s.Name)
		for _, kv := range s.Attributes {
			assert.NotContains(t, kv.Value.Emit(), secret, "attribute %s of span %q", kv.Key, s.Name)
		}
		for _, ev := range s.Events {
			assert.NotContains(t, ev.Name, secret)
			for _, kv := range ev.Attributes {
				assert.NotContains(t, kv.Value.Emit(), secret, "event %q attribute %s of span %q", ev.Name, kv.Key, s.Name)
			}
		}
	}
}

func TestTracingUploadCreatesNoSpans(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	exporter := tracingtest.Setup(t)
	fed := newTracedFed(t, tracedFedOptions{})
	ctx := testContext(t)

	te, err := NewTransferEngine(ctx)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, te.Shutdown())
	}()
	// An upload always needs a credential; this one is handed over.
	tc, err := te.NewClient(WithToken("upload-token"), WithAcquireToken(false))
	require.NoError(t, err)
	local := filepath.Join(t.TempDir(), "upload")
	require.NoError(t, os.WriteFile(local, []byte(tracedFedContents), 0o644))

	_, err = tc.NewTransferJob(ctx, fed.objectURL(t, "/test/upload.txt"), local, true, false)
	require.NoError(t, err)
	tc.Close()

	tracingtest.RequireNoSpans(t, exporter)
	require.NotEmpty(t, fed.headers("director"))
	for role, headers := range fed.all() {
		for _, h := range headers {
			assert.Empty(t, h, "the %s request for an upload carried a traceparent", role)
		}
	}
}

func TestTracingFailedJobCreationEndsRootSpan(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	exporter := tracingtest.Setup(t)
	test_utils.InitClient(t, map[param.Param]any{param.TLSSkipVerify: true})
	pelican_url.ResetState()
	t.Cleanup(pelican_url.ResetState)
	ctx := testContext(t)

	// Nothing listens here, so discovery fails.
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	host := strings.TrimPrefix(srv.URL, "https://")
	srv.Close()
	remote, err := url.Parse("pelican://" + host + "/test/object.txt")
	require.NoError(t, err)

	te, err := NewTransferEngine(ctx)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, te.Shutdown())
	}()
	tc, err := te.NewClient(WithAcquireToken(false))
	require.NoError(t, err)
	_, err = tc.NewTransferJob(ctx, remote, filepath.Join(t.TempDir(), "object"), false, false)
	require.Error(t, err)
	tc.Close()

	root := tracingtest.RequireSpan(t, exporter, spanTransfer)
	assert.Equal(t, codes.Error, root.Status.Code)
	discover := requireChild(t, exporter, root, spanDiscoverFed)
	assert.Equal(t, codes.Error, discover.Status.Code)
}

// failFedContents is what failFed serves for every object that succeeds.
const failFedContents = "0123456789"

// failFed is a federation whose objects fail or stall by name: an object
// named "fail" answers 500, one named "slow" blocks until its request is
// cancelled or release is closed, and any other is served.  The collection
// /test/dir lists the names it was built with.
type failFed struct {
	url         string
	release     chan struct{}
	releaseOnce sync.Once

	mu   sync.Mutex
	gets map[string]int
}

func newFailFed(t *testing.T, dirEntries ...string) *failFed {
	t.Helper()
	f := &failFed{release: make(chan struct{}), gets: make(map[string]int)}
	t.Cleanup(f.releaseSlow)

	propEntry := func(href string, collection bool) string {
		if collection {
			return fmt.Sprintf(`<D:response><D:href>%s/</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>`, href)
		}
		return fmt.Sprintf(`<D:response><D:href>%s</D:href><D:propstat><D:prop><D:resourcetype/><D:getcontentlength>%d</D:getcontentlength></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>`, href, len(failFedContents))
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		self := "https://" + r.Host
		switch {
		case r.URL.Path == "/.well-known/pelican-configuration":
			_, _ = fmt.Fprintf(w, `{"director_endpoint": "%s"}`, self)

		case r.Method == "PROPFIND":
			p := strings.TrimSuffix(r.URL.Path, "/")
			body := `<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">`
			if strings.HasSuffix(p, "/test/dir") {
				body += propEntry(p, true)
				for _, e := range dirEntries {
					body += propEntry(p+"/"+e, false)
				}
			} else {
				body += propEntry(p, false)
			}
			body += `</D:multistatus>`
			w.Header().Set("Content-Type", "application/xml; charset=utf-8")
			w.WriteHeader(http.StatusMultiStatus)
			_, _ = w.Write([]byte(body))

		case strings.HasPrefix(r.URL.Path, "/download/"):
			if isProbe(r) {
				w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-0/%d", len(failFedContents)))
				w.Header().Set("Content-Length", "1")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write([]byte(failFedContents[:1]))
				return
			}
			w.Header().Set("Content-Length", fmt.Sprint(len(failFedContents)))
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			name := path.Base(r.URL.Path)
			f.mu.Lock()
			f.gets[name]++
			f.mu.Unlock()
			switch name {
			case "fail":
				w.WriteHeader(http.StatusInternalServerError)
				return
			case "slow":
				select {
				case <-r.Context().Done():
					return
				case <-f.release:
				}
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(failFedContents))

		case strings.HasPrefix(r.URL.Path, "/test/"):
			w.Header().Set("Link", fmt.Sprintf(`<%s/download%s>; rel="duplicate"; pri=1; depth=1`, self, r.URL.Path))
			w.Header().Set("Location", self+"/download"+r.URL.Path)
			w.Header().Set("X-Pelican-Namespace", fmt.Sprintf("namespace=/test, require-token=false, collections-url=%s", self))
			w.WriteHeader(http.StatusTemporaryRedirect)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	f.url = srv.URL

	pelican_url.ResetState()
	t.Cleanup(pelican_url.ResetState)
	test_utils.InitClient(t, map[param.Param]any{param.TLSSkipVerify: true})
	return f
}

// objectURL returns the pelican:// URL of the object at objectPath.
func (f *failFed) objectURL(t *testing.T, objectPath string) *url.URL {
	t.Helper()
	u, err := url.Parse(f.url)
	require.NoError(t, err)
	remote, err := url.Parse("pelican://" + u.Host + objectPath)
	require.NoError(t, err)
	return remote
}

// releaseSlow lets every "slow" download complete.
func (f *failFed) releaseSlow() {
	f.releaseOnce.Do(func() { close(f.release) })
}

// downloadStarted reports whether the body of the object named name has been
// requested.
func (f *failFed) downloadStarted(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gets[name] > 0
}

// requireNoOpenJobSpans checks that every job span the test started has
// ended, so that no later FlushTracing waits on it.
func requireNoOpenJobSpans(t *testing.T) {
	t.Helper()
	require.Eventually(t, func() bool {
		openJobSpans.mu.Lock()
		defer openJobSpans.mu.Unlock()
		return openJobSpans.open == 0
	}, 10*time.Second, 10*time.Millisecond, "a client.transfer span was never ended")
}

// newTracedEngine returns an engine shut down at cleanup, after the test's
// own cleanups have checked its spans.
func newTracedEngine(t *testing.T, ctx context.Context, options ...TransferEngineOption) *TransferEngine {
	t.Helper()
	// The count of open job spans is process-wide.  Checking it here pins a
	// span leaked by an earlier test on that test, not on this one.
	requireNoOpenJobSpans(t)
	te, err := NewTransferEngine(ctx, options...)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = te.Shutdown()
		requireNoOpenJobSpans(t)
	})
	return te
}

// drainUntilFailure reads results the way cmd/transfer_batch.go's
// submitAndDrain does: it stops at the first failed result, cancelling the
// client, and returns that result.
func drainUntilFailure(t *testing.T, tc *TransferClient) TransferResults {
	t.Helper()
	for result := range tc.Results() {
		if result.Error != nil {
			tc.Cancel()
			return result
		}
	}
	require.Fail(t, "no transfer failed")
	return TransferResults{}
}

// requireFailedRoot checks, right after FlushTracing, that exactly one
// client.transfer span was exported and that it failed.
func requireFailedRoot(t *testing.T, exporter *tracetest.InMemoryExporter) tracetest.SpanStub {
	t.Helper()
	roots := tracingtest.SpansNamed(exporter, spanTransfer)
	require.Lenf(t, roots, 1, "FlushTracing returned before the job span ended; recorded spans: %v", tracingtest.Names(exporter))
	root := roots[0]
	assert.Equal(t, codes.Error, root.Status.Code)
	return root
}

func TestTracingRecursiveFailureBatchStyle(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	exporter := tracingtest.Setup(t)
	fed := newFailFed(t, "fail", "slow")
	ctx := testContext(t)

	te := newTracedEngine(t, ctx)
	tc, err := te.NewClient(WithAcquireToken(false))
	require.NoError(t, err)
	tj, err := tc.NewTransferJob(ctx, fed.objectURL(t, "/test/dir"), t.TempDir()+"/", false, true)
	require.NoError(t, err)
	require.NoError(t, tc.Submit(tj))
	tc.Close()

	// The sibling is still downloading when the failure arrives, so the job
	// never retires by itself.
	drainUntilFailure(t, tc)
	require.True(t, fed.downloadStarted("fail"))
	FlushTracing()

	root := requireFailedRoot(t, exporter)
	assert.GreaterOrEqual(t, tracingtest.Attributes(root)["pelican.transfer.objects"], int64(1))
	assert.Equal(t, true, tracingtest.Attributes(root)["pelican.transfer.recursive"])
}

func TestTracingRecursiveFailurePluginStyle(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	exporter := tracingtest.Setup(t)
	fed := newFailFed(t, "fail", "slow")
	engineCtx, cancelEngine := context.WithCancel(testContext(t))
	defer cancelEngine()

	te := newTracedEngine(t, engineCtx)
	tc, err := te.NewClient(WithAcquireToken(false))
	require.NoError(t, err)
	// The plugin's jobs have a context of their own; only the engine's
	// cancellation reaches them.
	tj, err := tc.NewTransferJob(context.Background(), fed.objectURL(t, "/test/dir"), t.TempDir()+"/", false, true)
	require.NoError(t, err)
	require.NoError(t, tc.Submit(tj))
	tc.Close()

	for result := range tc.Results() {
		if result.Error != nil {
			break
		}
	}
	require.True(t, fed.downloadStarted("fail"))
	cancelEngine()
	FlushTracing()

	requireFailedRoot(t, exporter)
}

func TestTracingSingleObjectFailure(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	exporter := tracingtest.Setup(t)
	fed := newFailFed(t)
	ctx := testContext(t)

	te := newTracedEngine(t, ctx)
	tc, err := te.NewClient(WithAcquireToken(false))
	require.NoError(t, err)
	tj, err := tc.NewTransferJob(ctx, fed.objectURL(t, "/test/fail"), filepath.Join(t.TempDir(), "object"), false, false)
	require.NoError(t, err)
	require.NoError(t, tc.Submit(tj))
	tc.Close()

	drainUntilFailure(t, tc)
	FlushTracing()

	root := requireFailedRoot(t, exporter)
	assert.Equal(t, int64(1), tracingtest.Attributes(root)["pelican.transfer.objects"])
	object := requireChild(t, exporter, root, spanDownloadObject)
	assert.Equal(t, codes.Error, object.Status.Code)
}

// A transfer the scheduler sheds never reaches downloadObject; its job must
// still count it and fail.
func TestTracingSchedulerRejectionFailsJob(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	exporter := tracingtest.Setup(t)
	fed := newFailFed(t)
	ctx := testContext(t)

	// One worker, and room for one transfer waiting for it.
	sched := NewTagScheduler(1, SchedulerConfig{PerTagPendingSize: 1})
	te := newTracedEngine(t, ctx, WithWorkerCount(1), WithScheduler(sched))
	submit := func(objectPath string) *TransferClient {
		tc, err := te.NewClient(WithAcquireToken(false))
		require.NoError(t, err)
		tj, err := tc.NewTransferJob(ctx, fed.objectURL(t, objectPath), filepath.Join(t.TempDir(), "object"), false, false)
		require.NoError(t, err)
		require.NoError(t, tc.Submit(tj))
		tc.Close()
		return tc
	}

	// The worker is taken by a transfer that stalls ...
	busy := submit("/test/slow")
	require.Eventually(t, func() bool { return fed.downloadStarted("slow") }, 10*time.Second, 10*time.Millisecond)
	// ... the one waiting slot by the next ...
	waiting := submit("/test/waiting")
	require.Eventually(t, func() bool { return sched.Snapshot(ctx).Global.TotalAdmits == 2 }, 10*time.Second, 10*time.Millisecond)
	// ... so this one is shed.
	shed := submit("/test/shed")
	results, err := shed.Shutdown()
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.ErrorIs(t, results[0].Error, ErrTooManyRequests)

	fed.releaseSlow()
	for _, tc := range []*TransferClient{busy, waiting} {
		results, err := tc.Shutdown()
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.NoError(t, results[0].Error)
	}
	FlushTracing()

	var root tracetest.SpanStub
	for _, s := range tracingtest.SpansNamed(exporter, spanTransfer) {
		if tracingtest.Attributes(s)["pelican.object.path"] == "/test/shed" {
			root = s
		}
	}
	require.Truef(t, root.SpanContext.IsValid(), "no client.transfer span for the shed object; recorded spans: %v", tracingtest.Names(exporter))
	assert.Equal(t, codes.Error, root.Status.Code)
	assert.Equal(t, int64(1), tracingtest.Attributes(root)["pelican.transfer.objects"])
	assert.Empty(t, childrenOf(exporter, root, spanDownloadObject), "the shed transfer never ran")
}

func TestTracingRecursiveSuccessCountsObjects(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	exporter := tracingtest.Setup(t)
	fed := newFailFed(t, "a", "b", "c")
	ctx := testContext(t)

	te := newTracedEngine(t, ctx)
	tc, err := te.NewClient(WithAcquireToken(false))
	require.NoError(t, err)
	tj, err := tc.NewTransferJob(ctx, fed.objectURL(t, "/test/dir"), t.TempDir()+"/", false, true)
	require.NoError(t, err)
	require.NoError(t, tc.Submit(tj))
	results, err := tc.Shutdown()
	require.NoError(t, err)
	require.Len(t, results, 3)
	for _, r := range results {
		require.NoError(t, r.Error)
	}
	FlushTracing()

	root := tracingtest.RequireSpan(t, exporter, spanTransfer)
	assert.Equal(t, codes.Unset, root.Status.Code)
	assert.Equal(t, int64(3), tracingtest.Attributes(root)["pelican.transfer.objects"])
	assert.Len(t, childrenOf(exporter, root, spanDownloadObject), 3)
}

// The client embedded in a server traces a download only under a span the
// server is already recording; it starts no trace of its own.
func TestTracingServerWithoutParentSpanIsNotTraced(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceCache))
	fed := newTracedFed(t, tracedFedOptions{failFirst: true})

	fed.download(t, testContext(t), "/test/object.txt", WithAcquireToken(false))

	tracingtest.RequireNoSpans(t, exporter)
	all := fed.all()
	for _, role := range []string{"discovery", "director", "download", "checksum", "fail-get"} {
		require.NotEmpty(t, all[role], "no %s request was made", role)
	}
	require.NotEmpty(t, append(all["probe"], all["fail-probe"]...), "the endpoints are probed")
	for role, headers := range all {
		for _, h := range headers {
			assert.Empty(t, h, "the %s request carried a traceparent", role)
		}
	}
	requireNoOpenJobSpans(t)
}

func TestTracingOffersEndpointOnlyInClient(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		tracingtest.Disabled(t)
		assert.False(t, offersTracingEndpoint())
	})
	t.Run("client", func(t *testing.T) {
		tracingtest.Setup(t)
		assert.True(t, offersTracingEndpoint())
	})
	t.Run("server", func(t *testing.T) {
		tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceCache))
		assert.False(t, offersTracingEndpoint(), "a server's export endpoint comes from its launcher")
	})
}

// staticFedToken is a federation token provider for tests.
type staticFedToken string

func (s staticFedToken) Get() (string, error) { return string(s), nil }

// A federation token travels in the data URL's query; it must not reach any
// span, including the error of an attempt whose message quotes that URL.
func TestTracingRecordsNoFederationToken(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	exporter := tracingtest.Setup(t)
	fed := newTracedFed(t, tracedFedOptions{failFirst: true, hangUp: true})

	const secret = "tracing-test-federation-token-0123456789"
	results := fed.download(t, testContext(t), "/test/object.txt", WithFedToken(staticFedToken(secret)), WithAcquireToken(false))
	require.Len(t, results[0].Attempts, 2)
	require.Error(t, results[0].Attempts[0].Error)

	attempts := tracingtest.SpansNamed(exporter, spanAttempt)
	require.Len(t, attempts, 2)
	failed := 0
	for _, a := range attempts {
		if a.Status.Code == codes.Error {
			failed++
		}
	}
	assert.Equal(t, 1, failed, "one attempt failed")
	assertNoSecretInSpans(t, exporter, secret)
	requireNoOpenJobSpans(t)
}

// A job that is created and never submitted has no result for the engine to
// see, so only the watch on its context can end its span.
func TestTracingUnsubmittedJobEndsOnCancel(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	exporter := tracingtest.Setup(t)
	fed := newFailFed(t)

	te := newTracedEngine(t, testContext(t))
	tc, err := te.NewClient(WithAcquireToken(false))
	require.NoError(t, err)
	jobCtx, cancelJob := context.WithCancel(context.Background())
	_, err = tc.NewTransferJob(jobCtx, fed.objectURL(t, "/test/x"), filepath.Join(t.TempDir(), "o"), false, false)
	require.NoError(t, err)

	cancelJob()
	requireNoOpenJobSpans(t)
	FlushTracing()
	requireFailedRoot(t, exporter)
}

// FlushTracing waits for a transfer span that ends after it was called, so
// that a command which flushes straight after a failure still exports the
// failing job's root span.
func TestTracingFlushWaitsForOpenSpan(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	exporter := tracingtest.Setup(t)
	fed := newFailFed(t)

	te := newTracedEngine(t, testContext(t))
	tc, err := te.NewClient(WithAcquireToken(false))
	require.NoError(t, err)
	jobCtx, cancelJob := context.WithCancel(context.Background())
	defer cancelJob()
	_, err = tc.NewTransferJob(jobCtx, fed.objectURL(t, "/test/x"), filepath.Join(t.TempDir(), "o"), false, false)
	require.NoError(t, err)

	flushed := make(chan struct{})
	go func() {
		FlushTracing()
		close(flushed)
	}()
	// The flush is now blocked on the open span; ending the span lets it go.
	require.Eventually(t, func() bool {
		openJobSpans.mu.Lock()
		defer openJobSpans.mu.Unlock()
		return len(openJobSpans.waiters) > 0
	}, tracingSpanWait, time.Millisecond, "FlushTracing did not wait for the open transfer span")
	cancelJob()
	<-flushed
	requireFailedRoot(t, exporter)
}
