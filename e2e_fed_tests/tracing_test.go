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

package fed_tests

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/tracing"
	"github.com/pelicanplatform/pelican/tracing/tracingtest"
)

// traceView indexes the spans of one trace.
type traceView struct {
	id    trace.TraceID
	spans []tracetest.SpanStub
	byID  map[trace.SpanID]tracetest.SpanStub
}

func newTraceView(exporter *tracetest.InMemoryExporter, id trace.TraceID) traceView {
	tv := traceView{id: id, byID: map[trace.SpanID]tracetest.SpanStub{}}
	for _, s := range exporter.GetSpans() {
		if s.SpanContext.TraceID() == id {
			tv.spans = append(tv.spans, s)
			tv.byID[s.SpanContext.SpanID()] = s
		}
	}
	return tv
}

// find returns the spans of the trace with the given service and name that
// satisfy every predicate.
func (tv traceView) find(service, name string, preds ...func(tracetest.SpanStub) bool) []tracetest.SpanStub {
	var found []tracetest.SpanStub
outer:
	for _, s := range tv.spans {
		if s.Name != name || tracingtest.ServiceName(s) != service {
			continue
		}
		for _, p := range preds {
			if !p(s) {
				continue outer
			}
		}
		found = append(found, s)
	}
	return found
}

// isDescendant reports whether child sits below ancestor in the trace,
// following parent span IDs (across services, since a server span's parent
// is the caller's HTTP client span).
func (tv traceView) isDescendant(child, ancestor tracetest.SpanStub) bool {
	want := ancestor.SpanContext.SpanID()
	cur := child
	for i := 0; i < len(tv.spans)+1; i++ {
		parent := cur.Parent.SpanID()
		if !parent.IsValid() {
			return false
		}
		if parent == want {
			return true
		}
		next, ok := tv.byID[parent]
		if !ok {
			return false
		}
		cur = next
	}
	return false
}

// below returns a predicate matching spans that descend from any of ancestors.
func (tv traceView) below(ancestors ...tracetest.SpanStub) func(tracetest.SpanStub) bool {
	return func(s tracetest.SpanStub) bool {
		for _, a := range ancestors {
			if tv.isDescendant(s, a) {
				return true
			}
		}
		return false
	}
}

func attrIs(key string, value any) func(tracetest.SpanStub) bool {
	return func(s tracetest.SpanStub) bool {
		return tracingtest.Attributes(s)[key] == value
	}
}

var (
	isGET  = attrIs("http.request.method", "GET")
	isHEAD = attrIs("http.request.method", "HEAD")
)

// render prints the trace as an indented tree, children in start order.
func (tv traceView) render() string {
	children := map[trace.SpanID][]tracetest.SpanStub{}
	var roots []tracetest.SpanStub
	for _, s := range tv.spans {
		if _, ok := tv.byID[s.Parent.SpanID()]; ok {
			children[s.Parent.SpanID()] = append(children[s.Parent.SpanID()], s)
		} else {
			roots = append(roots, s)
		}
	}
	byStart := func(ss []tracetest.SpanStub) {
		sort.SliceStable(ss, func(i, j int) bool { return ss[i].StartTime.Before(ss[j].StartTime) })
	}
	keys := []string{
		"http.request.method", "http.response.status_code", "pelican.object.path",
		"pelican.director.redirect_target", "pelican.director.chosen", "pelican.director.server_type",
		"pelican.cache.result", "pelican.cache.decision", "pelican.cache.range_request",
		"pelican.origin.storage_type", "pelican.origin.authorized", "pelican.attempt.number",
		"pelican.transfer.bytes", "pelican.job_id",
	}
	var b strings.Builder
	var walk func(s tracetest.SpanStub, depth int)
	walk = func(s tracetest.SpanStub, depth int) {
		attrs := tracingtest.Attributes(s)
		var parts []string
		for _, k := range keys {
			if v, ok := attrs[k]; ok {
				parts = append(parts, fmt.Sprintf("%s=%v", strings.TrimPrefix(k, "pelican."), v))
			}
		}
		fmt.Fprintf(&b, "%s[%s] %s (%s) %s\n", strings.Repeat("  ", depth), tracingtest.ServiceName(s), s.Name,
			s.EndTime.Sub(s.StartTime).Round(10*time.Microsecond), strings.Join(parts, " "))
		kids := children[s.SpanContext.SpanID()]
		byStart(kids)
		for _, k := range kids {
			walk(k, depth+1)
		}
	}
	byStart(roots)
	for _, r := range roots {
		walk(r, 0)
	}
	return b.String()
}

// newDownloadTrace returns the trace ID of the client's own download of
// objectPath that is not among seen.  It fails if there is not exactly one.
func newDownloadTrace(t *testing.T, exporter *tracetest.InMemoryExporter, objectPath string, seen map[trace.TraceID]bool) trace.TraceID {
	t.Helper()
	var ids []trace.TraceID
	for _, s := range exporter.GetSpans() {
		if s.Name == "client.transfer" && tracingtest.ServiceName(s) == string(tracing.ServiceClient) &&
			!s.Parent.IsValid() && tracingtest.Attributes(s)["pelican.object.path"] == objectPath &&
			!seen[s.SpanContext.TraceID()] {
			ids = append(ids, s.SpanContext.TraceID())
		}
	}
	require.Len(t, ids, 1, "expected one new client.transfer root span for %s", objectPath)
	seen[ids[0]] = true
	return ids[0]
}

// waitForTrace waits until the trace satisfies done, which is how the test
// knows that spans ending on the servers' goroutines have been recorded, and
// returns a view of it.  On timeout it fails with the trace as recorded.
func waitForTrace(t *testing.T, exporter *tracetest.InMemoryExporter, id trace.TraceID, label string, done func(traceView) bool) traceView {
	t.Helper()
	if !assert.Eventually(t, func() bool { return done(newTraceView(exporter, id)) }, 10*time.Second, 20*time.Millisecond) {
		t.Fatalf("the %s trace never completed; recorded:\n%s", label, newTraceView(exporter, id).render())
	}
	return newTraceView(exporter, id)
}

// writeOriginObject puts an object straight into the origin's posix storage,
// so that no upload (and none of its requests) precedes the traced download.
func writeOriginObject(t *testing.T, ft *fed_test_utils.FedTest, name string, size int) (objectPath, pelicanURL string) {
	t.Helper()
	content := []byte(strings.Repeat("tracing!", size/8))
	require.NoError(t, os.WriteFile(filepath.Join(ft.Exports[0].StoragePrefix, name), content, 0644))
	objectPath = "/test/" + name
	pelicanURL = fmt.Sprintf("pelican://%s:%d%s", param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), objectPath)
	return
}

// TestTracingEndToEnd downloads objects through an in-process Go-native
// federation (posixv2 origin, Cache.EnableV2) with tracing on, and checks
// that one download is one trace across the client, director, cache and
// origin, that a cache hit never reaches the origin, and that no token is
// recorded anywhere.
func TestTracingEndToEnd(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	// Installed before the federation starts so that every service's spans
	// land here.  Tracing.Enabled stays unset, which makes the launcher's
	// tracing.Init a no-op that leaves this exporter in place.  Spans with no
	// parent are the test's own downloads, hence the client default.
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceClient))

	require.NoError(t, param.Cache_EnableV2.Set(true))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)
	require.True(t, tracing.Enabled(), "the federation's start-up must leave the test exporter installed")

	const (
		svcClient   = string(tracing.ServiceClient)
		svcDirector = string(tracing.ServiceDirector)
		svcCache    = string(tracing.ServiceCache)
		svcOrigin   = string(tracing.ServiceOrigin)
	)

	seen := map[trace.TraceID]bool{}
	objectPath, objectURL := writeOriginObject(t, ft, "tracing_object.txt", 64*1024)
	destDir := t.TempDir()

	// Scenario A: the first download is a cache miss.
	_, err := downloadPublic(ft, objectURL, filepath.Join(destDir, "miss"))
	require.NoError(t, err)
	missID := newDownloadTrace(t, exporter, objectPath, seen)

	// The client's spans have ended when DoGet returns; the servers' spans
	// end on their own goroutines, so wait until the origin's GET and the
	// cache's request span have been recorded.
	tv := waitForTrace(t, exporter, missID, "miss", func(tv traceView) bool {
		attempts := tv.find(svcClient, "client.attempt")
		return len(tv.find(svcOrigin, "origin.serve_object", isGET)) > 0 &&
			len(tv.find(svcCache, "cache.fetch_origin")) > 0 &&
			len(tv.find(svcCache, "cache.serve_object", tv.below(attempts...))) > 0
	})
	t.Logf("Scenario A (miss) span tree:\n%s", tv.render())

	t.Run("MissIsOneTraceAcrossAllServices", func(t *testing.T) {
		transfer := tv.find(svcClient, "client.transfer")
		require.Len(t, transfer, 1)
		queries := tv.find(svcClient, "client.query_director", tv.below(transfer...))
		require.NotEmpty(t, queries)
		objects := tv.find(svcClient, "client.download_object", tv.below(transfer...))
		require.Len(t, objects, 1)
		attempts := tv.find(svcClient, "client.attempt", tv.below(objects...))
		require.NotEmpty(t, attempts)

		// Director: the client's lookup, sent to a cache, under the client's
		// director query; and the cache's own lookup, sent to the origin.
		clientLookups := tv.find(svcDirector, "director.redirect", tv.below(queries...))
		require.NotEmpty(t, clientLookups, "the client's director lookup is missing")
		assert.Equal(t, "cache", tracingtest.Attributes(clientLookups[0])["pelican.director.redirect_target"])
		assert.NotEmpty(t, tv.find(svcDirector, "director.redirect", attrIs("pelican.director.redirect_target", "origin")),
			"the cache's director lookup for the origin is missing")
		assert.GreaterOrEqual(t, len(tv.find(svcDirector, "director.redirect")), 2)

		// Cache: the request the client's attempt made is a miss.
		serves := tv.find(svcCache, "cache.serve_object", tv.below(attempts...))
		require.NotEmpty(t, serves)
		misses := tv.find(svcCache, "cache.serve_object", tv.below(attempts...), attrIs("pelican.cache.result", "miss"))
		assert.NotEmpty(t, misses, "no cache.serve_object under the client's attempt reports a miss")
		assert.NotEmpty(t, tv.find(svcCache, "cache.resolve_object", tv.below(serves...)))
		fetches := tv.find(svcCache, "cache.fetch_origin")
		require.Len(t, fetches, 1)
		// The cache's embedded client reports under the cache's name.
		embedded := tv.find(svcCache, "client.transfer", tv.below(fetches...))
		assert.Len(t, embedded, 1, "the cache's embedded client.transfer is missing")

		// Origin: the GET is served under the cache's fetch, authorized and read.
		originGets := tv.find(svcOrigin, "origin.serve_object", isGET, tv.below(fetches...))
		require.Len(t, originGets, 1, "the origin's GET is not under cache.fetch_origin")
		assert.EqualValues(t, 200, tracingtest.Attributes(originGets[0])["http.response.status_code"])
		assert.NotEmpty(t, tv.find(svcOrigin, "origin.authorize", tv.below(originGets...)))
		assert.NotEmpty(t, tv.find(svcOrigin, "origin.read", tv.below(originGets...)))

		// The same object throughout.
		for _, s := range []tracetest.SpanStub{transfer[0], serves[0], originGets[0]} {
			assert.Equal(t, objectPath, tracingtest.Attributes(s)["pelican.object.path"],
				"%s/%s names a different object", tracingtest.ServiceName(s), s.Name)
		}

		// Outside an HTCondor job the client sends no X-Pelican-JobId, so only
		// the director, which assigns a request ID of its own, records one.
		// (client.DoGet cannot be given a job ID: WithRequestId is a job
		// option that DoGet hands only to NewClient, where it is ignored.)
		assert.NotEmpty(t, tracingtest.Attributes(clientLookups[0])["pelican.job_id"],
			"director.redirect does not record its request ID")
		assert.NotContains(t, tracingtest.Attributes(transfer[0]), "pelican.job_id")

		// The director records its decision, with the client's address masked.
		var decision string
		for _, e := range clientLookups[0].Events {
			if e.Name == "director.decision" {
				for _, kv := range e.Attributes {
					if kv.Key == "pelican.director.decision" {
						decision = kv.Value.AsString()
					}
				}
			}
		}
		require.NotEmpty(t, decision, "director.redirect has no director.decision event")
		t.Logf("director.decision: %s", decision)
		assert.NotContains(t, decision, `"ipAddr":"127.0.0.1"`)

		// Every one of the four services took part, in this one trace.
		services := map[string]bool{}
		for _, s := range tv.spans {
			services[tracingtest.ServiceName(s)] = true
		}
		for _, svc := range []string{svcClient, svcDirector, svcCache, svcOrigin} {
			assert.True(t, services[svc], "no %s span in the trace", svc)
		}
	})

	// Scenario B: the second download of the same object is a hit and never
	// reaches the origin for data.
	_, err = downloadPublic(ft, objectURL, filepath.Join(destDir, "hit"))
	require.NoError(t, err)
	hitID := newDownloadTrace(t, exporter, objectPath, seen)
	hv := waitForTrace(t, exporter, hitID, "hit", func(hv traceView) bool {
		attempts := hv.find(svcClient, "client.attempt")
		return len(hv.find(svcCache, "cache.serve_object", hv.below(attempts...))) > 0
	})
	t.Logf("Scenario B (hit) span tree:\n%s", hv.render())

	t.Run("HitDoesNotReachOrigin", func(t *testing.T) {
		attempts := hv.find(svcClient, "client.attempt")
		hits := hv.find(svcCache, "cache.serve_object", hv.below(attempts...), isGET, attrIs("pelican.cache.result", "hit"))
		assert.NotEmpty(t, hits, "the client's attempt was not a cache hit")
		assert.Empty(t, hv.find(svcCache, "cache.fetch_origin"), "a hit fetched from the origin")
		assert.Empty(t, hv.find(svcOrigin, "origin.serve_object", isGET), "a hit sent a GET to the origin")
		// The director may still stat the origin with a HEAD; that is allowed.
		if heads := hv.find(svcOrigin, "origin.serve_object", isHEAD); len(heads) > 0 {
			t.Logf("The hit trace holds %d origin HEAD request(s), from the director's stat", len(heads))
		}
	})

	// Scenario C: a download that carries a token records it nowhere.
	tokenPath, tokenURL := writeOriginObject(t, ft, "tracing_token_object.txt", 4*1024)
	require.NotEmpty(t, ft.Token)
	_, err = client.DoGet(ft.Ctx, tokenURL, filepath.Join(destDir, "token"), false, client.WithToken(ft.Token))
	require.NoError(t, err)
	tokenID := newDownloadTrace(t, exporter, tokenPath, seen)
	waitForTrace(t, exporter, tokenID, "token", func(cv traceView) bool {
		attempts := cv.find(svcClient, "client.attempt")
		return len(cv.find(svcOrigin, "origin.serve_object", isGET)) > 0 &&
			len(cv.find(svcCache, "cache.serve_object", cv.below(attempts...))) > 0
	})

	t.Run("NoSecretsRecorded", func(t *testing.T) {
		forbidden := []string{ft.Token, "authz=", "Bearer "}
		check := func(where, value string) {
			for _, f := range forbidden {
				assert.NotContains(t, value, f, "%s records a secret", where)
			}
		}
		checkAttrs := func(where string, kvs []attribute.KeyValue) {
			for _, kv := range kvs {
				check(where+" attribute "+string(kv.Key), kv.Value.Emit())
			}
		}
		spans := exporter.GetSpans()
		require.NotEmpty(t, spans)
		for _, s := range spans {
			where := tracingtest.ServiceName(s) + "/" + s.Name
			check(where+" name", s.Name)
			check(where+" status", s.Status.Description)
			checkAttrs(where, s.Attributes)
			for _, e := range s.Events {
				check(where+" event", e.Name)
				checkAttrs(where+" event "+e.Name, e.Attributes)
			}
			for _, l := range s.Links {
				checkAttrs(where+" link", l.Attributes)
			}
		}
	})
}

// downloadPublic downloads objectURL through the federation the way a user
// does, without a token (the namespace allows public reads).
func downloadPublic(ft *fed_test_utils.FedTest, objectURL, dest string, options ...client.TransferOption) ([]client.TransferResults, error) {
	return client.DoGet(ft.Ctx, objectURL, dest, false, options...)
}

// TestTracingDisabledEndToEnd checks that the same miss-then-hit downloads
// work through a Go-native federation with tracing off, and that nothing
// turns tracing on along the way.
func TestTracingDisabledEndToEnd(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	tracingtest.Disabled(t)
	require.NoError(t, param.Cache_EnableV2.Set(true))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)
	require.False(t, tracing.Enabled())

	_, objectURL := writeOriginObject(t, ft, "untraced_object.txt", 4*1024)
	destDir := t.TempDir()
	for _, name := range []string{"miss", "hit"} {
		results, err := downloadPublic(ft, objectURL, filepath.Join(destDir, name))
		require.NoError(t, err, name)
		require.Len(t, results, 1, name)
		assert.EqualValues(t, 4*1024, results[0].TransferredBytes, name)
		assert.False(t, tracing.Enabled(), "tracing turned on during the %s download", name)
	}
}

// TestTracingServerExportsToAdvertisedCollector starts a federation with
// Tracing.Enabled actually set, so that the launcher itself initialises
// tracing, and with Federation.TracingEndpoint naming a stand-in collector.
// It checks that the director advertises that endpoint in the federation's
// discovery document and that the servers export their spans to it without
// any Tracing.Endpoint of their own.
func TestTracingServerExportsToAdvertisedCollector(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	// Registered first so that it runs last: whatever happens, the next test
	// starts with tracing off.
	tracingtest.Disabled(t)

	var posts atomic.Int32
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/traces" {
			posts.Add(1)
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(collector.Close)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")

	require.NoError(t, param.Cache_EnableV2.Set(true))
	require.NoError(t, param.Tracing_Enabled.Set(true))
	require.NoError(t, param.Federation_TracingEndpoint.Set(collector.URL))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)
	require.True(t, tracing.Enabled(), "the launcher must have started tracing")
	require.Equal(t, tracing.ServiceServer, tracing.DefaultService())

	// The director advertises the endpoint, unaltered, to everyone else.
	discoveryURL := param.Server_ExternalWebUrl.GetString() + "/.well-known/pelican-configuration"
	req, err := http.NewRequestWithContext(ft.Ctx, http.MethodGet, discoveryURL, nil)
	require.NoError(t, err)
	resp, err := config.GetClient().Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, resp.Body.Close())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	var discovery pelican_url.FederationDiscovery
	require.NoError(t, json.Unmarshal(body, &discovery))
	assert.Equal(t, collector.URL, discovery.TracingEndpoint)

	// A download through the federation.  This process is a server, so the
	// client library starts no trace of its own; the director, cache and
	// origin each record the requests they serve.
	_, objectURL := writeOriginObject(t, ft, "exported_object.txt", 4*1024)
	results, err := downloadPublic(ft, objectURL, filepath.Join(t.TempDir(), "exported"))
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.EqualValues(t, 4*1024, results[0].TransferredBytes)

	// The servers' spans end shortly after the download returns; flush until
	// the collector has received an export.
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tracing.Flush(ctx)
		return posts.Load() > 0
	}, 20*time.Second, 100*time.Millisecond, "no spans reached the advertised collector")
}
