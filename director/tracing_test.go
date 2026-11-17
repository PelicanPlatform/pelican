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

package director

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/tracing"
	"github.com/pelicanplatform/pelican/tracing/tracingtest"
)

const (
	tracingTestNs        = "/tracing/ns"
	tracingTestUserAgent = "pelican-client/7.6.1"
	tracingTestJobID     = "3f1c2b8e-8a8e-4d3c-9b0e-0f6a1c2d3e4f"
)

// headRecorder is an httptest origin that answers stat HEAD requests and
// remembers the traceparent header of each one.
type headRecorder struct {
	mu           sync.Mutex
	traceparents []string
	heads        int
}

func (h *headRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		h.mu.Lock()
		h.heads++
		h.traceparents = append(h.traceparents, r.Header.Get("traceparent"))
		h.mu.Unlock()
		w.Header().Set("Content-Length", "5")
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func (h *headRecorder) snapshot() (heads int, traceparents []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.heads, append([]string(nil), h.traceparents...)
}

// setupTracingFederation registers one origin at originURL and nCaches
// caches for tracingTestNs, with distance sorting and stats disabled.  It
// restores the director's global state on cleanup.
func setupTracingFederation(t *testing.T, originURL url.URL, nCaches int) {
	t.Helper()
	setGinTestMode()
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	serverAds.DeleteAll()
	shutdownStatUtils()

	oldStartup := startupTime
	// Out of the startup window, so an unknown namespace is a 404, not a 429.
	SetStartupTime(time.Now().Add(-10 * time.Minute))

	t.Cleanup(func() {
		serverAds.DeleteAll()
		shutdownStatUtils()
		SetStartupTime(oldStartup)
		server_utils.ResetTestState()
	})

	require.NoError(t, param.Director_CacheSortMethod.Set(string(server_structs.DistanceType)))
	require.NoError(t, param.Director_CheckOriginPresence.Set(false))
	require.NoError(t, param.Director_CheckCachePresence.Set(false))
	require.NoError(t, param.Director_StatTimeout.Set(5*time.Second))
	require.NoError(t, param.Director_CachePresenceTTL.Set(time.Minute))
	require.NoError(t, param.Director_StatConcurrencyLimit.Set(10))
	require.NoError(t, param.Director_CachePresenceCapacity.Set(100))
	require.NoError(t, param.Server_ExternalWebUrl.Set("https://director.tracing.test"))

	nsAds := []server_structs.NamespaceAd{{
		Path: tracingTestNs,
		Caps: server_structs.Capabilities{PublicReads: true, Reads: true, DirectReads: true},
	}}
	caps := server_structs.Capabilities{PublicReads: true, Reads: true, DirectReads: true}

	originAd := server_structs.ServerAd{
		URL:                 originURL,
		Type:                server_structs.OriginType.String(),
		Caps:                caps,
		DisableDirectorTest: true,
	}
	originAd.Initialize("tracing-origin")
	recordAd(context.Background(), originAd, &nsAds)

	for i := 0; i < nCaches; i++ {
		cacheAd := server_structs.ServerAd{
			URL:                 url.URL{Scheme: "https", Host: fmt.Sprintf("cache%d.tracing.test:8443", i)},
			Type:                server_structs.CacheType.String(),
			Caps:                caps,
			DisableDirectorTest: true,
		}
		cacheAd.Initialize(fmt.Sprintf("tracing-cache-%d", i))
		cacheNs := append([]server_structs.NamespaceAd(nil), nsAds...)
		recordAd(context.Background(), cacheAd, &cacheNs)
	}
}

// fakeOriginURL is an origin URL that is never contacted.
func fakeOriginURL() url.URL {
	return url.URL{Scheme: "https", Host: "origin.tracing.test:8443"}
}

// newTracingRequest builds a director request with the headers a client sends.
func newTracingRequest(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("User-Agent", tracingTestUserAgent)
	req.Header.Set("X-Pelican-JobId", tracingTestJobID)
	return req
}

// serveDirect runs handler on req the way gin's router would.
func serveDirect(handler gin.HandlerFunc, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	handler(c)
	c.Writer.WriteHeaderNow()
	return w
}

// serveRouter sends req through a router with the redirect routes.
func serveRouter(req *http.Request) *httptest.ResponseRecorder {
	router := gin.New()
	router.GET("/api/v1.0/director/object/*any", redirectToCache)
	router.HEAD("/api/v1.0/director/object/*any", redirectToCache)
	router.GET("/api/v1.0/director/origin/*any", redirectToOrigin)
	router.PUT("/api/v1.0/director/origin/*any", redirectToOrigin)
	router.DELETE("/api/v1.0/director/origin/*any", redirectToOrigin)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func requireChildren(t *testing.T, parent tracetest.SpanStub, children ...tracetest.SpanStub) {
	t.Helper()
	for _, child := range children {
		tracingtest.RequireParent(t, parent, child)
	}
}

func decisionEvent(t *testing.T, span tracetest.SpanStub) server_structs.RedirectInfo {
	t.Helper()
	var found []string
	for _, ev := range span.Events {
		if ev.Name != eventDecision {
			continue
		}
		for _, kv := range ev.Attributes {
			if kv.Key == attrDecision {
				found = append(found, kv.Value.AsString())
			}
		}
	}
	require.Len(t, found, 1, "expected one %s event with a %s attribute", eventDecision, attrDecision)
	var info server_structs.RedirectInfo
	require.NoError(t, json.Unmarshal([]byte(found[0]), &info))
	return info
}

func TestRedirectSpanCacheRoute(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceDirector))
	setupTracingFederation(t, fakeOriginURL(), 2)

	w := serveRouter(newTracingRequest(http.MethodGet, "/api/v1.0/director/object"+tracingTestNs+"/file.txt"))
	require.Equal(t, http.StatusTemporaryRedirect, w.Code)

	redirect := tracingtest.RequireSpan(t, exporter, spanRedirect)
	assert.Equal(t, string(tracing.ServiceDirector), tracingtest.ServiceName(redirect))
	attrs := tracingtest.Attributes(redirect)
	assert.Equal(t, tracingTestJobID, attrs[string(tracing.AttrJobID)])
	assert.Equal(t, tracingTestNs+"/file.txt", attrs[string(tracing.AttrObjectPath)])
	assert.Equal(t, tracingTestNs, attrs[string(tracing.AttrNamespace)])
	assert.Equal(t, "cache", attrs[string(attrRedirectTarget)])
	assert.Equal(t, int64(1), attrs[string(attrCandidateOrigins)])
	assert.Equal(t, int64(2), attrs[string(attrCandidateCaches)])
	assert.Equal(t, int64(http.StatusTemporaryRedirect), attrs["http.response.status_code"])
	assert.Equal(t, http.MethodGet, attrs["http.request.method"])
	chosen, ok := attrs[string(attrChosen)].([]string)
	require.True(t, ok, "chosen must be a string slice, got %T", attrs[string(attrChosen)])
	require.Len(t, chosen, 2)
	for _, host := range chosen {
		assert.Contains(t, w.Header().Get("Link"), "https://"+host+"/", "every chosen host is in the Link header")
		assert.True(t, strings.HasPrefix(host, "cache"), "chosen host %q is a cache", host)
	}
	assert.Contains(t, w.Header().Get("Location"), chosen[0], "the first chosen host is the redirect target")
	assert.NotEqual(t, codes.Error, redirect.Status.Code)

	match := tracingtest.RequireSpan(t, exporter, spanMatchNamespace)
	assert.Equal(t, tracingTestNs, tracingtest.Attributes(match)[string(tracing.AttrNamespace)])
	assert.Equal(t, string(tracing.ServiceDirector), tracingtest.ServiceName(match))

	sorts := tracingtest.SpansNamed(exporter, spanSortServers)
	require.Len(t, sorts, 1, "a cache request sorts only the caches")
	sortAttrs := tracingtest.Attributes(sorts[0])
	assert.Equal(t, "cache", sortAttrs[string(attrServerType)])
	assert.Equal(t, string(server_structs.DistanceType), sortAttrs[string(attrSortMethod)])
	assert.Equal(t, int64(2), sortAttrs[string(attrCandidates)])
	assert.Contains(t, []any{coordSourceRandom, coordSourceCachedRandom, coordSourceMaxMind}, sortAttrs[string(attrClientCoordinateSource)])
	requireChildren(t, redirect, match, sorts[0])

	assert.Empty(t, tracingtest.SpansNamed(exporter, spanStatServers), "stats are disabled")

	info := decisionEvent(t, redirect)
	assert.Equal(t, string(server_structs.DistanceType), info.DirectorSortMethod)
	assert.Len(t, info.ServersInfo, 2)
	// httptest requests come from 192.0.2.1; the event carries only its /24.
	assert.Equal(t, "192.0.2.0", info.ClientInfo.IpAddr)
}

func TestRedirectSpanClientCoordinateHeader(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceDirector))
	setupTracingFederation(t, fakeOriginURL(), 1)

	req := newTracingRequest(http.MethodGet, "/api/v1.0/director/object"+tracingTestNs+"/file.txt")
	req.Header.Set("X-Pelican-Coordinate", "lat=43.07, long=-89.40")
	w := serveRouter(req)
	require.Equal(t, http.StatusTemporaryRedirect, w.Code)

	sort := tracingtest.RequireSpan(t, exporter, spanSortServers)
	assert.Equal(t, coordSourceHeader, tracingtest.Attributes(sort)[string(attrClientCoordinateSource)])
}

func TestRedirectSpanJoinsTraceparent(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceDirector))
	setupTracingFederation(t, fakeOriginURL(), 1)

	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	const parentID = "00f067aa0ba902b7"
	req := newTracingRequest(http.MethodGet, "/api/v1.0/director/object"+tracingTestNs+"/file.txt")
	req.Header.Set("traceparent", "00-"+traceID+"-"+parentID+"-01")
	w := serveRouter(req)
	require.Equal(t, http.StatusTemporaryRedirect, w.Code)

	redirect := tracingtest.RequireSpan(t, exporter, spanRedirect)
	assert.Equal(t, traceID, redirect.SpanContext.TraceID().String())
	assert.Equal(t, parentID, redirect.Parent.SpanID().String())
	assert.True(t, redirect.Parent.IsRemote())
	for _, s := range exporter.GetSpans() {
		assert.Equal(t, traceID, s.SpanContext.TraceID().String(), "span %s is in the client's trace", s.Name)
	}
	assert.Empty(t, w.Header().Get("traceparent"), "the director adds no tracing header to its response")
}

func TestRedirectSpanOriginRoute(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceDirector))
	setupTracingFederation(t, fakeOriginURL(), 1)

	w := serveRouter(newTracingRequest(http.MethodGet, "/api/v1.0/director/origin"+tracingTestNs+"/file.txt"))
	require.Equal(t, http.StatusTemporaryRedirect, w.Code)

	redirect := tracingtest.RequireSpan(t, exporter, spanRedirect)
	attrs := tracingtest.Attributes(redirect)
	assert.Equal(t, "origin", attrs[string(attrRedirectTarget)])
	assert.Equal(t, []string{"origin.tracing.test:8443"}, attrs[string(attrChosen)])

	sort := tracingtest.RequireSpan(t, exporter, spanSortServers)
	assert.Equal(t, "origin", tracingtest.Attributes(sort)[string(attrServerType)])
	assert.Equal(t, int64(1), tracingtest.Attributes(sort)[string(attrCandidates)])
	requireChildren(t, redirect, sort, tracingtest.RequireSpan(t, exporter, spanMatchNamespace))
}

func TestRedirectSpanSortsOriginsAndCaches(t *testing.T) {
	if raceDetectorEnabled {
		// When getSortedAds sorts origins and caches it runs sortServerAds in
		// two goroutines that both write the one shared redirectInfo:
		// sortServerAds (sort.go) sets DirectorSortMethod and
		// ClientInfo.IpAddr, and the sort algorithms (sort_algorithms.go) set
		// ClientInfo.Coordinate and write ServersInfo.  That race predates
		// tracing; the tracing code reads redirectInfo only in
		// addDecisionEvent, after wg.Wait().  Remove this skip once the race
		// is fixed.
		t.Skip("sorting origins and caches together races on RedirectInfo (pre-existing); skipped under -race")
	}
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceDirector))
	setupTracingFederation(t, fakeOriginURL(), 2)
	require.NoError(t, param.Director_CachesPullFromCaches.Set(true))

	w := serveRouter(newTracingRequest(http.MethodGet, "/api/v1.0/director/origin"+tracingTestNs+"/file.txt?prefercached"))
	require.Equal(t, http.StatusTemporaryRedirect, w.Code)

	redirect := tracingtest.RequireSpan(t, exporter, spanRedirect)
	sorts := tracingtest.SpansNamed(exporter, spanSortServers)
	require.Len(t, sorts, 2)
	types := []any{tracingtest.Attributes(sorts[0])[string(attrServerType)], tracingtest.Attributes(sorts[1])[string(attrServerType)]}
	assert.ElementsMatch(t, []any{"origin", "cache"}, types)
	requireChildren(t, redirect, sorts...)
	// Caches are placed ahead of the origin when chaining, so the client is
	// sent to a cache even though this is the origin route.
	attrs := tracingtest.Attributes(redirect)
	chosen, ok := attrs[string(attrChosen)].([]string)
	require.True(t, ok)
	require.Len(t, chosen, 3)
	assert.True(t, strings.HasPrefix(chosen[0], "cache"), "first chosen host %q is a cache", chosen[0])
	assert.Contains(t, w.Header().Get("Location"), chosen[0])
	assert.Equal(t, "cache", attrs[string(attrRedirectTarget)])
}

func TestRedirectSpanShortcutMiddleware(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceDirector))
	setupTracingFederation(t, fakeOriginURL(), 1)

	for _, mode := range []string{"cache", "origin"} {
		t.Run(mode, func(t *testing.T) {
			exporter.Reset()
			req := newTracingRequest(http.MethodGet, tracingTestNs+"/file.txt")
			w := serveDirect(ShortcutMiddleware(mode), req)
			require.Equal(t, http.StatusTemporaryRedirect, w.Code)

			redirect := tracingtest.RequireSpan(t, exporter, spanRedirect)
			assert.Equal(t, mode, tracingtest.Attributes(redirect)[string(attrRedirectTarget)])
			assert.Equal(t, tracingTestNs+"/file.txt", tracingtest.Attributes(redirect)[string(tracing.AttrObjectPath)])
		})
	}

	// Through the hostname redirect, which rewrites the path before calling
	// the handler.
	t.Run("host-header", func(t *testing.T) {
		exporter.Reset()
		require.NoError(t, param.Director_OriginResponseHostnames.Set([]string{"origin-hostname.tracing.test"}))
		req := newTracingRequest(http.MethodGet, tracingTestNs+"/file.txt")
		req.Header.Set("Host", "origin-hostname.tracing.test")
		w := serveDirect(ShortcutMiddleware("cache"), req)
		require.Equal(t, http.StatusTemporaryRedirect, w.Code)
		redirect := tracingtest.RequireSpan(t, exporter, spanRedirect)
		assert.Equal(t, "origin", tracingtest.Attributes(redirect)[string(attrRedirectTarget)])
	})
}

func TestRedirectSpanNamespaceNotFound(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceDirector))
	setupTracingFederation(t, fakeOriginURL(), 1)

	w := serveRouter(newTracingRequest(http.MethodGet, "/api/v1.0/director/object/no/such/namespace/file.txt"))
	require.Equal(t, http.StatusNotFound, w.Code)

	// A 404 is the client's outcome: the error is attached, the span is not
	// failed.
	redirect := tracingtest.RequireSpan(t, exporter, spanRedirect)
	assert.Equal(t, int64(http.StatusNotFound), tracingtest.Attributes(redirect)["http.response.status_code"])
	assert.Equal(t, codes.Unset, redirect.Status.Code)
	assert.Contains(t, exceptionMessage(t, redirect), "/no/such/namespace/file.txt")
	assert.NotContains(t, tracingtest.Attributes(redirect), string(tracing.AttrNamespace))

	// The stage is not failed either, and does not repeat the error its
	// handler attached to the request's span.
	match := tracingtest.RequireSpan(t, exporter, spanMatchNamespace)
	assert.Equal(t, codes.Unset, match.Status.Code)
	assert.Empty(t, match.Events)
	tracingtest.RequireParent(t, redirect, match)
	assert.Empty(t, tracingtest.SpansNamed(exporter, spanSortServers))
}

func TestRedirectSpanStatHead(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceDirector))
	recorder := &headRecorder{}
	origin := httptest.NewServer(recorder)
	t.Cleanup(origin.Close)
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)
	setupTracingFederation(t, *originURL, 0)
	require.NoError(t, param.Director_CheckOriginPresence.Set(true))

	w := serveRouter(newTracingRequest(http.MethodGet, "/api/v1.0/director/origin"+tracingTestNs+"/stat-me.txt"))
	require.Equal(t, http.StatusTemporaryRedirect, w.Code)

	redirect := tracingtest.RequireSpan(t, exporter, spanRedirect)
	stat := tracingtest.RequireSpan(t, exporter, spanStatServers)
	tracingtest.RequireParent(t, redirect, stat)
	statAttrs := tracingtest.Attributes(stat)
	assert.Equal(t, int64(1), statAttrs[string(attrStatQueried)])
	assert.Equal(t, int64(1), statAttrs[string(attrStatAvailable)])

	// The HEAD (sent with a digest request first) is a child of the stat span.
	heads := tracingtest.SpansNamed(exporter, http.MethodHead)
	require.NotEmpty(t, heads)
	for _, head := range heads {
		tracingtest.RequireParent(t, stat, head)
		assert.Equal(t, int64(http.StatusOK), tracingtest.Attributes(head)["http.response.status_code"])
	}

	n, traceparents := recorder.snapshot()
	require.Equal(t, len(heads), n)
	for _, tp := range traceparents {
		require.NotEmpty(t, tp, "the stat HEAD carries traceparent")
		assert.Contains(t, tp, redirect.SpanContext.TraceID().String())
	}
}

func TestRedirectSpanSkipped(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceDirector))
	setupTracingFederation(t, fakeOriginURL(), 1)

	t.Run("put", func(t *testing.T) {
		exporter.Reset()
		serveRouter(newTracingRequest(http.MethodPut, "/api/v1.0/director/origin"+tracingTestNs+"/file.txt"))
		tracingtest.RequireNoSpans(t, exporter)
	})

	t.Run("delete", func(t *testing.T) {
		exporter.Reset()
		serveRouter(newTracingRequest(http.MethodDelete, "/api/v1.0/director/origin"+tracingTestNs+"/file.txt"))
		tracingtest.RequireNoSpans(t, exporter)
	})

	t.Run("put-through-middleware", func(t *testing.T) {
		exporter.Reset()
		serveDirect(ShortcutMiddleware("cache"), newTracingRequest(http.MethodPut, tracingTestNs+"/file.txt"))
		tracingtest.RequireNoSpans(t, exporter)
	})

	t.Run("monitoring", func(t *testing.T) {
		exporter.Reset()
		w := serveRouter(newTracingRequest(http.MethodGet, "/api/v1.0/director/origin"+server_utils.MonitoringBaseNs+"/test.txt"))
		require.Equal(t, http.StatusTemporaryRedirect, w.Code)
		tracingtest.RequireNoSpans(t, exporter)
	})

	// The exclusion is by object path, so it holds on the cache route and for
	// the bare monitoring prefix, whatever those requests answer.
	for _, target := range []string{
		"/api/v1.0/director/object" + server_utils.MonitoringBaseNs + "/directorTest/test.txt",
		"/api/v1.0/director/object" + server_utils.MonitoringBaseNs,
		"/api/v1.0/director/origin" + server_utils.MonitoringBaseNs,
	} {
		t.Run("monitoring"+strings.ReplaceAll(target, "/", "-"), func(t *testing.T) {
			exporter.Reset()
			w := serveRouter(newTracingRequest(http.MethodGet, target))
			require.NotZero(t, w.Code)
			tracingtest.RequireNoSpans(t, exporter)
		})
	}

	t.Run("director-ui-stat-path", func(t *testing.T) {
		// getSortedAds called without a redirect span starts no trace.
		exporter.Reset()
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = newTracingRequest(http.MethodGet, "/api/v1.0/director_ui/servers/origins/stat"+tracingTestNs+"/file.txt")
		_, _, err := getSortedAds(c, [16]byte{})
		require.NoError(t, err)
		tracingtest.RequireNoSpans(t, exporter)
	})
}

// runRedirectForComparison sends the same GET through the cache route and
// returns the response.
func runRedirectForComparison(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	req := newTracingRequest(http.MethodGet, "/api/v1.0/director/object"+tracingTestNs+"/compare.txt")
	req.Header.Set("X-Pelican-Coordinate", "lat=43.07, long=-89.40")
	return serveRouter(req)
}

func TestRedirectTracingDisabled(t *testing.T) {
	recorder := &headRecorder{}
	origin := httptest.NewServer(recorder)
	t.Cleanup(origin.Close)
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)
	setupTracingFederation(t, *originURL, 1)
	// Origin stats on, via the origin route, so the disabled run sends a HEAD.
	require.NoError(t, param.Director_CheckOriginPresence.Set(true))

	tracingtest.Disabled(t)
	statResp := serveRouter(newTracingRequest(http.MethodGet, "/api/v1.0/director/origin"+tracingTestNs+"/disabled-stat.txt"))
	require.Equal(t, http.StatusTemporaryRedirect, statResp.Code)
	n, traceparents := recorder.snapshot()
	require.Positive(t, n)
	for _, tp := range traceparents {
		assert.Empty(t, tp, "no traceparent is sent while tracing is disabled")
	}

	disabled := runRedirectForComparison(t)
	require.Equal(t, http.StatusTemporaryRedirect, disabled.Code)

	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceDirector))
	enabled := runRedirectForComparison(t)
	require.Equal(t, http.StatusTemporaryRedirect, enabled.Code)
	tracingtest.RequireSpan(t, exporter, spanRedirect)

	assert.Equal(t, disabled.Code, enabled.Code)
	assert.Equal(t, disabled.Header(), enabled.Header(), "tracing does not change the response headers")
	assert.Equal(t, disabled.Body.String(), enabled.Body.String())
	for _, h := range []string{"Location", "Link", "X-Pelican-Namespace", "X-Pelican-Authorization", "X-Pelican-Token-Generation", "X-Pelican-JobId"} {
		assert.Equal(t, disabled.Header().Values(h), enabled.Header().Values(h), "header %s", h)
	}
	assert.NotEmpty(t, enabled.Header().Get("Location"))
	assert.NotEmpty(t, enabled.Header().Get("Link"))
}

func TestRedirectSpansHoldNoToken(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceDirector))
	recorder := &headRecorder{}
	origin := httptest.NewServer(recorder)
	t.Cleanup(origin.Close)
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)
	setupTracingFederation(t, *originURL, 1)
	require.NoError(t, param.Director_CheckOriginPresence.Set(true))

	const secret = "not-a-jwt-but-very-secret-token-5f2d"
	for _, target := range []string{
		"/api/v1.0/director/origin" + tracingTestNs + "/token.txt?authz=" + secret,
		"/api/v1.0/director/object" + tracingTestNs + "/token.txt?authz=Bearer%20" + secret,
		"/api/v1.0/director/object/no/such/ns/token.txt?authz=" + secret,
	} {
		w := serveRouter(newTracingRequest(http.MethodGet, target))
		require.NotZero(t, w.Code)
	}
	req := newTracingRequest(http.MethodGet, "/api/v1.0/director/origin"+tracingTestNs+"/header-token.txt")
	req.Header.Set("Authorization", "Bearer "+secret)
	serveRouter(req)

	spans := exporter.GetSpans()
	require.NotEmpty(t, tracingtest.SpansNamed(exporter, spanRedirect))
	require.NotEmpty(t, tracingtest.SpansNamed(exporter, http.MethodHead), "the token-bearing stat was traced")
	for _, s := range spans {
		assert.NotContains(t, s.Status.Description, secret, "span %s status", s.Name)
		for _, kv := range s.Attributes {
			assert.NotContains(t, kv.Value.Emit(), secret, "span %s attribute %s", s.Name, kv.Key)
		}
		for _, ev := range s.Events {
			assert.NotContains(t, ev.Name, secret)
			for _, kv := range ev.Attributes {
				assert.NotContains(t, kv.Value.Emit(), secret, "span %s event %s attribute %s", s.Name, ev.Name, kv.Key)
			}
		}
	}
}

// exceptionMessage returns the message of the one "exception" event on span.
func exceptionMessage(t *testing.T, span tracetest.SpanStub) string {
	t.Helper()
	var found []string
	for _, ev := range span.Events {
		if ev.Name != "exception" {
			continue
		}
		for _, kv := range ev.Attributes {
			if kv.Key == "exception.message" {
				found = append(found, kv.Value.AsString())
			}
		}
	}
	require.Len(t, found, 1, "expected one exception event on %s", span.Name)
	return found[0]
}

// expiredToken returns a signed JWT that expired a minute ago.
func expiredToken(t *testing.T) string {
	t.Helper()
	privEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.FromRaw(privEC)
	require.NoError(t, err)
	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer("https://issuer.tracing.test").
		Subject("tracing-user").
		IssuedAt(now.Add(-10 * time.Minute)).
		Expiration(now.Add(-time.Minute)).
		Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, key))
	require.NoError(t, err)
	return string(signed)
}

func TestRedirectSpanSortFailure(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceDirector))
	setupTracingFederation(t, fakeOriginURL(), 1)
	require.NoError(t, param.Director_CacheSortMethod.Set("no-such-sort"))

	w := serveRouter(newTracingRequest(http.MethodGet, "/api/v1.0/director/object"+tracingTestNs+"/file.txt"))
	require.Equal(t, http.StatusInternalServerError, w.Code)

	// The director failed: the status code fails the redirect span, and the
	// real reason is in its exception event.
	redirect := tracingtest.RequireSpan(t, exporter, spanRedirect)
	assert.Equal(t, int64(http.StatusInternalServerError), tracingtest.Attributes(redirect)["http.response.status_code"])
	assert.Equal(t, codes.Error, redirect.Status.Code)
	assert.Contains(t, exceptionMessage(t, redirect), "invalid sort method 'no-such-sort'")

	sort := tracingtest.RequireSpan(t, exporter, spanSortServers)
	assert.Equal(t, codes.Error, sort.Status.Code)
	assert.Contains(t, sort.Status.Description, "invalid sort method 'no-such-sort'")
	tracingtest.RequireParent(t, redirect, sort)

	match := tracingtest.RequireSpan(t, exporter, spanMatchNamespace)
	assert.Equal(t, codes.Unset, match.Status.Code)
}

func TestRedirectSpanClientErrorsNotFailed(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceDirector))
	setupTracingFederation(t, fakeOriginURL(), 1)

	t.Run("expired-token", func(t *testing.T) {
		exporter.Reset()
		req := newTracingRequest(http.MethodGet, "/api/v1.0/director/object"+tracingTestNs+"/file.txt")
		req.Header.Set("Authorization", "Bearer "+expiredToken(t))
		w := serveRouter(req)
		require.Equal(t, http.StatusUnauthorized, w.Code)

		redirect := tracingtest.RequireSpan(t, exporter, spanRedirect)
		assert.Equal(t, int64(http.StatusUnauthorized), tracingtest.Attributes(redirect)["http.response.status_code"])
		assert.Equal(t, codes.Unset, redirect.Status.Code)
		assert.Contains(t, exceptionMessage(t, redirect), "expired")
		for _, s := range exporter.GetSpans() {
			assert.Equal(t, codes.Unset, s.Status.Code, "span %s", s.Name)
		}
	})

	t.Run("startup", func(t *testing.T) {
		exporter.Reset()
		// setupTracingFederation restores the start-up time on cleanup.
		SetStartupTime(time.Now())
		w := serveRouter(newTracingRequest(http.MethodGet, "/api/v1.0/director/object/no/such/namespace/file.txt"))
		require.Equal(t, http.StatusTooManyRequests, w.Code)

		redirect := tracingtest.RequireSpan(t, exporter, spanRedirect)
		assert.Equal(t, int64(http.StatusTooManyRequests), tracingtest.Attributes(redirect)["http.response.status_code"])
		assert.Equal(t, codes.Unset, redirect.Status.Code)
		assert.NotEmpty(t, exceptionMessage(t, redirect))
		match := tracingtest.RequireSpan(t, exporter, spanMatchNamespace)
		assert.Equal(t, codes.Unset, match.Status.Code)
	})
}

func TestRedirectSpanDecisionCoordinateRounded(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceDirector))
	setupTracingFederation(t, fakeOriginURL(), 1)

	req := newTracingRequest(http.MethodGet, "/api/v1.0/director/object"+tracingTestNs+"/file.txt")
	req.Header.Set("X-Pelican-Coordinate", "lat=43.0731, long=-89.4012")
	req.Header.Set("X-Pelican-Debug", "true")
	w := serveRouter(req)
	require.Equal(t, http.StatusTemporaryRedirect, w.Code)

	// The debug client still gets the exact coordinate.
	var debugInfo server_structs.RedirectInfo
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &debugInfo))
	assert.Equal(t, 43.0731, debugInfo.ClientInfo.Coordinate.Lat)
	assert.Equal(t, -89.4012, debugInfo.ClientInfo.Coordinate.Long)
	assert.Equal(t, "192.0.2.1", debugInfo.ClientInfo.IpAddr)

	// The trace gets it to one decimal place, and the masked address.
	info := decisionEvent(t, tracingtest.RequireSpan(t, exporter, spanRedirect))
	assert.Equal(t, 43.1, info.ClientInfo.Coordinate.Lat)
	assert.Equal(t, -89.4, info.ClientInfo.Coordinate.Long)
	assert.Equal(t, "192.0.2.0", info.ClientInfo.IpAddr)
	assert.Len(t, info.ServersInfo, len(debugInfo.ServersInfo))
}

func TestRedirectSpanHead(t *testing.T) {
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceDirector))
	setupTracingFederation(t, fakeOriginURL(), 1)

	w := serveRouter(newTracingRequest(http.MethodHead, "/api/v1.0/director/object"+tracingTestNs+"/file.txt"))
	require.Equal(t, http.StatusTemporaryRedirect, w.Code)

	redirect := tracingtest.RequireSpan(t, exporter, spanRedirect)
	attrs := tracingtest.Attributes(redirect)
	assert.Equal(t, http.MethodHead, attrs["http.request.method"])
	assert.Equal(t, "cache", attrs[string(attrRedirectTarget)])
	requireChildren(t, redirect, tracingtest.RequireSpan(t, exporter, spanMatchNamespace), tracingtest.RequireSpan(t, exporter, spanSortServers))
}

func TestRedirectTracingSampledOut(t *testing.T) {
	setupTracingFederation(t, fakeOriginURL(), 1)

	tracingtest.Disabled(t)
	disabled := runRedirectForComparison(t)
	require.Equal(t, http.StatusTemporaryRedirect, disabled.Code)

	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceDirector), tracingtest.WithSamplePercentage(0))
	sampledOut := runRedirectForComparison(t)
	tracingtest.RequireNoSpans(t, exporter)

	assert.Equal(t, disabled.Code, sampledOut.Code)
	assert.Equal(t, disabled.Header(), sampledOut.Header())
	assert.Equal(t, disabled.Body.String(), sampledOut.Body.String())
}

// TestRedirectSpanRequestAfterHandler checks what middleware that runs after
// the handler (the access logger and metrics in web_ui) sees: the same method
// and path whether or not the request was traced, although the traced request
// stays on the gin context.
func TestRedirectSpanRequestAfterHandler(t *testing.T) {
	setupTracingFederation(t, fakeOriginURL(), 1)

	type seen struct{ method, path string }
	run := func() seen {
		var s seen
		engine := gin.New()
		engine.Use(func(c *gin.Context) {
			c.Next()
			s = seen{c.Request.Method, c.Request.URL.Path}
		})
		engine.Use(ShortcutMiddleware("cache"))
		engine.ServeHTTP(httptest.NewRecorder(), newTracingRequest(http.MethodGet, tracingTestNs+"/file.txt"))
		return s
	}

	tracingtest.Disabled(t)
	disabled := run()
	exporter := tracingtest.Setup(t, tracingtest.WithDefaultService(tracing.ServiceDirector))
	enabled := run()
	tracingtest.RequireSpan(t, exporter, spanRedirect)

	assert.Equal(t, seen{http.MethodGet, "/api/v1.0/director/object" + tracingTestNs + "/file.txt"}, disabled)
	assert.Equal(t, disabled, enabled)
}

// TestRedirectTracingHelpersAllocateNothing guards the rule that with tracing
// disabled the redirect path pays no more than a boolean check: none of the
// tracing helpers allocates.
func TestRedirectTracingHelpersAllocateNothing(t *testing.T) {
	tracingtest.Disabled(t)
	setGinTestMode()

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = newTracingRequest(http.MethodGet, "/api/v1.0/director/object"+tracingTestNs+"/file.txt")
	ctx := c.Request.Context()
	requestId := [16]byte{1}
	sortErr := fmt.Errorf("sort failed")
	nsAd := server_structs.NamespaceAd{Path: tracingTestNs}
	ads := []copyAd{{NamespaceAd: nsAd}}
	chosen := []server_structs.ServerAd{{Type: server_structs.CacheType.String()}}
	info := server_structs.NewRedirectInfoFromIP("192.0.2.1")
	var qr queryResult

	allocs := testing.AllocsPerRun(100, func() {
		span := startRedirectSpan(c)
		recordRequestID(span, requestId)

		match := startMatchNamespaceSpan(c)
		recordNamespace(c, match, ads)
		match.End()
		recordCandidates(c, 1, 2)

		_, stat := startStatSpan(c, 3)
		endStatSpan(stat, qr)

		sortCtx, sort := startSortSpan(ctx, false, 2, server_structs.AdaptiveType)
		recordCoordinateSource(sortCtx, coordSourceHeader)
		recordSortFallback(sort, sortErr, server_structs.DistanceType)
		_ = recordSortError(sort, sortErr)
		sort.End()

		addDecisionEvent(c, info)
		noteRedirectFailure(span, "no caches")
		tracing.NoteError(span, sortErr)
		recordRedirectChoice(span, c, chosen, nsAd)
		tracing.EndServerDeferred(span, c.Writer)
	})
	assert.Zero(t, allocs, "tracing helpers allocate while tracing is disabled")
}
