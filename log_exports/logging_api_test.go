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

package log_exports

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token_scopes"
)

func TestParseLogSelectorTimeWindow(t *testing.T) {
	now := fixedClock(time.Date(2026, 8, 20, 18, 5, 0, 0, time.UTC))

	t.Run("valid bucket is one UTC hour", func(t *testing.T) {
		sel, err := parseLogSelector("/2026/08/20/15.log", now)
		require.NoError(t, err)
		start, end := sel.Bounds()
		assert.Equal(t, time.Date(2026, 8, 20, 15, 0, 0, 0, time.UTC), start)
		assert.Equal(t, time.Date(2026, 8, 20, 16, 0, 0, 0, time.UTC), end)
	})

	t.Run("the .log suffix is optional and means the same window", func(t *testing.T) {
		withSuffix, err := parseLogSelector("/2026/08/20/15.log", now)
		require.NoError(t, err)
		without, err := parseLogSelector("/2026/08/20/15", now)
		require.NoError(t, err)

		s1, e1 := withSuffix.Bounds()
		s2, e2 := without.Bounds()
		assert.Equal(t, s1, s2)
		assert.Equal(t, e1, e2)
	})

	// Each of these is the shape of a real client mistake, and each must be a
	// 400 that names the window rather than a 404 or a silently wrong answer.
	for _, tc := range []struct {
		name string
		path string
	}{
		{"month out of range", "/2026/13/20/15"},
		{"month zero", "/2026/00/20/15"},
		{"day out of range", "/2026/08/32/15"},
		{"hour out of range", "/2026/08/20/24"},
		{"day absent from month", "/2026/02/31/15"},
		{"too few segments", "/2026/08/20"},
		{"too many segments", "/2026/08/20/15/30"},
		{"non-numeric hour", "/2026/08/20/xx"},
		// One window, one spelling: every accepted variant is a separate URL
		// -- a separate cache key -- for the same bytes, so widths are fixed
		// and only the .log suffix may vary.
		{"unpadded month", "/2026/8/20/15"},
		{"unpadded day", "/2026/08/2/15"},
		{"unpadded hour", "/2026/08/20/5"},
		{"overlong hour", "/2026/08/20/015"},
		{"signed hour", "/2026/08/20/+5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseLogSelector(tc.path, now)
			require.Error(t, err)
			// Malformed, not unrecognized: the caller asked for a time window
			// and spelled it wrong, which is a different fix than asking for
			// something this server does not serve.
			assert.ErrorIs(t, err, errMalformedWindow)
			assert.NotErrorIs(t, err, errUnknownSelectorKind)
		})
	}
}

func TestParseLogSelectorReservedNamespace(t *testing.T) {
	now := fixedClock(time.Date(2026, 8, 20, 18, 5, 0, 0, time.UTC))

	// A non-numeric leading segment names a kind of selector.  None exist:
	// there is deliberately no way to ask for "the last hour", because recent
	// activity is what the in-memory buffer behind /api/v1.0/logs/tail is for,
	// and because keeping every servable window closed is what lets every
	// response be immutable.
	//
	// The error still has to say "unknown kind" rather than "malformed date",
	// so that adding /job/{uuid} later is additive and does not change what
	// today's errors mean.
	for _, path := range []string{"/latest", "/latest.log", "/job/abc-123", "/metrics/5m", "/uuid"} {
		t.Run(path, func(t *testing.T) {
			_, err := parseLogSelector(path, now)
			require.Error(t, err)
			assert.ErrorIs(t, err, errUnknownSelectorKind)
			assert.NotErrorIs(t, err, errMalformedWindow)
		})
	}

	t.Run("empty path", func(t *testing.T) {
		_, err := parseLogSelector("/", now)
		require.Error(t, err)
		assert.ErrorIs(t, err, errUnknownSelectorKind)
	})
}

func TestValidateSitenameForURL(t *testing.T) {
	// Nothing else in Pelican constrains a sitename, but here it has to
	// survive being a path segment, the value compared against the decoded
	// :sitename parameter, and part of a token scope.
	for _, name := range []string{"uw-origin", "UW_OSDF_ORIGIN", "origin1.example.com", "a.b-c_d"} {
		t.Run("accepts "+name, func(t *testing.T) {
			assert.NoError(t, validateSitenameForURL(name))
		})
	}

	for _, tc := range []struct{ name, sitename string }{
		{"empty", ""},
		{"space", "uw origin"},
		{"slash", "uw/origin"},
		{"question mark", "uw?origin"},
		{"fragment", "uw#origin"},
		{"dot", "."},
		{"dot dot", ".."},
		{"percent", "uw%20origin"},
		{"non-ascii", "uw-orígen"},
	} {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			assert.Error(t, validateSitenameForURL(tc.sitename))
		})
	}
}

// stubSource serves a fixed body and coverage, so handler tests can assert on
// status and headers without a log file.  It is its own reader: Open returns
// the stub itself, which keeps the handler exercising the real open/close
// sequence without a file behind it.
type stubSource struct {
	body     string
	oldest   time.Time
	covered  bool
	readErr  error
	readCall int
}

func (s *stubSource) Open(context.Context) (logReader, error) { return s, nil }

func (s *stubSource) Close() error { return nil }

func (s *stubSource) Coverage(context.Context) (time.Time, bool, error) {
	return s.oldest, s.covered, nil
}

func (s *stubSource) Read(_ context.Context, _ logSelector, w io.Writer) error {
	s.readCall++
	if _, err := w.Write([]byte(s.body)); err != nil {
		return err
	}
	return s.readErr
}

// newLoggingEngine mounts the real routes with authorization stubbed, so the
// tests exercise the handler rather than the token stack.
func newLoggingEngine(t *testing.T, sitename string, src logSource, now time.Time) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	h := &loggingHandler{
		sitename:  sitename,
		scope:     token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, LoggingNamespaceForSitename(sitename)),
		source:    src,
		now:       fixedClock(now),
		sem:       make(chan struct{}, maxConcurrentLogReads),
		authorize: func(*gin.Context) bool { return true },
	}
	registerLoggingRoutes(engine, h)
	return engine
}

func do(t *testing.T, engine *gin.Engine, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestLoggingHandlerSitenameMismatch(t *testing.T) {
	now := time.Date(2026, 8, 20, 18, 30, 0, 0, time.UTC)
	src := &stubSource{body: "entries\n", covered: true}
	engine := newLoggingEngine(t, "uw-origin", src, now)

	// The namespace is per-server.  A request naming a different server has
	// reached the wrong host, and answering it would be answering for someone
	// else's logs.
	rec := do(t, engine, http.MethodGet, "/pelican/logging/other-origin/2026/08/20/15.log")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Zero(t, src.readCall, "a mismatched sitename must be refused before any log is read")
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"),
		"a refusal is never a durable answer and must not be cached")
}

func TestLoggingHandlerMalformedPath(t *testing.T) {
	now := time.Date(2026, 8, 20, 18, 30, 0, 0, time.UTC)
	src := &stubSource{covered: true}
	engine := newLoggingEngine(t, "uw-origin", src, now)

	rec := do(t, engine, http.MethodGet, "/pelican/logging/uw-origin/2026/13/20/15.log")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Zero(t, src.readCall)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"),
		"a refusal is never a durable answer and must not be cached")
}

func TestLoggingHandlerServesWindow(t *testing.T) {
	now := time.Date(2026, 8, 20, 18, 30, 0, 0, time.UTC)
	src := &stubSource{
		body:    "one\ntwo\n",
		oldest:  time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC),
		covered: true,
	}
	engine := newLoggingEngine(t, "uw-origin", src, now)

	rec := do(t, engine, http.MethodGet, "/pelican/logging/uw-origin/2026/08/20/15.log")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "one\ntwo\n", rec.Body.String())
	assert.Equal(t, "text/plain; charset=utf-8", rec.Header().Get("Content-Type"))
}

func TestLoggingHandlerEmptyWindowIsOK(t *testing.T) {
	now := time.Date(2026, 8, 20, 18, 30, 0, 0, time.UTC)
	src := &stubSource{
		body:    "",
		oldest:  time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC),
		covered: true,
	}
	engine := newLoggingEngine(t, "uw-origin", src, now)

	// An hour in which the server logged nothing is a real answer, not a 404.
	rec := do(t, engine, http.MethodGet, "/pelican/logging/uw-origin/2026/08/20/15.log")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Body.String())
}

func TestLoggingHandlerHead(t *testing.T) {
	now := time.Date(2026, 8, 20, 18, 30, 0, 0, time.UTC)
	src := &stubSource{
		body:    "one\ntwo\n",
		oldest:  time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC),
		covered: true,
	}
	engine := newLoggingEngine(t, "uw-origin", src, now)

	// The Director stats a server with HEAD before redirecting to it, and
	// the presence checks are on by default.  Without this route that stat
	// draws a 405 and the server drops out of routing entirely.
	rec := do(t, engine, http.MethodHead, "/pelican/logging/uw-origin/2026/08/20/15.log")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/plain; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Zero(t, src.readCall,
		"a presence check should not cost a scan of the log file")
}

func TestLoggingHandlerCacheDirectives(t *testing.T) {
	// 18:30, so the 18:00 bucket is still open while the 15:00 one is closed.
	now := time.Date(2026, 8, 20, 18, 30, 0, 0, time.UTC)
	wellCovered := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)

	t.Run("closed and covered is immutable", func(t *testing.T) {
		engine := newLoggingEngine(t, "uw-origin",
			&stubSource{oldest: wellCovered, covered: true}, now)
		rec := do(t, engine, http.MethodGet, "/pelican/logging/uw-origin/2026/08/20/15.log")
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Header().Get("Cache-Control"), "immutable")
	})

	t.Run("an unsettled window is refused rather than served uncacheably", func(t *testing.T) {
		// Everything this endpoint serves has finished and settled, so there
		// is no such thing as a served-but-uncacheable window.  That is what
		// removes the need to keep any response away from a cache.
		engine := newLoggingEngine(t, "uw-origin",
			&stubSource{oldest: wellCovered, covered: true}, now)
		rec := do(t, engine, http.MethodGet, "/pelican/logging/uw-origin/2026/08/20/18.log")
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("a rotated-away window is not cacheable", func(t *testing.T) {
		// The log now only reaches back to 17:00, so the 15:00 bucket comes
		// back empty because its entries were rotated away -- not because
		// nothing happened then.  Marking that immutable would let a cache
		// pin an empty answer for a real hour, permanently.
		engine := newLoggingEngine(t, "uw-origin",
			&stubSource{oldest: time.Date(2026, 8, 20, 17, 0, 0, 0, time.UTC), covered: true}, now)
		rec := do(t, engine, http.MethodGet, "/pelican/logging/uw-origin/2026/08/20/15.log")
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	})

	t.Run("an empty log covers nothing", func(t *testing.T) {
		engine := newLoggingEngine(t, "uw-origin", &stubSource{covered: false}, now)
		rec := do(t, engine, http.MethodGet, "/pelican/logging/uw-origin/2026/08/20/15.log")
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	})
}

// TestRegisterLoggingExportAPIDisabled covers the exported entry point's
// opt-in gate.  A server that has not enabled log export must mount nothing,
// so the endpoint 404s by absence rather than existing only to refuse.
func TestRegisterLoggingExportAPIDisabled(t *testing.T) {
	prev := param.Logging_LogExports_Enabled.GetBool()
	require.NoError(t, param.Logging_LogExports_Enabled.Set(false))
	t.Cleanup(func() { _ = param.Logging_LogExports_Enabled.Set(prev) })

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	require.NoError(t, RegisterLoggingExportAPI(context.Background(), engine, server_structs.OriginType))

	rec := do(t, engine, http.MethodGet, "/pelican/logging/uw-origin/2026/08/20/15.log")
	assert.Equal(t, http.StatusNotFound, rec.Code, "a disabled server must have no such route")
}

// TestRegisterLoggingExportForWiring exercises everything the exported
// registration does once the server's name is known.  This is the region the
// route actually gets assembled in -- and the region a missing middleware
// argument hid in until it was audited -- so it is worth reaching directly
// rather than only through the unexported route mounting.
func TestRegisterLoggingExportForWiring(t *testing.T) {
	t.Run("rejects a sitename that is not URL-safe", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		engine := gin.New()
		err := registerLoggingExportFor(engine, "uw origin/bad")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "uw origin/bad",
			"the error should name the offending value so an admin can fix it")
	})

	t.Run("mounts a working route for a valid sitename", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		engine := gin.New()
		require.NoError(t, registerLoggingExportFor(engine, "uw-origin"))

		// Real registration wires the real token check, so an unauthenticated
		// request must be refused rather than served.  What matters here is
		// that the route exists and reaches the handler at all.
		rec := do(t, engine, http.MethodGet, "/pelican/logging/uw-origin/2026/08/20/15.log")
		assert.NotEqual(t, http.StatusNotFound, rec.Code, "the route should be mounted")
		assert.Equal(t, http.StatusForbidden, rec.Code, "and should refuse an unauthenticated caller")
	})

	t.Run("supplied middleware reaches the mounted route", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		engine := gin.New()
		var ran int
		require.NoError(t, registerLoggingExportFor(engine, "uw-origin",
			func(c *gin.Context) { ran++; c.Next() }))

		do(t, engine, http.MethodGet, "/pelican/logging/uw-origin/2026/08/20/15.log")
		assert.Equal(t, 1, ran, "middleware handed to the exported API must be attached")
	})

	t.Run("both methods are mounted", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		engine := gin.New()
		require.NoError(t, registerLoggingExportFor(engine, "uw-origin"))

		for _, method := range []string{http.MethodGet, http.MethodHead} {
			rec := do(t, engine, method, "/pelican/logging/uw-origin/2026/08/20/15.log")
			assert.NotEqual(t, http.StatusMethodNotAllowed, rec.Code,
				"%s must be routed -- the Director stats with HEAD and a 405 drops this server from routing", method)
		}
	})

	t.Run("registration is server-type-agnostic", func(t *testing.T) {
		// Nothing below the name lookup knows what kind of server this is:
		// anything server-specific, like a server type's metrics middleware,
		// is the launcher's to supply.  A cache's sitename mounts on the same
		// terms as an origin's.
		gin.SetMode(gin.TestMode)
		engine := gin.New()
		require.NoError(t, registerLoggingExportFor(engine, "uw-cache"))

		rec := do(t, engine, http.MethodGet, "/pelican/logging/uw-cache/2026/08/20/15.log")
		assert.NotEqual(t, http.StatusNotFound, rec.Code, "the route should be mounted for a cache's sitename")
	})
}

func TestLoggingRoutesRunSuppliedMiddleware(t *testing.T) {
	// Middleware is threaded in from the launcher rather than imported here,
	// which makes it easy to mount the group and forget to pass anything --
	// exactly what happened once.  Assert it actually runs, on both methods.
	now := time.Date(2026, 8, 20, 18, 30, 0, 0, time.UTC)

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			engine := gin.New()

			var ran int
			h := &loggingHandler{
				sitename:  "uw-origin",
				source:    &stubSource{oldest: time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC), covered: true},
				now:       fixedClock(now),
				sem:       make(chan struct{}, maxConcurrentLogReads),
				authorize: func(*gin.Context) bool { return true },
			}
			registerLoggingRoutes(engine, h, func(c *gin.Context) {
				ran++
				c.Header("X-Test-Middleware", "ran")
				c.Next()
			})

			rec := do(t, engine, method, "/pelican/logging/uw-origin/2026/08/20/15.log")
			require.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, 1, ran, "supplied middleware must run for %s", method)
			assert.Equal(t, "ran", rec.Header().Get("X-Test-Middleware"))
		})
	}
}

func TestLoggingHandlerSettleMargin(t *testing.T) {
	// The trap this guards: an hour ending is not the same as all of its
	// entries being on disk.  The async writer holds entries until a size
	// threshold or the flush interval pushes them out, so serving an hour the
	// instant it ends would hand out a copy missing its tail -- and a cache
	// would keep that copy for good, since Cache-Control decides whether a
	// response is stored, not whether a stored one is dropped.
	wellCovered := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	src := func() *stubSource { return &stubSource{oldest: wellCovered, covered: true} }

	// The 17:00 bucket ends at 18:00, so it becomes servable at 18:05.
	for _, tc := range []struct {
		name  string
		now   time.Time
		want  int
		cache string
	}{
		{"during the hour itself", time.Date(2026, 8, 20, 17, 30, 0, 0, time.UTC), http.StatusNotFound, "no-store"},
		{"the instant it ends", time.Date(2026, 8, 20, 18, 0, 0, 0, time.UTC), http.StatusNotFound, "no-store"},
		{"one minute after", time.Date(2026, 8, 20, 18, 1, 0, 0, time.UTC), http.StatusNotFound, "no-store"},
		{"just short of the margin", time.Date(2026, 8, 20, 18, 4, 59, 0, time.UTC), http.StatusNotFound, "no-store"},
		{"exactly at the margin", time.Date(2026, 8, 20, 18, 5, 0, 0, time.UTC), http.StatusOK, "immutable"},
		{"well after", time.Date(2026, 8, 20, 19, 0, 0, 0, time.UTC), http.StatusOK, "immutable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := src()
			engine := newLoggingEngine(t, "uw-origin", s, tc.now)
			rec := do(t, engine, http.MethodGet, "/pelican/logging/uw-origin/2026/08/20/17.log")
			require.Equal(t, tc.want, rec.Code)
			// The refusal must itself be no-store: RFC 9111 makes a 404
			// heuristically cacheable, so an unmarked "not available yet"
			// could be stored by a cache on the path and outlive the settle
			// margin that justified it.
			assert.Contains(t, rec.Header().Get("Cache-Control"), tc.cache)
			if tc.want == http.StatusNotFound {
				assert.Zero(t, s.readCall, "an unsettled window must not be read")
			}
		})
	}
}

func TestLoggingHandlerAuthorizesBeforeInterpretingRequest(t *testing.T) {
	// An unauthenticated caller should not be able to learn which paths parse
	// or which windows exist, so authorization runs before both checks.
	now := time.Date(2026, 8, 20, 18, 30, 0, 0, time.UTC)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	h := &loggingHandler{
		sitename: "uw-origin",
		source:   &stubSource{covered: true},
		now:      fixedClock(now),
		sem:      make(chan struct{}, maxConcurrentLogReads),
		authorize: func(c *gin.Context) bool {
			c.Status(http.StatusForbidden)
			return false
		},
	}
	registerLoggingRoutes(engine, h)

	for _, path := range []string{
		"/pelican/logging/uw-origin/2026/13/40/99.log", // malformed
		"/pelican/logging/uw-origin/2026/08/20/18.log", // unsettled
		"/pelican/logging/uw-origin/nonsense",          // unknown kind
	} {
		t.Run(path, func(t *testing.T) {
			rec := do(t, engine, http.MethodGet, path)
			assert.Equal(t, http.StatusForbidden, rec.Code,
				"the refusal must not depend on what was asked for")
		})
	}
}

func TestLoggingHandlerRefusesWhenUnauthorized(t *testing.T) {
	now := time.Date(2026, 8, 20, 18, 30, 0, 0, time.UTC)
	src := &stubSource{body: "secret\n", covered: true}

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	h := &loggingHandler{
		sitename: "uw-origin",
		scope:    token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, LoggingNamespaceForSitename("uw-origin")),
		source:   src,
		now:      fixedClock(now),
		sem:      make(chan struct{}, maxConcurrentLogReads),
		authorize: func(c *gin.Context) bool {
			c.Status(http.StatusForbidden)
			return false
		},
	}
	registerLoggingRoutes(engine, h)

	rec := do(t, engine, http.MethodGet, "/pelican/logging/uw-origin/2026/08/20/15.log")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Zero(t, src.readCall, "an unauthorized caller must not reach the log")
	assert.NotContains(t, rec.Body.String(), "secret")
}

// tokenWithScope builds an unsigned token carrying a scope claim. Signature
// and issuer are token.Verify's business; what is under test here is the
// handler's own scope decision.
func tokenWithScope(t *testing.T, scope string) jwt.Token {
	t.Helper()
	builder := jwt.NewBuilder().Issuer("https://origin.example.com").Subject("test")
	if scope != "" {
		builder = builder.Claim("scope", scope)
	}
	tok, err := builder.Build()
	require.NoError(t, err)
	return tok
}

func TestLoggingHandlerScopeAuthorized(t *testing.T) {
	// This exercises the handler's own scope check, over real tokens.
	// An earlier version of this test asserted on token_scopes.Contains
	// directly, which tested the scopes package rather than any of this
	// handler's behaviour -- the loop below was uncovered.
	h := &loggingHandler{
		sitename: "uw-origin",
		scope: token_scopes.NewResourceScope(
			token_scopes.Wlcg_Storage_Read, LoggingNamespaceForSitename("uw-origin")),
	}

	// A federation administrator holds one broad scope covering every
	// server's logs. token.Verify compares scope strings exactly, which is why
	// the handler asks the hierarchical question itself: an exact comparison
	// would refuse precisely the caller AllowFederationAdmin exists to admit.
	for _, scope := range []string{
		"storage.read:/",
		"storage.read:/pelican",
		"storage.read:/pelican/logging",
		"storage.read:/pelican/logging/uw-origin",
		"storage.read:/pelican/logging/uw-origin/",
		"storage.modify:/ storage.read:/pelican/logging", // several scopes, one sufficient
	} {
		t.Run("accepts "+scope, func(t *testing.T) {
			assert.True(t, h.scopeAuthorized(tokenWithScope(t, scope)))
		})
	}

	for _, scope := range []string{
		"storage.read:/pelican/logging/other-origin",
		"storage.read:/pelican/logging/uw-origin-2", // prefix-of-string but not of path
		"storage.read:/pelican/metrics/uw-origin",
		"storage.modify:/pelican/logging", // write does not imply read
		"storage.create:/",
		"pelican.log_read", // the web-UI identity scope is not a namespace grant
		"",                 // no scope claim at all
	} {
		t.Run("rejects "+scope, func(t *testing.T) {
			assert.False(t, h.scopeAuthorized(tokenWithScope(t, scope)))
		})
	}

	t.Run("rejects a nil token", func(t *testing.T) {
		assert.False(t, h.scopeAuthorized(nil),
			"a missing token must never be read as authorization")
	})

	t.Run("a token for another server does not open this one", func(t *testing.T) {
		other := &loggingHandler{
			scope: token_scopes.NewResourceScope(
				token_scopes.Wlcg_Storage_Read, LoggingNamespaceForSitename("other-origin")),
		}
		tok := tokenWithScope(t, "storage.read:/pelican/logging/uw-origin")
		assert.True(t, h.scopeAuthorized(tok))
		assert.False(t, other.scopeAuthorized(tok))
	})
}

func TestLoggingNamespaceForSitename(t *testing.T) {
	assert.Equal(t, "/pelican/logging/uw-origin", LoggingNamespaceForSitename("uw-origin"))
}

func TestPrefixShadowsLoggingRoute(t *testing.T) {
	// These expectations are not guesses about Gin's routing -- each was
	// checked against a live engine.  An export mounts a catch-all at its own
	// prefix, and Gin refuses to register a route that descends through an
	// existing catch-all, so only an export at or above /pelican/logging
	// collides.  A static segment and a :param segment coexist at the same
	// level, which is why an export *below* the logging root is fine and must
	// not be rejected.
	for _, prefix := range []string{"/", "/pelican", "/pelican/logging"} {
		t.Run("shadows "+prefix, func(t *testing.T) {
			assert.True(t, prefixShadowsLoggingRoute(prefix))
		})
	}

	for _, prefix := range []string{
		"/pelican/logging/some-export",
		"/pelican/other",
		"/pelicanish",
		"/data",
		"/chtc/staging",
	} {
		t.Run("does not shadow "+prefix, func(t *testing.T) {
			assert.False(t, prefixShadowsLoggingRoute(prefix),
				"rejecting this would refuse a configuration that works")
		})
	}

	t.Run("trailing slashes and un-normalized prefixes still match", func(t *testing.T) {
		assert.True(t, prefixShadowsLoggingRoute("/pelican/"))
		assert.True(t, prefixShadowsLoggingRoute("pelican"))
		assert.True(t, prefixShadowsLoggingRoute("/pelican/logging/"))
	})
}

// TestLoggingRoutesCoexistWithExportCatchall pins down the routing assumption
// the guard above encodes: a WebDAV-style catch-all at a sibling or descendant
// prefix does not stop the logging routes from mounting.  If a Gin upgrade
// changes that, this fails rather than a server panicking on startup.
func TestLoggingRoutesCoexistWithExportCatchall(t *testing.T) {
	for _, prefix := range []string{"/pelican/logging/some-export", "/pelican/other", "/data"} {
		t.Run(prefix, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			engine := gin.New()
			engine.Group(prefix).Any("/*path", func(c *gin.Context) {})

			require.NotPanics(t, func() {
				registerLoggingRoutes(engine, &loggingHandler{
					sitename:  "uw-origin",
					source:    &stubSource{},
					now:       fixedClock(time.Now()),
					sem:       make(chan struct{}, 1),
					authorize: func(*gin.Context) bool { return true },
				})
			})
		})
	}
}

func TestLoggingHandlerReadErrorAbortsResponse(t *testing.T) {
	// A server-side failure mid-stream must not produce a response that looks
	// complete: the headers -- possibly saying immutable -- are already out, so
	// a clean finish would let a cache keep the truncated body forever.  The
	// handler kills the connection instead, leaving the framing visibly
	// unterminated.  A recorder cannot see framing, so this drives a real
	// server.
	now := time.Date(2026, 8, 20, 18, 30, 0, 0, time.UTC)
	src := &stubSource{
		body:    "the part that made it out\n",
		oldest:  time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC),
		covered: true,
		readErr: errors.New("disk fell over"),
	}
	engine := newLoggingEngine(t, "uw-origin", src, now)

	server := httptest.NewServer(engine)
	defer server.Close()

	// The timeout bounds the whole exchange: if the abort path ever regresses
	// into leaving the connection dangling, this test must fail in seconds,
	// not hang the suite.
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(server.URL + "/pelican/logging/uw-origin/2026/08/20/15.log")
	if err != nil {
		// The connection died before the response came back at all -- equally
		// impossible to mistake for a complete answer.
		return
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	assert.Error(t, err, "a truncated stream must not read as a well-formed body")
}

func TestLoggingHandlerClientDisconnectIsNotAnError(t *testing.T) {
	// The client going away mid-stream is routine -- a poller timing out, a
	// person hitting ^C -- and must not travel the abort path or be logged as
	// a failure.  It surfaces as context cancellation from the read.
	now := time.Date(2026, 8, 20, 18, 30, 0, 0, time.UTC)
	src := &stubSource{
		oldest:  time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC),
		covered: true,
		readErr: context.Canceled,
	}
	engine := newLoggingEngine(t, "uw-origin", src, now)

	rec := do(t, engine, http.MethodGet, "/pelican/logging/uw-origin/2026/08/20/15.log")
	assert.Equal(t, http.StatusOK, rec.Code)
}
