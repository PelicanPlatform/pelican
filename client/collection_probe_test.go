//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
)

// The tests in this file cover the collection-detection probe that guards the
// client's download path: sortAttempts(..., wantCollectionInfo=true) and the
// helpers underneath it.  The machinery is fail-closed -- downloadObject
// refuses the transfer when no endpoint says whether the path is a collection
// -- so what is pinned down here is not only "collection" versus "object" but
// also the difference between an answer and no answer at all.
//
// Everything is exercised against httptest servers: no federation, no
// director, no XRootD.

// davMultistatus renders the 207 body gowebdav's Stat() expects.  The shape,
// not the prettiness, is what matters: gowebdav decodes each <response> into a
// struct keyed on `DAV: prop>resourcetype>collection` and
// `DAV: prop>getcontentlength`, and picks the propstat whose status contains
// "200".
func davMultistatus(href string, isCollection bool, size int64) string {
	resourceType := "<D:resourcetype/>"
	sizeProp := fmt.Sprintf("<D:getcontentlength>%d</D:getcontentlength>", size)
	if isCollection {
		resourceType = "<D:resourcetype><D:collection/></D:resourcetype>"
		sizeProp = ""
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>%s</D:href>
    <D:propstat>
      <D:prop>
        <D:displayname>probe</D:displayname>
        %s
        %s
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>
`, href, resourceType, sizeProp)
}

// writeMultistatus answers a PROPFIND the way a WebDAV-speaking object server
// would.
func writeMultistatus(t *testing.T, w http.ResponseWriter, href string, isCollection bool, size int64) {
	t.Helper()
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	_, err := w.Write([]byte(davMultistatus(href, isCollection, size)))
	require.NoError(t, err)
}

// methodCounter records how many requests of each HTTP method an httptest
// server saw, so a test can assert on requests that were *not* made.
type methodCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

func newMethodCounter() *methodCounter {
	return &methodCounter{counts: make(map[string]int)}
}

func (m *methodCounter) record(method string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counts[method]++
}

func (m *methodCounter) get(method string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counts[method]
}

// probeTestToken builds the same kind of generator the existing sortAttempts
// tests use: a fixed token, no acquisition, no director response.
func probeTestToken() *tokenGenerator {
	token := newTokenGenerator(nil, nil, config.TokenRead, false)
	token.SetToken("aaa")
	return token
}

// newProbeServer starts a plain-HTTP test server whose handler is wrapped in a
// per-method request counter.
func newProbeServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *url.URL, *methodCounter) {
	t.Helper()
	counter := newMethodCounter()
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counter.record(r.Method)
		handler(w, r)
	}))
	t.Cleanup(svr.Close)
	svrUrl, err := url.Parse(svr.URL)
	require.NoError(t, err)
	return svr, svrUrl, counter
}

// TestCollectionProbeDetectsCollection: an endpoint that describes the path
// with a `<D:collection/>` resourcetype makes sortAttempts report a collection.
// The ranged GET deliberately carries no Content-Range, which is what pushes
// objectCached on to the PROPFIND.
func TestCollectionProbeDetectsCollection(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
	defer cancel()

	_, svrUrl, counter := newProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PROPFIND":
			writeMultistatus(t, w, "/path", true, 0)
		case http.MethodGet:
			// A collection has no byte range to serve, so no Content-Range.
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	_, collection, results := sortAttempts(ctx, "/path", []transferAttemptDetails{{Url: svrUrl}}, probeTestToken(), true)

	require.Len(t, results, 1)
	assert.True(t, collection.answered, "the endpoint answered the PROPFIND, so the question is answered")
	assert.True(t, collection.isCollection, "a <D:collection/> resourcetype means the path is a collection")
	assert.Equal(t, 1, counter.get("PROPFIND"), "the collection answer must come from exactly one PROPFIND")
}

// TestCollectionProbeDetectsObject: the same PROPFIND path, but the endpoint
// describes an ordinary sized object.  The size reported by the PROPFIND is
// the size sortAttempts returns, so the caller does not have to re-stat.
func TestCollectionProbeDetectsObject(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
	defer cancel()

	_, svrUrl, _ := newProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PROPFIND":
			writeMultistatus(t, w, "/path", false, 4096)
		case http.MethodGet:
			// No Content-Range: this server does not honor byte ranges, which
			// is exactly the case the PROPFIND fall-back exists for.
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	size, collection, results := sortAttempts(ctx, "/path", []transferAttemptDetails{{Url: svrUrl}}, probeTestToken(), true)

	require.Len(t, results, 1)
	assert.True(t, collection.answered)
	assert.False(t, collection.isCollection, "a resourcetype without <D:collection/> is an ordinary object")
	assert.Equal(t, int64(4096), size, "the size must come from the PROPFIND's getcontentlength")
}

// TestCollectionProbeConflictIsCollection: an XRootD cache does not describe a
// collection, it refuses the PROPFIND with 409 Conflict.  The refusal is the
// answer, and it means "collection".
func TestCollectionProbeConflictIsCollection(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
	defer cancel()

	_, svrUrl, _ := newProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PROPFIND":
			w.WriteHeader(http.StatusConflict)
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	_, collection, results := sortAttempts(ctx, "/path", []transferAttemptDetails{{Url: svrUrl}}, probeTestToken(), true)

	require.Len(t, results, 1)
	assert.True(t, collection.answered, "a 409 is an answer, not a failure to answer")
	assert.True(t, collection.isCollection, "409 Conflict from an XRootD cache means the path is a collection")
}

// TestCollectionProbePropfindUnsupportedLeavesUnanswered is the fail-closed
// trigger, and the most important test in this file.  An endpoint that does
// not implement PROPFIND leaves the question unanswered; `answered` stays
// false even though the endpoint is perfectly healthy and the transfer would
// otherwise succeed.  downloadObject turns that into a refusal rather than
// writing an unidentified response to the caller's file.
func TestCollectionProbePropfindUnsupportedLeavesUnanswered(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
	defer cancel()

	_, svrUrl, counter := newProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PROPFIND":
			w.WriteHeader(http.StatusMethodNotAllowed)
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
		case http.MethodHead:
			w.Header().Set("Content-Length", "17")
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	size, collection, results := sortAttempts(ctx, "/path", []transferAttemptDetails{{Url: svrUrl}}, probeTestToken(), true)

	require.Len(t, results, 1)
	assert.False(t, collection.answered,
		"a 405 to the PROPFIND leaves the collection question unanswered; this is what makes downloadObject refuse")
	assert.False(t, collection.isCollection, "an unanswered question must not be reported as a positive answer")
	// Sizing and endpoint selection keep working through the HEAD fall-back:
	// the refusal is the caller's decision, not the probe's.
	assert.Equal(t, int64(17), size, "the HEAD fall-back still sizes the object")
	assert.Equal(t, 1, counter.get("PROPFIND"))
	assert.Equal(t, 1, counter.get(http.MethodHead))
}

// TestCollectionProbeContentRangeShortCircuit documents the escape hatch that
// keeps plain HTTP object servers usable under a fail-closed policy: a server
// that satisfies the one-byte range served an object -- collections have no
// byte ranges -- so the question is answered without a PROPFIND ever being
// sent.
func TestCollectionProbeContentRangeShortCircuit(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
	defer cancel()

	var gotRange string
	_, svrUrl, counter := newProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gotRange = r.Header.Get("Range")
			w.Header().Set("Content-Length", "1")
			w.Header().Set("Content-Range", "bytes 0-0/1234")
			w.WriteHeader(http.StatusPartialContent)
			_, err := w.Write([]byte("A"))
			require.NoError(t, err)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})

	size, collection, results := sortAttempts(ctx, "/path", []transferAttemptDetails{{Url: svrUrl}}, probeTestToken(), true)

	require.Len(t, results, 1)
	assert.Equal(t, "bytes=0-0", gotRange,
		"the probe must ask in RFC 7233 syntax, or a compliant server will not satisfy it")
	assert.True(t, collection.answered, "serving a byte range answers the question")
	assert.False(t, collection.isCollection)
	assert.Equal(t, int64(1234), size, "the size comes from the Content-Range")
	assert.Zero(t, counter.get("PROPFIND"),
		"a satisfied byte range must short-circuit the PROPFIND entirely, so servers that speak no WebDAV still work")
	assert.Zero(t, counter.get(http.MethodHead), "and no HEAD either -- the range answered both questions")
}

// TestCollectionProbeContentRangeNeedsPartialStatus: a 200 carrying a
// Content-Range is a server contradicting itself.  Since this value decides
// whether a download is refused, it is taken only when the status agrees, and
// the probe goes on to ask properly.
func TestCollectionProbeContentRangeNeedsPartialStatus(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
	defer cancel()

	_, svrUrl, counter := newProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Range", "bytes 0-0/1234")
			w.WriteHeader(http.StatusOK)
		case "PROPFIND":
			writeMultistatus(t, w, "/path", false, 99)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	size, collection, _ := sortAttempts(ctx, "/path", []transferAttemptDetails{{Url: svrUrl}}, probeTestToken(), true)

	assert.Equal(t, 1, counter.get("PROPFIND"), "the contradictory response must not short-circuit")
	assert.True(t, collection.answered)
	assert.False(t, collection.isCollection)
	assert.Equal(t, int64(99), size, "the size must come from the PROPFIND, not the disputed header")
}

// TestCollectionProbeRangeNotSatisfiable: a 416 says the endpoint would not
// serve the range asked for, which is not the same as the endpoint being
// broken.  It must not be recorded as a failure, or a strict server that
// answers the collection question correctly gets sorted behind one that does
// not answer at all.
func TestCollectionProbeRangeNotSatisfiable(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
	defer cancel()

	_, strictUrl, _ := newProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		case "PROPFIND":
			writeMultistatus(t, w, "/path", true, 0)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	_, collection, results := sortAttempts(ctx, "/path", []transferAttemptDetails{{Url: strictUrl}}, probeTestToken(), true)

	require.Len(t, results, 1)
	assert.True(t, collection.answered, "the endpoint answered by PROPFIND; the 416 was only about the range")
	assert.True(t, collection.isCollection)
}

// TestCollectionProbeMixedAnswersRefuseWins: when two endpoints both answer and
// they disagree, the merged answer is "collection" -- the reading that refuses
// the download.
//
// The object endpoint's probe is gated on the collection endpoint having
// already answered.  Without the gate, an endpoint at index 0 that succeeds
// cancels the remaining probes, and the test would race on whether the second
// answer was ever heard.  The gate is a channel, not a sleep.
func TestCollectionProbeMixedAnswersRefuseWins(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
	defer cancel()

	collectionAnswered := make(chan struct{})
	var once sync.Once

	_, collectionUrl, _ := newProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PROPFIND":
			writeMultistatus(t, w, "/path", true, 0)
			once.Do(func() { close(collectionAnswered) })
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	_, objectUrl, _ := newProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PROPFIND":
			writeMultistatus(t, w, "/path", false, 99)
		case http.MethodGet:
			select {
			case <-collectionAnswered:
			case <-ctx.Done():
			}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	attempts := []transferAttemptDetails{{Url: objectUrl}, {Url: collectionUrl}}
	_, collection, results := sortAttempts(ctx, "/path", attempts, probeTestToken(), true)

	require.Len(t, results, 2)
	assert.True(t, collection.answered)
	assert.True(t, collection.isCollection,
		"one endpoint calling the path a collection is enough to refuse, even when another calls it an object")
}

// TestCollectionProbeAnswerSurvivesUnhealthyEndpoint: whether the path is a
// collection and whether a given endpoint can serve it are separate questions.
// An endpoint whose ranged GET fails still answers the first, and the answer
// counts -- all the endpoints are describing the same path.  What the failure
// costs the endpoint is its place in the sort: it is not promoted for having
// answered.
func TestCollectionProbeAnswerSurvivesUnhealthyEndpoint(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
	defer cancel()

	// Answers the question but cannot serve the object.
	unhealthySvr, unhealthyUrl, _ := newProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PROPFIND":
			writeMultistatus(t, w, "/path", true, 0)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	// Serves fine but has nothing to say about collections, so it is the
	// unhealthy endpoint alone that answers.
	healthySvr, healthyUrl, _ := newProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PROPFIND":
			w.WriteHeader(http.StatusMethodNotAllowed)
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
		case http.MethodHead:
			w.Header().Set("Content-Length", "7")
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	// The unhealthy endpoint is listed first so that no early-exit cancellation
	// can hide the healthy endpoint's result: the short-circuit only fires for
	// a *successful* probe at index 0.
	attempts := []transferAttemptDetails{{Url: unhealthyUrl}, {Url: healthyUrl}}
	size, collection, results := sortAttempts(ctx, "/path", attempts, probeTestToken(), true)

	assert.True(t, collection.answered, "a failed health check does not retract the endpoint's description of the path")
	assert.True(t, collection.isCollection)

	require.Len(t, results, 2)
	assert.Equal(t, healthySvr.URL, results[0].Url.String(),
		"the endpoint that can actually serve the object sorts first")
	assert.Equal(t, unhealthySvr.URL, results[1].Url.String(),
		"answering the collection question must not promote an endpoint that failed its probe")
	assert.Equal(t, int64(7), size, "only the endpoint that succeeded contributes a size")
}

// TestCollectionProbeZeroLengthObject: an empty file is a legitimate object.
// It produces no Content-Range on the ranged GET -- the same signal a
// collection gives -- so the PROPFIND has to be what distinguishes them.
func TestCollectionProbeZeroLengthObject(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
	defer cancel()

	_, svrUrl, _ := newProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PROPFIND":
			writeMultistatus(t, w, "/empty", false, 0)
		case http.MethodGet:
			// Nothing to range over; a zero-length object cannot produce a
			// Content-Range.
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	size, collection, results := sortAttempts(ctx, "/empty", []transferAttemptDetails{{Url: svrUrl}}, probeTestToken(), true)

	require.Len(t, results, 1)
	assert.True(t, collection.answered)
	assert.False(t, collection.isCollection, "an empty file must not be mistaken for a collection")
	assert.Equal(t, int64(0), size)
}

// fixedTokenProvider is a TokenProvider whose answer the test controls,
// including the "no credential" answers StaticTokenProvider cannot express.
type fixedTokenProvider struct {
	token string
	err   error
}

func (f fixedTokenProvider) Get() (string, error) { return f.token, f.err }

// TestProbeTokenFallback pins down which credential the probe presents.  The
// download adds the federation token per-attempt, after an endpoint has been
// chosen; the probe runs before that, so on a namespace where the federation
// token is the only credential it has to fall back to it or every probe is
// refused -- and under fail-closed a refused probe fails the download.
func TestProbeTokenFallback(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	t.Run("NilUserTokenUsesFedToken", func(t *testing.T) {
		probe := probeToken(nil, StaticTokenProvider("fed-token"))
		require.NotNil(t, probe, "a federation token must produce a usable generator even with no user token")
		contents, err := probe.Get()
		require.NoError(t, err)
		assert.Equal(t, "fed-token", contents)
	})

	t.Run("EmptyUserTokenUsesFedToken", func(t *testing.T) {
		userToken := newTokenGenerator(nil, nil, config.TokenRead, false)
		userToken.SetExternalProvider(fixedTokenProvider{token: ""})

		probe := probeToken(userToken, StaticTokenProvider("fed-token"))
		require.NotNil(t, probe)
		contents, err := probe.Get()
		require.NoError(t, err)
		assert.Equal(t, "fed-token", contents,
			"a user generator that yields nothing must not shadow the federation token")
	})

	t.Run("FailingUserTokenUsesFedToken", func(t *testing.T) {
		userToken := newTokenGenerator(nil, nil, config.TokenRead, false)
		userToken.SetExternalProvider(fixedTokenProvider{err: errors.New("no credential discovered")})

		probe := probeToken(userToken, StaticTokenProvider("fed-token"))
		require.NotNil(t, probe)
		contents, err := probe.Get()
		require.NoError(t, err)
		assert.Equal(t, "fed-token", contents)
	})

	t.Run("UserTokenWinsOverFedToken", func(t *testing.T) {
		userToken := newTokenGenerator(nil, nil, config.TokenRead, false)
		userToken.SetToken("user-token")

		probe := probeToken(userToken, StaticTokenProvider("fed-token"))
		require.Same(t, userToken, probe, "the user's own credential is used as-is, not copied or replaced")
		contents, err := probe.Get()
		require.NoError(t, err)
		assert.Equal(t, "user-token", contents)
	})

	t.Run("NoTokensAtAll", func(t *testing.T) {
		assert.Nil(t, probeToken(nil, nil), "with nothing to present, the probe goes unauthenticated")
	})

	t.Run("NoFedTokenKeepsUserGenerator", func(t *testing.T) {
		userToken := newTokenGenerator(nil, nil, config.TokenRead, false)
		userToken.SetExternalProvider(fixedTokenProvider{token: ""})

		assert.Same(t, userToken, probeToken(userToken, nil),
			"with no federation token to fall back on, the original generator is returned unchanged")
	})
}

// TestCollectionProbeMultistatusWithoutUsableProps documents a crash, and is
// skipped so the suite stays green until the non-test code is fixed.
//
// gowebdav's Stat() returns (nil, nil) whenever it fails to extract a usable
// <D:propstat> with a 200 status from a 207 response: a multistatus whose only
// propstat reports 404, a body with no <D:response> at all, or a body it
// cannot parse (parseXML silently ignores decode errors).  propfindObject then
// calls info.Size() on that nil, and because gowebdav's File methods take a
// value receiver, that is a nil-pointer dereference rather than a nil
// interface call:
//
//	panic: value method github.com/studio-b12/gowebdav.File.Size called using nil *File pointer
//	  gowebdav.(*File).Size(...)
//	  client.propfindObject(...) handle_http.go:5846
//
// The panic would happen on the goroutine sortAttempts spawns per endpoint,
// where nothing recovers it, so it would take the whole client process down --
// and this probe runs on every guarded download, against whatever endpoint the
// director hands out.  propfindObject guards the returned FileInfo for nil and
// treats it as "unanswered", which for a caller that refuses collections means
// a refused download rather than a crashed one.
func TestCollectionProbeMultistatusWithoutUsableProps(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
	defer cancel()

	_, svrUrl, _ := newProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PROPFIND":
			// A legal multistatus that names no property with a 200 status.
			w.Header().Set("Content-Type", "application/xml; charset=utf-8")
			w.WriteHeader(http.StatusMultiStatus)
			_, err := w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/path</D:href>
    <D:propstat>
      <D:prop><D:getcontentlength/></D:prop>
      <D:status>HTTP/1.1 404 Not Found</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>`))
			require.NoError(t, err)
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
		case http.MethodHead:
			w.Header().Set("Content-Length", "17")
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	// The endpoint said nothing usable, so the correct outcome is the
	// fail-closed one: unanswered, and no crash.
	_, collection, results := sortAttempts(ctx, "/path", []transferAttemptDetails{{Url: svrUrl}}, probeTestToken(), true)

	require.Len(t, results, 1)
	assert.False(t, collection.answered, "a 207 that describes nothing is not an answer")
	assert.False(t, collection.isCollection)
}

// statHttpTestDirResp points statHttp at a single object server.
func statHttpTestDirResp(t *testing.T, svrUrl *url.URL) server_structs.DirectorResponse {
	t.Helper()
	return server_structs.DirectorResponse{ObjectServers: []*url.URL{svrUrl}}
}

// TestStatHttpHonorsContext: statHttp fans PROPFINDs out across every stat
// host and waits for all of them, so a hung object server used to hold the
// caller for as long as the transport allowed.  The cache calls this on the
// path of every miss it fills, so it must be the caller's deadline that
// decides.
func TestStatHttpHonorsContext(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	released := make(chan struct{})
	_, svrUrl, _ := newProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
		<-released // never answers until the test lets it
	})
	t.Cleanup(func() { close(released) })

	pUrl, err := pelican_url.Parse("pelican://example.com/path", nil, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, statErr := statHttp(ctx, pUrl, statHttpTestDirResp(t, svrUrl), probeTestToken(), nil)
		done <- statErr
	}()

	select {
	case statErr := <-done:
		require.Error(t, statErr, "a stat whose context expired must not report success")
	case <-time.After(15 * time.Second):
		t.Fatal("statHttp ignored the context and hung on an unresponsive endpoint")
	}
}

// TestStatHttpBoundsResponseBody: a Depth-0 PROPFIND describes one resource,
// so an endless response body is a server misbehaving.  gowebdav decodes into
// memory with no bound of its own, and this runs on a goroutine the caller
// does not wait on, so the bound is enforced at the transport.
func TestStatHttpBoundsResponseBody(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	stop := make(chan struct{})
	_, svrUrl, _ := newProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.WriteHeader(http.StatusMultiStatus)
		// A well-formed prologue followed by an href that never ends.
		if _, err := w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:"><D:response><D:href>/`)); err != nil {
			return
		}
		flusher, _ := w.(http.Flusher)
		chunk := strings.Repeat("A", 4096)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	})
	t.Cleanup(func() { close(stop) })

	pUrl, err := pelican_url.Parse("pelican://example.com/path", nil, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, statErr := statHttp(ctx, pUrl, statHttpTestDirResp(t, svrUrl), probeTestToken(), nil)
		done <- statErr
	}()

	select {
	case statErr := <-done:
		require.Error(t, statErr, "an unbounded multistatus must fail the stat, not be accepted")
		assert.NotContains(t, statErr.Error(), "context deadline exceeded",
			"the body limit should stop this, not the timeout standing in for it")
	case <-time.After(25 * time.Second):
		t.Fatal("statHttp read an unbounded PROPFIND body without stopping")
	}
}

// TestCollectionProbeThrottleSurvivesRefusal pins the seam between the
// collection guard and the cache's fair scheduler.
//
// A shed probe answers nothing, so the guard's fail-closed rule fires and the
// download is refused.  What it is refused *with* matters: the throttle is
// retryable and carries the cache's Retry-After, while the guard's own refusal
// is a resolution error, which is not retryable.  Reporting the latter would
// tell a client to give up on a cache that only asked it to wait -- the same
// mistake objectCached avoids one layer down when it declines to let a HEAD
// overwrite the 429.
func TestCollectionProbeThrottleSurvivesRefusal(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
	defer cancel()

	_, svrUrl, _ := newProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "23")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"cache_overloaded","detail":"shed"}`))
	})

	_, collection, _ := sortAttempts(ctx, "/path", []transferAttemptDetails{{Url: svrUrl}}, probeTestToken(), true)

	require.False(t, collection.answered, "a shed probe answers nothing, so the guard must still refuse")
	require.NotNil(t, collection.throttleErr, "but the reason must survive for the caller to report")
	assert.ErrorIs(t, collection.throttleErr, ErrTooManyRequests)
	assert.True(t, IsRetryable(collection.throttleErr),
		"a refusal caused by throttling must stay retryable")

	var throttled *CacheThrottleError
	require.ErrorAs(t, collection.throttleErr, &throttled)
	assert.Equal(t, 23*time.Second, throttled.RetryAfter,
		"the cache's own backoff hint must reach the caller")
}
