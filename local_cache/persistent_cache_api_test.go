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

package local_cache

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/error_codes"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

func TestIsFederationAllowed(t *testing.T) {
	const primary = "director.example.com:8444"

	t.Run("PrimaryAlwaysAllowed", func(t *testing.T) {
		assert.True(t, isFederationAllowed(primary, primary, nil))
		assert.True(t, isFederationAllowed(primary, primary, []string{}))
		assert.True(t, isFederationAllowed(primary, primary, []string{"other.example.com:443"}))
	})

	t.Run("PrimaryCaseInsensitive", func(t *testing.T) {
		assert.True(t, isFederationAllowed("Director.Example.COM:8444", primary, nil))
	})

	t.Run("EmptyListRejectsNonPrimary", func(t *testing.T) {
		assert.False(t, isFederationAllowed("other.example.com:443", primary, nil))
		assert.False(t, isFederationAllowed("other.example.com:443", primary, []string{}))
	})

	t.Run("WildcardAllowsAll", func(t *testing.T) {
		assert.True(t, isFederationAllowed("any.federation.org:443", primary, []string{"*"}))
		assert.True(t, isFederationAllowed("random.host:9999", primary, []string{"specific.host:443", "*"}))
	})

	t.Run("ExplicitListEntry", func(t *testing.T) {
		list := []string{"allowed.example.com:443", "also-allowed.org:8444"}
		assert.True(t, isFederationAllowed("allowed.example.com:443", primary, list))
		assert.True(t, isFederationAllowed("also-allowed.org:8444", primary, list))
		assert.False(t, isFederationAllowed("not-in-list.org:443", primary, list))
	})

	t.Run("ListEntryCaseInsensitive", func(t *testing.T) {
		list := []string{"Allowed.Example.COM:443"}
		assert.True(t, isFederationAllowed("allowed.example.com:443", primary, list))
	})
}

// TestHandleErrorTooManyRequests pins the wire contract for the fair
// scheduler's shedding path: when the upstream fetch returns
// client.ErrTooManyRequests, the cache's serveObject error path must
// answer the client with HTTP 429 and a Retry-After header, not the
// generic 500. If this test breaks, dashboards and clients relying on
// the 429 backoff signal will silently degrade.
func TestHandleErrorTooManyRequests(t *testing.T) {
	reqLog := log.NewEntry(log.New())

	t.Run("BareSentinel", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handleError(rec, client.ErrTooManyRequests, false, reqLog)
		require.Equal(t, 429, rec.Code)
		require.Equal(t, "60", rec.Header().Get("Retry-After"),
			"Retry-After should tell the client to back off for 60 seconds")
		require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		var body map[string]string
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, "too_many_requests", body["error"])
		assert.NotEmpty(t, body["detail"])
	})

	t.Run("WrappedSentinel", func(t *testing.T) {
		// The transfer engine wraps the sentinel with a per-origin
		// context ("pending queue is full", "origin \"…\" pending
		// queue is full", …); handleError must still recognise it
		// via errors.Is.
		rec := httptest.NewRecorder()
		wrapped := errors.Wrapf(client.ErrTooManyRequests, "origin %q pending queue is full", "originA")
		handleError(rec, wrapped, false, reqLog)
		require.Equal(t, 429, rec.Code)
		require.Equal(t, "60", rec.Header().Get("Retry-After"))
	})

	t.Run("StructuredReasonSurfaced", func(t *testing.T) {
		// A classified SchedulerRejection surfaces its specific reason in
		// the JSON body's "error" field so the client can distinguish an
		// unresponsive origin from a merely-slow one.
		for _, reason := range []client.ShedReason{
			client.ShedOriginUnresponsive,
			client.ShedOriginSlow,
			client.ShedCacheOverloaded,
		} {
			rec := httptest.NewRecorder()
			rej := &client.SchedulerRejection{Reason: reason, Tag: "originA"}
			handleError(rec, rej, false, reqLog)
			require.Equal(t, 429, rec.Code)
			require.Equal(t, "60", rec.Header().Get("Retry-After"))
			var body map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			assert.Equal(t, string(reason), body["error"],
				"the structured shed reason must be the machine-parseable error field")
		}
	})

	t.Run("UpstreamThrottlePassesThrough", func(t *testing.T) {
		// When the upstream server 429s the cache's own fetch, the resulting
		// client.CacheThrottleError must surface to the remote client as a
		// 429 with the upstream's reason — not as a misleading 500.
		rec := httptest.NewRecorder()
		throttled := &client.CacheThrottleError{Reason: string(client.ShedOriginSlow)}
		handleError(rec, throttled, false, reqLog)
		require.Equal(t, 429, rec.Code)
		require.Equal(t, "60", rec.Header().Get("Retry-After"))
		var body map[string]string
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, string(client.ShedOriginSlow), body["error"])
	})

	t.Run("UnrelatedErrorStaysNon429", func(t *testing.T) {
		// A regression guard: any bare error should still take the
		// existing internal_error / not_found / etc. paths, not fall
		// through the new 429 branch.
		rec := httptest.NewRecorder()
		handleError(rec, errors.New("some other error"), false, reqLog)
		assert.NotEqual(t, 429, rec.Code, "non-scheduler errors must not accidentally map to 429")
		assert.Empty(t, rec.Header().Get("Retry-After"))
	})
}

// TestHandleErrorThrottlePrecedence pins the precedence between a throttle and
// a definitive failure when a fetch tried several object servers.
//
// A cache fetch accumulates one error per server it contacted
// (client.TransferErrors implements Unwrap() []error), so errors.Is finds
// ErrTooManyRequests as soon as a *single* attempt was shed. Answering 429 on
// that basis lets a throttled origin mask a definitive answer from another one:
// a namespace served by origins A and B where A says "not found" and B is
// throttled would be reported as "retry later", and the client would retry
// forever for an object that does not exist. The 429 path is only correct when
// throttling is the *whole* story.
func TestHandleErrorThrottlePrecedence(t *testing.T) {
	reqLog := log.NewEntry(log.New())

	// accumulate builds the multi-error the transfer engine hands back after
	// trying several object servers, one child per attempt.
	accumulate := func(errs ...error) error {
		te := client.NewTransferErrors()
		for _, err := range errs {
			te.AddError(err)
		}
		return te
	}

	notFound := func() error {
		return error_codes.NewSpecification_FileNotFoundError(errors.New("object does not exist at origin"))
	}
	shed := func() error {
		return &client.SchedulerRejection{Reason: client.ShedOriginSlow, Tag: "originB"}
	}

	tests := []struct {
		name string
		err  error
		// wantStatus is the exact status expected; 0 means the only
		// requirement is that the response is not a 429.
		wantStatus int
	}{
		{
			// Every server tried was shed: there is nothing more specific to
			// report, so "retry later" is the honest answer.
			name:       "AllAttemptsThrottled",
			err:        accumulate(errors.Wrap(client.ErrTooManyRequests, "origin \"originA\" pending queue is full"), shed()),
			wantStatus: http.StatusTooManyRequests,
		},
		{
			// One server said the object does not exist. That answer is
			// definitive and must reach the client, even though a sibling
			// attempt was shed.
			name:       "ThrottleDoesNotMaskNotFound",
			err:        accumulate(client.ErrTooManyRequests, notFound()),
			wantStatus: http.StatusNotFound,
		},
		{
			// Same, with the attempts recorded in the other order: precedence
			// must not depend on which server happened to answer first.
			name:       "NotFoundBeforeThrottle",
			err:        accumulate(notFound(), client.ErrTooManyRequests),
			wantStatus: http.StatusNotFound,
		},
		{
			// The accumulator reaches handleError wrapped with transfer
			// context; the per-attempt errors must still be examined
			// individually rather than collapsed by errors.Is.
			name:       "WrappedAccumulatorDoesNotMaskNotFound",
			err:        fmt.Errorf("failed to download object: %w", accumulate(client.ErrTooManyRequests, notFound())),
			wantStatus: http.StatusNotFound,
		},
		{
			// errors.Wrap inserts two links (withStack around withMessage),
			// and this path is wrapped that way in practice. Peeking only a
			// single level below the top would miss the accumulator entirely
			// and fall back to the errors.Is answer, which is exactly the
			// masking this test exists to prevent.
			name:       "PkgErrorsWrappedAccumulatorDoesNotMaskNotFound",
			err:        errors.Wrap(accumulate(client.ErrTooManyRequests, notFound()), "failed to download object"),
			wantStatus: http.StatusNotFound,
		},
		{
			// A structured rejection unwraps to a typed PelicanError, so a
			// plain errors.As scan finds *its* code first and would answer
			// 500. The definitive not-found from the sibling attempt still has
			// to win.
			name:       "StructuredThrottleDoesNotMaskNotFound",
			err:        accumulate(shed(), notFound()),
			wantStatus: http.StatusNotFound,
		},
		{
			// A non-throttle failure of any kind is enough to disqualify the
			// 429 path: the client is told about the real failure instead of
			// being sent into an unbounded retry loop.
			name:       "ThrottleDoesNotMaskOtherFailure",
			err:        accumulate(shed(), errors.New("connection reset by peer")),
			wantStatus: 0,
		},
		{
			// The common case: a single shed attempt, not accumulated.
			name:       "SingleThrottle",
			err:        shed(),
			wantStatus: http.StatusTooManyRequests,
		},
		{
			// A lone accumulated throttle is still purely a throttle.
			name:       "SingleAccumulatedThrottle",
			err:        accumulate(shed()),
			wantStatus: http.StatusTooManyRequests,
		},
		{
			// An accumulator with no attempts recorded carries no evidence of
			// throttling, so it must not be advertised as retryable.
			name:       "EmptyAccumulator",
			err:        accumulate(),
			wantStatus: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handleError(rec, tt.err, false, reqLog)
			if tt.wantStatus == 0 {
				assert.NotEqual(t, http.StatusTooManyRequests, rec.Code,
					"a throttled attempt must not mask a more specific failure")
			} else {
				assert.Equal(t, tt.wantStatus, rec.Code)
			}
			if rec.Code == http.StatusTooManyRequests {
				assert.Equal(t, "60", rec.Header().Get("Retry-After"),
					"a 429 must always carry the backoff hint")
			} else {
				assert.Empty(t, rec.Header().Get("Retry-After"),
					"only a 429 advertises a backoff")
			}
		})
	}
}

// TestRetryAfterValue verifies that the advertised backoff comes from
// Cache.Throttle.RetryAfter. Operators tune this to match how long their cache
// actually needs to drain; if the parameter were ignored, every deployment
// would silently advertise the 60s fallback and clients would retry on a
// schedule unrelated to the cache's real recovery time.
func TestRetryAfterValue(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{
			name:  "ConfiguredValue",
			value: "90s",
			want:  "90",
		},
		{
			// Retry-After is whole seconds on the wire. A sub-second setting
			// must round up: truncating to "0" tells the client to retry
			// immediately, which turns a shed request into a hot loop against
			// an already-overloaded cache.
			name:  "SubSecondRoundsUp",
			value: "500ms",
			want:  "1",
		},
		{
			name:  "ZeroFallsBackToDefault",
			value: "0s",
			want:  "60",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server_utils.ResetTestState()
			t.Cleanup(server_utils.ResetTestState)
			viper.Set(param.Cache_Throttle_RetryAfter.GetName(), tt.value)
			assert.Equal(t, tt.want, retryAfterValue())

			// The same value is what a shed request actually advertises.
			rec := httptest.NewRecorder()
			handleError(rec, client.ErrTooManyRequests, false, log.NewEntry(log.New()))
			require.Equal(t, http.StatusTooManyRequests, rec.Code)
			assert.Equal(t, tt.want, rec.Header().Get("Retry-After"))
		})
	}

	t.Run("UnsetFallsBackToDefault", func(t *testing.T) {
		server_utils.ResetTestState()
		t.Cleanup(server_utils.ResetTestState)
		assert.Equal(t, "60", retryAfterValue(),
			"an unconfigured cache must still advertise a sane backoff")
	})
}

// TestHandleErrorShedReasonIsValidated pins that the machine-parseable "error"
// field of a 429 body only ever carries a known shed reason.
//
// The reason on a CacheThrottleError originated at whatever upstream answered
// the cache's own fetch. It is validated where that response is parsed, but it
// travels here on an exported field of an exported type, so nothing structural
// stops a future caller from setting it to anything at all. Echoing an
// arbitrary upstream string to a client would hand it onward into that
// client's logs and HTCondor job ads, where an embedded newline forges records.
func TestHandleErrorShedReasonIsValidated(t *testing.T) {
	reqLog := log.NewEntry(log.New())

	known := []string{"origin_unresponsive", "origin_slow", "cache_overloaded"}
	for _, reason := range known {
		t.Run("known/"+reason, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handleError(rec, &client.CacheThrottleError{
				Reason: reason,
				Err:    client.ErrTooManyRequests,
			}, false, reqLog)
			require.Equal(t, http.StatusTooManyRequests, rec.Code)

			var body map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			assert.Equal(t, reason, body["error"], "a known reason is passed through verbatim")
		})
	}

	hostile := []struct {
		name   string
		reason string
	}{
		{"NewlineInjection", "origin_slow\nlevel=fatal msg=\"forged record\""},
		{"UnknownVocabulary", "please_stop"},
		{"CarriageReturn", "origin_slow\r\nSet-Cookie: x=y"},
		{"Empty", " "},
	}
	for _, tt := range hostile {
		t.Run("rejected/"+tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handleError(rec, &client.CacheThrottleError{
				Reason: tt.reason,
				Err:    client.ErrTooManyRequests,
			}, false, reqLog)
			require.Equal(t, http.StatusTooManyRequests, rec.Code,
				"the response is still a throttle; only the reason is discarded")

			var body map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			assert.Equal(t, "too_many_requests", body["error"],
				"an unrecognized reason must fall back to the generic vocabulary")
			assert.NotContains(t, body["error"], "\n")
			assert.NotContains(t, body["error"], "\r")
		})
	}
}

// TestHandleErrorNotFoundDoesNotMaskSpecificFailures pins the other side of the
// precedence rule: preferring a definitive not-found must not let it swallow an
// answer that says something more useful about the object.
//
// A namespace served by two origins where one holds the object but rejects the
// caller's token, and the other simply does not have it, has to report the
// authorization failure. Reporting 404 there tells the client the object does
// not exist, so it stops rather than refreshing its credential -- the mirror of
// the masking the not-found preference exists to prevent.
func TestHandleErrorNotFoundDoesNotMaskSpecificFailures(t *testing.T) {
	reqLog := log.NewEntry(log.New())

	accumulate := func(errs ...error) error {
		te := client.NewTransferErrors()
		for _, err := range errs {
			te.AddError(err)
		}
		return te
	}
	notFound := func() error {
		return error_codes.NewSpecification_FileNotFoundError(errors.New("object does not exist at origin"))
	}
	// relayed builds the shape a download produces for an upstream status code:
	// a StatusCodeError wrapped by the transfer machinery.
	relayed := func(code int) error {
		sce := client.StatusCodeError(code)
		return error_codes.NewTransferError(&client.HttpErrResp{
			Code: code,
			Str:  fmt.Sprintf("request failed (HTTP status %d)", code),
			Err:  &sce,
		})
	}
	unauthorized := func() error {
		return error_codes.NewAuthorizationError(errors.New("token rejected by origin"))
	}

	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{
			// The object exists behind an origin that refused the token.
			name:       "RelayedForbiddenBeatsNotFound",
			err:        accumulate(relayed(http.StatusForbidden), notFound()),
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "RelayedServerErrorBeatsNotFound",
			err:        accumulate(relayed(http.StatusInternalServerError), notFound()),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "RelayedRangeNotSatisfiableBeatsNotFound",
			err:        accumulate(relayed(http.StatusRequestedRangeNotSatisfiable), notFound()),
			wantStatus: http.StatusRequestedRangeNotSatisfiable,
		},
		{
			// Ordering must not decide it either way.
			name:       "NotFoundRecordedFirstStillYieldsForbidden",
			err:        accumulate(notFound(), relayed(http.StatusForbidden)),
			wantStatus: http.StatusForbidden,
		},
		{
			// An authorization failure carried as a Pelican error, not a
			// relayed status code, also outranks a sibling's not-found.
			name:       "AuthorizationBeatsNotFound",
			err:        accumulate(unauthorized(), notFound()),
			wantStatus: http.StatusForbidden,
		},
		{
			// And with nothing more specific to say, the not-found stands.
			name:       "NotFoundAloneIsStillNotFound",
			err:        accumulate(notFound()),
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handleError(rec, tt.err, false, reqLog)
			assert.Equal(t, tt.wantStatus, rec.Code)
		})
	}
}

// The shapes below mirror just enough of RFC 4918 §14 to read back what
// buildPropfindMultistatus emits.  A pointer for the collection element lets
// the test tell "absent" from "present but empty".
type testDavResourceType struct {
	Collection *struct{} `xml:"DAV: collection"`
}

type testDavProp struct {
	ResourceType  testDavResourceType `xml:"DAV: resourcetype"`
	ContentLength int64               `xml:"DAV: getcontentlength"`
	LastModified  string              `xml:"DAV: getlastmodified"`
	ContentType   string              `xml:"DAV: getcontenttype"`
	ETag          string              `xml:"DAV: getetag"`
}

type testDavPropstat struct {
	Prop   testDavProp `xml:"DAV: prop"`
	Status string      `xml:"DAV: status"`
}

type testDavResponse struct {
	Href     string            `xml:"DAV: href"`
	Propstat []testDavPropstat `xml:"DAV: propstat"`
}

type testDavMultistatus struct {
	XMLName   xml.Name          `xml:"DAV: multistatus"`
	Responses []testDavResponse `xml:"DAV: response"`
}

// TestBuildPropfindMultistatus checks that the multistatus body the cache
// synthesizes from its own metadata cannot be steered by the origin that
// supplied that metadata.  ContentType and ETag are copied verbatim out of the
// upstream response headers, so a hostile origin controls them; unescaped,
// either can close the element it sits in and forge sibling properties.  The
// forged property that matters most is resourcetype/collection, which clients
// now read to decide whether a path is a collection.
func TestBuildPropfindMultistatus(t *testing.T) {
	lastMod := time.Date(2026, time.February, 3, 4, 5, 6, 0, time.UTC)

	t.Run("BenignValuesAreUnchanged", func(t *testing.T) {
		meta := &CacheMetadata{
			ETag:          "abc123",
			ContentType:   "application/octet-stream",
			ContentLength: 42,
			LastModified:  lastMod,
		}
		expected := `<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/test/object.txt</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype/>
        <D:getcontentlength>42</D:getcontentlength>
        <D:getlastmodified>Tue, 03 Feb 2026 04:05:06 GMT</D:getlastmodified>
        <D:getcontenttype>application/octet-stream</D:getcontenttype>
        <D:getetag>abc123</D:getetag>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>
`
		assert.Equal(t, expected, string(buildPropfindMultistatus("/test/object.txt", meta)))
	})

	t.Run("HostileOriginCannotForgeProperties", func(t *testing.T) {
		// An ETag that tries to close its own element, declare the object a
		// collection, and leave an element open for the rest of the document.
		hostileETag := `"x"</D:getetag><D:resourcetype><D:collection/></D:resourcetype><D:x>`
		hostileContentType := `text/plain</D:getcontenttype><D:getetag>forged & "spoofed"</D:getetag><D:y>`
		hostilePath := `/test/a&b<c>/object.txt`

		meta := &CacheMetadata{
			ETag:          hostileETag,
			ContentType:   hostileContentType,
			ContentLength: 42,
			LastModified:  lastMod,
		}
		body := buildPropfindMultistatus(hostilePath, meta)

		// The document still parses, which an unescaped `<D:x>` would prevent.
		var ms testDavMultistatus
		require.NoError(t, xml.Unmarshal(body, &ms), "body is not well-formed XML: %s", body)

		require.Len(t, ms.Responses, 1)
		resp := ms.Responses[0]
		require.Len(t, resp.Propstat, 1, "origin must not be able to add a propstat")
		prop := resp.Propstat[0].Prop

		// Every hostile value survives as literal text, in its own property.
		assert.Equal(t, hostilePath, resp.Href)
		assert.Equal(t, hostileETag, prop.ETag)
		assert.Equal(t, hostileContentType, prop.ContentType)
		assert.Equal(t, int64(42), prop.ContentLength)
		assert.Equal(t, "Tue, 03 Feb 2026 04:05:06 GMT", prop.LastModified)
		assert.Equal(t, "HTTP/1.1 200 OK", resp.Propstat[0].Status)

		// The injected markup did not become elements: the resource is still
		// reported as a plain object, not a collection.
		assert.Nil(t, prop.ResourceType.Collection, "forged collection element was parsed: %s", body)
		assert.NotContains(t, string(body), "<D:collection")
	})
}
