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
	"net/http/httptest"
	"testing"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
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
