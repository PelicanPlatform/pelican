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
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/error_codes"
)

// wrapErrorByStatusCode maps HTTP 429 to a retryable Pelican error, so a cache
// shed is no longer mis-classified as a fatal specification error.
func TestWrapStatusCode429IsRetryable(t *testing.T) {
	wrapped := wrapErrorByStatusCode(http.StatusTooManyRequests, errors.New("shed"))
	var pe *error_codes.PelicanError
	require.ErrorAs(t, wrapped, &pe)
	assert.True(t, pe.IsRetryable(), "429 must be retryable")
	assert.True(t, IsRetryable(wrapped), "IsRetryable must report 429 as retryable")
}

// throttleErrorForReason maps the structured reason string to the specific
// retryable Pelican error type; unknown reasons fall back to cache-overloaded.
func TestThrottleErrorForReason(t *testing.T) {
	cases := []struct {
		reason  string
		errType string
	}{
		{"origin_unresponsive", "Transfer.OriginUnresponsive"},
		{"origin_slow", "Transfer.OriginSlow"},
		{"cache_overloaded", "Transfer.CacheOverloaded"},
		{"", "Transfer.CacheOverloaded"},
		{"garbage", "Transfer.CacheOverloaded"},
	}
	for _, tc := range cases {
		t.Run(tc.reason, func(t *testing.T) {
			err := throttleErrorForReason(tc.reason, errors.New("x"))
			var pe *error_codes.PelicanError
			require.ErrorAs(t, err, &pe)
			assert.Equal(t, tc.errType, pe.ErrorType())
			assert.True(t, pe.IsRetryable())
		})
	}
}

func TestParseThrottleReason(t *testing.T) {
	assert.Equal(t, "origin_unresponsive",
		parseThrottleReason(`{"error":"origin_unresponsive","detail":"..."}`))
	assert.Equal(t, "cache_overloaded",
		parseThrottleReason(`{"error":"cache_overloaded"}`))
	assert.Equal(t, "", parseThrottleReason(""))
	assert.Equal(t, "", parseThrottleReason("not json"))
	assert.Equal(t, "", parseThrottleReason(`{"other":"field"}`))
}

func TestParseRetryAfter(t *testing.T) {
	assert.Equal(t, 60*time.Second, parseRetryAfter("60"))
	assert.Equal(t, time.Duration(0), parseRetryAfter(""))
	assert.Equal(t, time.Duration(0), parseRetryAfter("-5"))
	assert.Equal(t, time.Duration(0), parseRetryAfter("garbage"))
	// HTTP-date form: a time in the future yields a positive duration.
	future := time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)
	d := parseRetryAfter(future)
	assert.Greater(t, d, time.Duration(0))
	assert.LessOrEqual(t, d, 30*time.Second)
}

// A CacheThrottleError built from a cache's 429 wraps the specific retryable
// Pelican error, so both errors.Is(ErrTooManyRequests-adjacent) checks via the
// PelicanError chain and IsRetryable hold, and it carries the reason + hint.
func TestCacheThrottleErrorIsRetryable(t *testing.T) {
	err := newCacheThrottleError("origin_unresponsive", "origin is over its share", "cache.example.org:8443", 60*time.Second)
	assert.Equal(t, "origin_unresponsive", err.Reason)
	assert.Equal(t, 60*time.Second, err.RetryAfter)
	assert.Equal(t, "cache.example.org:8443", err.Endpoint)

	var pe *error_codes.PelicanError
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "Transfer.OriginUnresponsive", pe.ErrorType())
	assert.True(t, IsRetryable(err), "a cache throttle must be retryable")
	assert.True(t, ShouldRetry(err), "ShouldRetry must honor a cache throttle")

	// Recoverable as a typed error so external retriers can read RetryAfter.
	var throttled *CacheThrottleError
	require.ErrorAs(t, err, &throttled)
	assert.Equal(t, 60*time.Second, throttled.RetryAfter)
}
