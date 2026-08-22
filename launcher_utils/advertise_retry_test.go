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

package launcher_utils

import (
	"net/http"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIsRetryableAdStatus pins down which director answers buy a quick retry.
// The set is deliberately narrow: retrying a director that is actually broken
// just adds load to something already in trouble.
func TestIsRetryableAdStatus(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusTooManyRequests} {
		assert.True(t, isRetryableAdStatus(status), "HTTP %d means 'ask again shortly'", status)
	}
	for _, status := range []int{
		http.StatusInternalServerError, // something is wrong, not merely unready
		http.StatusForbidden,
		http.StatusBadRequest,
		http.StatusNotFound,
		http.StatusOK,
	} {
		assert.False(t, isRetryableAdStatus(status), "HTTP %d must not be retried", status)
	}
}

func TestParseAdRetryAfter(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   time.Duration
	}{
		{"absent means no hint", "", 0},
		{"whole seconds", "1", time.Second},
		{"surrounding space is tolerated", "  3 ", 3 * time.Second},
		{"zero means no hint", "0", 0},
		{"an HTTP-date is not a hint we understand", "Wed, 21 Oct 2026 07:28:00 GMT", 0},
		{"garbage means no hint", "soon", 0},
		{"negative means no hint", "-5", 0},
		{"an absurd hint is clamped, never honored as-is", "3600", maxAdRetryDelay},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseAdRetryAfter(tc.header))
		})
	}

	assert.LessOrEqual(t, defaultAdRetryDelay, maxAdRetryDelay,
		"the fallback delay must respect the same cap as a hint")
}

// TestRetryableAdErrorSurvivesWrapping guards the mechanism the retry hangs
// on. doAdvertise decides whether to retry with errors.As, so if any layer
// between the response handler and it were to flatten the error into a plain
// string, the retry would silently never fire and the regression would be
// invisible -- advertisement would simply go back to costing a full cycle.
func TestRetryableAdErrorSurvivesWrapping(t *testing.T) {
	base := &retryableAdError{
		status:     http.StatusServiceUnavailable,
		retryAfter: time.Second,
		msg:        "not ready",
	}

	var found *retryableAdError
	require.True(t, errors.As(error(base), &found), "the error must be recognizable as itself")
	assert.Equal(t, http.StatusServiceUnavailable, found.status)
	assert.Equal(t, time.Second, found.retryAfter)

	// pkg/errors is what this package wraps with; make sure a wrap on the way
	// up does not hide the status.
	found = nil
	wrapped := errors.Wrap(error(base), "failed to advertise")
	require.True(t, errors.As(wrapped, &found), "wrapping must not hide a retryable rejection")
	assert.Equal(t, http.StatusServiceUnavailable, found.status)

	// And a plain failure must not be mistaken for a retryable one.
	found = nil
	assert.False(t, errors.As(errors.New("the director rejected the server advertisement"), &found))

	assert.Contains(t, base.Error(), "503", "the message should name the status a reader will see in logs")
}
