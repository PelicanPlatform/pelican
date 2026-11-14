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

package local_cache

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTierMetricsTransport checks that a target's HTTP requests are counted
// by method and the target's status, that a request with no response counts
// as an error, and that one the cache abandoned is not counted at all.
func TestTierMetricsTransport(t *testing.T) {
	// The counters are process-wide, so the test compares against what they
	// held before rather than assuming they start at zero.
	const label = "metrics-transport-test"
	count := func(method, code string) float64 {
		return testutil.ToFloat64(tierTargetHTTPRequestsTotal.WithLabelValues(label, method, code))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInsufficientStorage)
	}))
	client := &http.Client{Transport: newTierMetricsTransport(http.DefaultTransport, label)}
	full, failed := count(http.MethodPut, "507"), count(http.MethodGet, tierHTTPCodeError)

	req, err := http.NewRequest(http.MethodPut, srv.URL+"/full", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, full+1, count(http.MethodPut, "507"), "the target's answer is counted with its status")

	// A request abandoned by the cache says nothing about the target.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/gone", nil)
	require.NoError(t, err)
	_, err = client.Do(req)
	require.Error(t, err)
	assert.Equal(t, failed, count(http.MethodGet, tierHTTPCodeError))

	// One that ran out of time is the target's failure.
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	req, err = http.NewRequestWithContext(expired, http.MethodGet, srv.URL+"/slow", nil)
	require.NoError(t, err)
	_, err = client.Do(req)
	require.Error(t, err)
	assert.Equal(t, failed+1, count(http.MethodGet, tierHTTPCodeError))

	// So is a target that does not answer at all.
	srv.Close()
	_, err = client.Get(srv.URL + "/down")
	require.Error(t, err)
	assert.Equal(t, failed+2, count(http.MethodGet, tierHTTPCodeError))
}
