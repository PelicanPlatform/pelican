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

package local_cache

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
)

func drainMonitorChan(ch chan []byte) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// TestEmitTransferMonitoring verifies that serving a GET emits XRootD-style
// monitoring packets to the shoveler's internal channel when monitoring is
// enabled.
func TestEmitTransferMonitoring(t *testing.T) {
	require.NoError(t, param.Shoveler_Enable.Set(true))
	defer func() { require.NoError(t, param.Shoveler_Enable.Set(false)) }()

	ch := metrics.GetInternalMonitorChan()
	drainMonitorChan(ch)

	pc := &PersistentCache{}
	req := httptest.NewRequest("GET", "http://cache.example/test/foo.dat", nil)
	req.Header.Set("User-Agent", "pelican-client/7.0 project/myproj")
	req.RemoteAddr = "192.0.2.10:54321"

	pc.emitTransferMonitoring(req, "/test/foo.dat", 4096, time.Now().Add(-time.Second), "")

	select {
	case pkt := <-ch:
		assert.NotEmpty(t, pkt, "expected a non-empty monitoring packet")
	case <-time.After(2 * time.Second):
		t.Fatal("expected a monitoring packet to be emitted")
	}
}

// TestEmitTransferMonitoring_NoOp verifies no packets are emitted when the
// shoveler is disabled or when nothing was served.
func TestEmitTransferMonitoring_NoOp(t *testing.T) {
	ch := metrics.GetInternalMonitorChan()

	pc := &PersistentCache{}
	req := httptest.NewRequest("GET", "http://cache.example/test/foo.dat", nil)

	// Shoveler disabled (default): no packets even with bytes served.
	require.NoError(t, param.Shoveler_Enable.Set(false))
	drainMonitorChan(ch)
	pc.emitTransferMonitoring(req, "/test/foo.dat", 4096, time.Now(), "")

	// Shoveler enabled but zero bytes served (e.g. a 304): no packets.
	require.NoError(t, param.Shoveler_Enable.Set(true))
	defer func() { require.NoError(t, param.Shoveler_Enable.Set(false)) }()
	pc.emitTransferMonitoring(req, "/test/foo.dat", 0, time.Now(), "")

	select {
	case <-ch:
		t.Fatal("did not expect a monitoring packet")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestCacheClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		expected   string
	}{
		{"remote addr", "192.0.2.5:1234", nil, "192.0.2.5"},
		{"x-forwarded-for single", "10.0.0.1:1", map[string]string{"X-Forwarded-For": "203.0.113.7"}, "203.0.113.7"},
		{"x-forwarded-for list", "10.0.0.1:1", map[string]string{"X-Forwarded-For": "203.0.113.7, 10.0.0.1"}, "203.0.113.7"},
		{"x-real-ip", "10.0.0.1:1", map[string]string{"X-Real-IP": "198.51.100.2"}, "198.51.100.2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://cache/test/x", nil)
			req.RemoteAddr = tc.remoteAddr
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			assert.Equal(t, tc.expected, cacheClientIP(req))
		})
	}
}
