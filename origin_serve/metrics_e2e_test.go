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

package origin_serve

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

// setupE2ETestServer creates a complete test server with POSIXv2 backend
// It returns the server, storage directory, and cleanup function
func setupE2ETestServer(t *testing.T) (*httptest.Server, string, func()) {
	// Create temporary directory for storage
	storageDir := t.TempDir()
	testFile := filepath.Join(storageDir, "test.txt")
	err := os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	// Reset handlers for clean test state
	ResetHandlers()

	// Initialize exports
	exports := []server_utils.OriginExport{
		{
			FederationPrefix: "/test",
			StoragePrefix:    storageDir,
			Capabilities: server_structs.Capabilities{
				PublicReads: true, // Allow public reads for testing
			},
		},
	}

	// Initialize handlers
	err = InitializeHandlers(exports)
	require.NoError(t, err)

	// Initialize auth config for the test (required even for public reads)
	// Create a dummy key for auth (won't be used since reads are public)
	_, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ac := &authConfig{}
	ac.exports.Store(&exports)
	globalAuthConfig = ac

	// Create Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register handlers
	err = RegisterHandlers(router, false)
	require.NoError(t, err)

	// Add Prometheus metrics endpoint
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Create test server
	server := httptest.NewServer(router)

	cleanup := func() {
		server.Close()
		ResetHandlers()
	}

	return server, storageDir, cleanup
}

// TestMetricsEndToEnd tests the complete metrics pipeline:
// HTTP request -> WebDAV handler -> filesystem operation -> metrics published
func TestMetricsEndToEnd(t *testing.T) {
	// Setup server
	server, storageDir, cleanup := setupE2ETestServer(t)
	defer cleanup()

	_ = storageDir // storageDir is from setupE2ETestServer

	// Reset metrics for clean test
	metrics.HttpRequestsTotal.Reset()
	metrics.HttpBytesTotal.Reset()
	metrics.StorageReadsTotal.Reset()
	metrics.StorageBytesRead.Reset()

	// Get initial metric values
	initialHTTPRequests := promtest.ToFloat64(metrics.HttpRequestsTotal.WithLabelValues(metrics.ServerTypeOrigin, "GET", "200"))
	initialHTTPBytesOut := promtest.ToFloat64(metrics.HttpBytesTotal.WithLabelValues(metrics.ServerTypeOrigin, metrics.DirectionOut, "GET"))
	initialStorageReads := promtest.ToFloat64(metrics.StorageReadsTotal.WithLabelValues("posixv2"))
	initialStorageBytes := promtest.ToFloat64(metrics.StorageBytesRead.WithLabelValues("posixv2"))

	// Make GET request to download file
	resp, err := http.Get(server.URL + "/test/test.txt")
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify HTTP response
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "test content", string(body))

	// Verify HTTP metrics were updated
	httpRequests := promtest.ToFloat64(metrics.HttpRequestsTotal.WithLabelValues(metrics.ServerTypeOrigin, "GET", "200"))
	assert.Greater(t, httpRequests, initialHTTPRequests, "HTTP request metric should increment")

	httpBytesOut := promtest.ToFloat64(metrics.HttpBytesTotal.WithLabelValues(metrics.ServerTypeOrigin, metrics.DirectionOut, "GET"))
	assert.Greater(t, httpBytesOut, initialHTTPBytesOut, "HTTP bytes out metric should increment")

	// Verify storage metrics were updated
	storageReads := promtest.ToFloat64(metrics.StorageReadsTotal.WithLabelValues("posixv2"))
	assert.Greater(t, storageReads, initialStorageReads, "Storage read metric should increment for backend=posixv2")

	storageBytes := promtest.ToFloat64(metrics.StorageBytesRead.WithLabelValues("posixv2"))
	assert.GreaterOrEqual(t, storageBytes, initialStorageBytes+float64(len(body)), "Storage read bytes should track actual bytes read")

	// Verify metrics are scrapable from /metrics endpoint
	metricsResp, err := http.Get(server.URL + "/metrics")
	require.NoError(t, err)
	defer metricsResp.Body.Close()
	assert.Equal(t, http.StatusOK, metricsResp.StatusCode)

	metricsBody, err := io.ReadAll(metricsResp.Body)
	require.NoError(t, err)
	metricsText := string(metricsBody)

	// Verify unified storage metrics are present with backend label
	assert.Contains(t, metricsText, "pelican_storage_reads_total", "Should export unified storage metrics")
	assert.Contains(t, metricsText, `backend="posixv2"`, "Should include backend=posixv2 label")

	// Verify HTTP metrics are present
	assert.Contains(t, metricsText, "pelican_http_requests_total", "Should export HTTP request metrics")
	assert.Contains(t, metricsText, "pelican_http_bytes_total", "Should export HTTP byte metrics")
	assert.Contains(t, metricsText, `server_type="origin"`, "Should include server_type=origin label")

	// Verify specific metric values in scraped output
	assert.Contains(t, metricsText, "pelican_storage_reads_total{backend=\"posixv2\"}", "Should have posixv2 read counter")
	assert.Contains(t, metricsText, "pelican_http_requests_total{code=\"200\",method=\"GET\",server_type=\"origin\"}", "Should have HTTP GET/200 counter")
}

// TestMetricsEndToEndWithAuth tests metrics with authorization
// NOTE: Moved to e2e_fed_tests/metrics_test.go to use fed_test_utils infrastructure
func TestMetricsEndToEndWithAuth(t *testing.T) {
	t.Skip("Test moved to e2e_fed_tests/metrics_test.go to avoid import cycle with fed_test_utils")
}

// TestMetricsEndToEndWriteOperations tests write operation metrics
// NOTE: Moved to e2e_fed_tests/metrics_test.go to use fed_test_utils infrastructure
func TestMetricsEndToEndWriteOperations(t *testing.T) {
	t.Skip("Test moved to e2e_fed_tests/metrics_test.go to avoid import cycle with fed_test_utils")
}

// TestMetricsPrometheusIntegration tests that metrics are properly exported in Prometheus format
func TestMetricsPrometheusIntegration(t *testing.T) {
	server, _, cleanup := setupE2ETestServer(t)
	defer cleanup()

	// Make some requests to generate metrics
	_, _ = http.Get(server.URL + "/test/test.txt")

	// Scrape metrics endpoint
	resp, err := http.Get(server.URL + "/metrics")
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	metricsText := string(body)

	// Verify Prometheus format
	assert.Contains(t, metricsText, "# HELP", "Should include metric help text")
	assert.Contains(t, metricsText, "# TYPE", "Should include metric type declarations")

	// Verify storage metrics structure (check for reads since we did a GET)
	assert.Contains(t, metricsText, "pelican_storage_reads_total{backend=\"posixv2\"}", "Should have posixv2 backend label")

	// Verify HTTP metrics structure
	assert.Contains(t, metricsText, "pelican_http_requests_total{", "Should have HTTP request metrics")
	assert.Contains(t, metricsText, "server_type=\"origin\"", "Should have server_type label")
	assert.Contains(t, metricsText, "method=\"GET\"", "Should have method label")

	// Verify histogram metrics (should have _bucket, _sum, _count)
	assert.Contains(t, metricsText, "pelican_http_request_duration_seconds_bucket", "Should have duration histogram buckets")
	assert.Contains(t, metricsText, "pelican_http_request_duration_seconds_sum", "Should have duration sum")
	assert.Contains(t, metricsText, "pelican_http_request_duration_seconds_count", "Should have duration count")

	// Verify gauge metrics are present
	assert.Contains(t, metricsText, "pelican_http_active_connections", "Should have active connections gauge")
	assert.Contains(t, metricsText, "pelican_http_active_requests", "Should have active requests gauge")
}
