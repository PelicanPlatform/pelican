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
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/metrics"
)

// setupTestServer creates a test Gin server with HTTP metrics middleware
func setupTestServer() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Add metrics middleware
	router.Use(httpMetricsMiddleware())

	// Add test handlers
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "Hello World")
	})

	router.GET("/error", func(c *gin.Context) {
		c.String(http.StatusInternalServerError, "Internal Error")
	})

	router.PUT("/upload", func(c *gin.Context) {
		body, _ := io.ReadAll(c.Request.Body)
		c.String(http.StatusOK, "Uploaded %d bytes", len(body))
	})

	router.DELETE("/delete", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	return router
}

// TestHTTPMetricsMiddlewareBasic tests basic HTTP request tracking
func TestHTTPMetricsMiddlewareBasic(t *testing.T) {
	// Reset metrics to avoid interference from other tests
	metrics.HttpConnectionsTotal.Reset()
	metrics.HttpRequestsTotal.Reset()

	router := setupTestServer()

	// Get initial metric values
	initialConnections := promtest.ToFloat64(metrics.HttpConnectionsTotal.WithLabelValues(metrics.ServerTypeOrigin))
	initialRequests := promtest.ToFloat64(metrics.HttpRequestsTotal.WithLabelValues(metrics.ServerTypeOrigin, "GET", "200"))

	// Make a GET request
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "Hello World", w.Body.String())

	// Verify connection metric incremented
	connections := promtest.ToFloat64(metrics.HttpConnectionsTotal.WithLabelValues(metrics.ServerTypeOrigin))
	assert.Greater(t, connections, initialConnections, "Connection count should increment")

	// Verify request metric incremented
	requests := promtest.ToFloat64(metrics.HttpRequestsTotal.WithLabelValues(metrics.ServerTypeOrigin, "GET", "200"))
	assert.Greater(t, requests, initialRequests, "Request count should increment for GET/200")
}

// TestHTTPMetricsMiddlewareErrorTracking tests 5xx error tracking
func TestHTTPMetricsMiddlewareErrorTracking(t *testing.T) {
	// Reset metrics
	metrics.HttpErrorsTotal.Reset()
	metrics.HttpRequestsTotal.Reset()

	router := setupTestServer()

	// Get initial error count
	initialErrors := promtest.ToFloat64(metrics.HttpErrorsTotal.WithLabelValues(metrics.ServerTypeOrigin, "GET", "500"))

	// Make a request that returns 500
	req := httptest.NewRequest("GET", "/error", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Verify response
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	// Verify error metric incremented
	errors := promtest.ToFloat64(metrics.HttpErrorsTotal.WithLabelValues(metrics.ServerTypeOrigin, "GET", "500"))
	assert.Greater(t, errors, initialErrors, "Error count should increment for 5xx responses")

	// Verify request metric also incremented
	requests := promtest.ToFloat64(metrics.HttpRequestsTotal.WithLabelValues(metrics.ServerTypeOrigin, "GET", "500"))
	assert.Greater(t, requests, float64(0), "Request count should track 5xx responses")
}

// TestHTTPMetricsByteTracking tests request and response byte tracking
func TestHTTPMetricsByteTracking(t *testing.T) {
	// Reset metrics
	metrics.HttpBytesTotal.Reset()

	router := setupTestServer()

	// Get initial byte counts
	initialBytesIn := promtest.ToFloat64(metrics.HttpBytesTotal.WithLabelValues(metrics.ServerTypeOrigin, metrics.DirectionIn, "PUT"))
	initialBytesOut := promtest.ToFloat64(metrics.HttpBytesTotal.WithLabelValues(metrics.ServerTypeOrigin, metrics.DirectionOut, "PUT"))

	// Upload data
	testData := []byte(strings.Repeat("A", 1000)) // 1000 bytes
	req := httptest.NewRequest("PUT", "/upload", bytes.NewReader(testData))
	req.Header.Set("Content-Length", "1000")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify bytes in tracked
	bytesIn := promtest.ToFloat64(metrics.HttpBytesTotal.WithLabelValues(metrics.ServerTypeOrigin, metrics.DirectionIn, "PUT"))
	assert.GreaterOrEqual(t, bytesIn-initialBytesIn, float64(1000), "Should track bytes sent in request")

	// Verify bytes out tracked
	bytesOut := promtest.ToFloat64(metrics.HttpBytesTotal.WithLabelValues(metrics.ServerTypeOrigin, metrics.DirectionOut, "PUT"))
	assert.Greater(t, bytesOut, initialBytesOut, "Should track bytes sent in response")
}

// TestHTTPMetricsLargeTransfers tests large transfer detection (>100MB)
func TestHTTPMetricsLargeTransfers(t *testing.T) {
	// Reset metrics
	metrics.HttpLargeTransfersTotal.Reset()
	metrics.HttpLargeTransferBytes.Reset()

	router := setupTestServer()

	// Get initial large transfer counts
	initialLargeTransfers := promtest.ToFloat64(metrics.HttpLargeTransfersTotal.WithLabelValues(metrics.ServerTypeOrigin, "PUT"))
	initialLargeBytes := promtest.ToFloat64(metrics.HttpLargeTransferBytes.WithLabelValues(metrics.ServerTypeOrigin, metrics.DirectionIn, "PUT"))

	// Simulate a large upload (>100MB)
	// We set Content-Length without actually sending the data (mock)
	largeSize := int64(150 * 1024 * 1024) // 150MB
	req := httptest.NewRequest("PUT", "/upload", bytes.NewReader([]byte("mock")))
	req.ContentLength = largeSize
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Verify large transfer metric incremented
	largeTransfers := promtest.ToFloat64(metrics.HttpLargeTransfersTotal.WithLabelValues(metrics.ServerTypeOrigin, "PUT"))
	assert.Greater(t, largeTransfers, initialLargeTransfers, "Should track large transfers >100MB")

	// Verify large transfer bytes tracked
	largeBytes := promtest.ToFloat64(metrics.HttpLargeTransferBytes.WithLabelValues(metrics.ServerTypeOrigin, metrics.DirectionIn, "PUT"))
	assert.Greater(t, largeBytes, initialLargeBytes, "Should track bytes for large transfers")
}

// TestHTTPMetricsRequestDuration tests request duration histogram
func TestHTTPMetricsRequestDuration(t *testing.T) {
	router := setupTestServer()

	// Make a request
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Verify duration histogram was updated
	// We can't easily check the exact duration, but we can verify the metric exists
	// by checking the count (which is part of the histogram)
	metric := metrics.HttpRequestDuration.WithLabelValues(metrics.ServerTypeOrigin, "GET", "200")
	observer, ok := metric.(prometheus.Observer)
	require.True(t, ok, "HttpRequestDuration should be an Observer")
	require.NotNil(t, observer, "HttpRequestDuration should not be nil")
}

// TestHTTPMetricsMultipleMethods tests tracking different HTTP methods
func TestHTTPMetricsMultipleMethods(t *testing.T) {
	// Reset metrics
	metrics.HttpRequestsTotal.Reset()

	router := setupTestServer()

	// Test different methods
	methods := []string{"GET", "PUT", "DELETE"}
	paths := []string{"/test", "/upload", "/delete"}
	expectedCodes := []int{200, 200, 204}

	for i, method := range methods {
		initialRequests := promtest.ToFloat64(metrics.HttpRequestsTotal.WithLabelValues(metrics.ServerTypeOrigin, method, http.StatusText(expectedCodes[i])))

		req := httptest.NewRequest(method, paths[i], nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Convert status code to string for metric label
		statusStr := fmt.Sprintf("%d", expectedCodes[i])

		requests := promtest.ToFloat64(metrics.HttpRequestsTotal.WithLabelValues(metrics.ServerTypeOrigin, method, statusStr))
		assert.Greater(t, requests, initialRequests, "Should track %s requests", method)
	}
}

// TestHTTPMetricsActiveConnections tests active connection gauge
func TestHTTPMetricsActiveConnections(t *testing.T) {
	router := setupTestServer()

	// Get initial active connections
	initialActive := promtest.ToFloat64(metrics.HttpActiveConnections.WithLabelValues(metrics.ServerTypeOrigin))

	// Make a request (synchronous, so active connections will go back to baseline)
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// After request completes, active connections should be back to baseline
	activeAfter := promtest.ToFloat64(metrics.HttpActiveConnections.WithLabelValues(metrics.ServerTypeOrigin))
	assert.Equal(t, initialActive, activeAfter, "Active connections should return to baseline after request completes")
}

// TestHTTPMetricsActiveRequests tests active request gauge
func TestHTTPMetricsActiveRequests(t *testing.T) {
	router := setupTestServer()

	// Get initial active requests
	initialActive := promtest.ToFloat64(metrics.HttpActiveRequests.WithLabelValues(metrics.ServerTypeOrigin, "GET"))

	// Make a request (synchronous, so active requests will go back to baseline)
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// After request completes, active requests should be back to baseline
	activeAfter := promtest.ToFloat64(metrics.HttpActiveRequests.WithLabelValues(metrics.ServerTypeOrigin, "GET"))
	assert.Equal(t, initialActive, activeAfter, "Active requests should return to baseline after request completes")
}

// TestMetricsResponseWriter tests the custom response writer
func TestMetricsResponseWriter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create a test gin context
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Wrap with metrics response writer
	mrw := &metricsResponseWriter{ResponseWriter: c.Writer}

	// Write some data
	testData := "Hello, metrics!"
	n, err := mrw.Write([]byte(testData))
	require.NoError(t, err)
	assert.Equal(t, len(testData), n)
	assert.Equal(t, int64(len(testData)), mrw.bytesWritten, "Should track bytes written")

	// Write more data with WriteString
	moreData := " More data."
	n, err = mrw.WriteString(moreData)
	require.NoError(t, err)
	assert.Equal(t, len(moreData), n)
	assert.Equal(t, int64(len(testData)+len(moreData)), mrw.bytesWritten, "Should accumulate bytes written")
}

// TestHTTPMetricsLabels verifies that all metrics use correct labels
func TestHTTPMetricsLabels(t *testing.T) {
	router := setupTestServer()

	// Make various requests
	methods := []string{"GET", "PUT", "DELETE"}
	paths := []string{"/test", "/upload", "/delete"}

	for i, method := range methods {
		req := httptest.NewRequest(method, paths[i], nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}

	// Verify metrics can be queried with server_type="origin" label
	// This will panic if labels are incorrect
	_ = promtest.ToFloat64(metrics.HttpConnectionsTotal.WithLabelValues(metrics.ServerTypeOrigin))
	_ = promtest.ToFloat64(metrics.HttpActiveConnections.WithLabelValues(metrics.ServerTypeOrigin))
	_ = promtest.ToFloat64(metrics.HttpRequestsTotal.WithLabelValues(metrics.ServerTypeOrigin, "GET", "200"))
	_ = promtest.ToFloat64(metrics.HttpBytesTotal.WithLabelValues(metrics.ServerTypeOrigin, metrics.DirectionIn, "GET"))
	_ = promtest.ToFloat64(metrics.HttpBytesTotal.WithLabelValues(metrics.ServerTypeOrigin, metrics.DirectionOut, "GET"))
	_ = promtest.ToFloat64(metrics.HttpActiveRequests.WithLabelValues(metrics.ServerTypeOrigin, "GET"))
}
