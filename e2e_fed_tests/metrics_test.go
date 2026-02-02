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

package fed_tests

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// verifyMetrics verifies that the specified metrics exist in Prometheus output with non-zero values
func verifyMetrics(t *testing.T, metricsText string, expectedMetrics map[string]string) {
	for metricName, description := range expectedMetrics {
		// Verify metric exists in output
		assert.Contains(t, metricsText, metricName, description)

		// Find the metric line and verify it has a non-zero value
		found := false
		for _, line := range strings.Split(metricsText, "\n") {
			if line == "" || line[0] == '#' {
				continue
			}
			if strings.Contains(line, metricName) && strings.Contains(line, `backend="posixv2"`) {
				found = true
				t.Logf("Found metric: %s", line)

				// Extract and verify the value is non-zero
				// Prometheus format: metric_name{labels} value
				parts := strings.Fields(line)
				require.GreaterOrEqual(t, len(parts), 2, "Metric line should have at least 2 parts")
				value := parts[len(parts)-1]
				assert.NotEqual(t, "0", value, "Metric %s should have non-zero value", metricName)
				break
			}
		}
		assert.True(t, found, "Should find %s with posixv2 backend", metricName)
	}
}

// setupMetricsTest creates a test federation with metrics enabled
func setupMetricsTest(t *testing.T) *fed_test_utils.FedTest {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	originConfig := `
Origin:
  StorageType: posixv2
  Exports:
    - FederationPrefix: /test
      StoragePrefix: /storage
      Capabilities: ["PublicReads", "Writes", "Listings"]
Monitoring:
  MetricAuthorization: false
`

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)
	require.Greater(t, len(ft.Exports), 0)
	return ft
}

// queryMetrics retrieves Prometheus metrics from the server
func queryMetrics(t *testing.T) string {
	client := &http.Client{Transport: config.GetTransport()}
	metricsURL := param.Server_ExternalWebUrl.GetString() + "/metrics"
	req, err := http.NewRequest("GET", metricsURL, nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "Should be able to access metrics endpoint")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

// verifyHTTPMetric verifies that pelican_http_requests_total exists with the specified method and status code
func verifyHTTPMetric(t *testing.T, metricsText, method, code string) {
	found := false
	for _, line := range strings.Split(metricsText, "\n") {
		if line == "" || line[0] == '#' {
			continue
		}
		if strings.Contains(line, "pelican_http_requests_total") &&
			strings.Contains(line, fmt.Sprintf(`method="%s"`, method)) &&
			strings.Contains(line, fmt.Sprintf(`code="%s"`, code)) &&
			strings.Contains(line, `server_type="origin"`) {
			found = true
			t.Logf("Found HTTP metric: %s", line)

			// Extract and verify the value is non-zero
			// Prometheus format: metric_name{labels} value
			parts := strings.Fields(line)
			require.GreaterOrEqual(t, len(parts), 2, "Metric line should have at least 2 parts")
			value := parts[len(parts)-1]
			assert.NotEqual(t, "0", value, "HTTP metric should have non-zero value")
			break
		}
	}
	assert.True(t, found, "Should have pelican_http_requests_total with method=%s, code=%s, server_type=origin", method, code)
}

// TestMetricsEndToEndWithAuth tests the complete metrics pipeline with authenticated read requests
func TestMetricsEndToEndWithAuth(t *testing.T) {
	ft := setupMetricsTest(t)

	// Create a test file
	testContent := "test data for auth metrics"
	testFile := filepath.Join(ft.Exports[0].StoragePrefix, "auth_test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte(testContent), 0644))

	// Make authenticated GET request
	testToken := getTempTokenForTest(t)
	client := &http.Client{Transport: config.GetTransport()}
	downloadURL := fmt.Sprintf("%s/test/auth_test.txt", param.Server_ExternalWebUrl.GetString())
	req, err := http.NewRequest("GET", downloadURL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testToken)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, testContent, string(body))

	// Query and verify metrics
	metricsText := queryMetrics(t)

	// Verify storage metrics with non-zero values
	verifyMetrics(t, metricsText, map[string]string{
		"pelican_storage_reads_total": "Should have storage read counter",
		"pelican_storage_bytes_read":  "Should have bytes read counter",
	})

	// Verify HTTP metrics (GET returns 206 Partial Content)
	verifyHTTPMetric(t, metricsText, "GET", "206")
}

// TestMetricsEndToEndWriteOperations tests metrics for write/PUT operations
func TestMetricsEndToEndWriteOperations(t *testing.T) {
	ft := setupMetricsTest(t)

	// Create test content and make authenticated PUT request
	testContent := "test data for write metrics"
	testToken := getTempTokenForTest(t)
	client := &http.Client{Transport: config.GetTransport()}
	uploadURL := fmt.Sprintf("%s/test/write_test.txt", param.Server_ExternalWebUrl.GetString())
	req, err := http.NewRequest("PUT", uploadURL, bytes.NewBufferString(testContent))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Verify file was actually written
	writtenFile := filepath.Join(ft.Exports[0].StoragePrefix, "write_test.txt")
	content, err := os.ReadFile(writtenFile)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(content), "File content should match uploaded data")

	// Query and verify metrics
	metricsText := queryMetrics(t)

	// Verify storage write metrics with non-zero values
	verifyMetrics(t, metricsText, map[string]string{
		"pelican_storage_writes_total":  "Should have storage write counter",
		"pelican_storage_bytes_written": "Should have bytes written counter",
	})

	// Verify HTTP metrics (PUT returns 201 Created)
	verifyHTTPMetric(t, metricsText, "PUT", "201")
}
