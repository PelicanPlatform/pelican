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

package origin_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/origin"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// TestDiskUsageIntegration tests the complete disk usage calculation flow
func TestDiskUsageIntegration(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()
	origin.PelicanOriginDiskUsageBytes.Reset()
	origin.PelicanOriginDiskUsageObjects.Reset()
	origin.PelicanOriginDiskUsageCrawlErrors.Reset()

	// Create a temporary directory with test files
	tmpDir := t.TempDir()
	exportDir := filepath.Join(tmpDir, "export")
	require.NoError(t, os.MkdirAll(exportDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(exportDir, "file1.txt"), []byte("hello"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(exportDir, "file2.txt"), []byte("world"), 0644))

	// Configure parameters
	require.NoError(t, param.Set(param.Origin_StorageType.GetName(), "posix"))
	require.NoError(t, param.Set(param.Origin_EnableDiskUsageCalculation.GetName(), true))
	require.NoError(t, param.Set(param.Origin_DiskUsageCalculationInterval.GetName(), "100ms"))
	require.NoError(t, param.Set(param.Origin_DiskUsageCalculationRateLimit.GetName(), 1000))
	require.NoError(t, param.Set(param.Origin_ExportVolumes.GetName(), []string{exportDir + ":/test"}))

	// Reset the origin exports cache to pick up new configuration
	server_utils.ResetOriginExports()

	// Verify exports are configured correctly
	exports, err := server_utils.GetOriginExports()
	require.NoError(t, err)
	require.Len(t, exports, 1)
	assert.Equal(t, "/test", exports[0].FederationPrefix)

	// Create context and errgroup for the launcher
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	egrp := &errgroup.Group{}

	// Launch the disk usage calculator
	origin.LaunchDiskUsageCalculator(ctx, egrp)

	// Wait for the initial calculation to complete
	require.Eventually(t, func() bool {
		bytesMetric := origin.PelicanOriginDiskUsageBytes.WithLabelValues("/test")
		return testutil.ToFloat64(bytesMetric) == 10
	}, 5*time.Second, 100*time.Millisecond, "Disk usage bytes did not reach expected value")

	// Check that metrics were updated
	bytesMetric := origin.PelicanOriginDiskUsageBytes.WithLabelValues("/test")
	bytesValue := testutil.ToFloat64(bytesMetric)
	assert.Equal(t, float64(10), bytesValue, "Expected 10 bytes (5 + 5)")

	objectsMetric := origin.PelicanOriginDiskUsageObjects.WithLabelValues("/test")
	objectsValue := testutil.ToFloat64(objectsMetric)
	assert.Equal(t, float64(2), objectsValue, "Expected 2 objects")

	// Check that the crawl duration metric was set
	durationValue := testutil.ToFloat64(origin.PelicanOriginDiskUsageCrawlDuration)
	assert.Greater(t, durationValue, float64(0), "Crawl duration should be greater than 0")

	// Check that the last crawl timestamp was set
	timestampValue := testutil.ToFloat64(origin.PelicanOriginDiskUsageLastCrawlTimestamp)
	assert.Greater(t, timestampValue, float64(0), "Last crawl timestamp should be set")

	// Cancel context and wait for goroutines to finish
	cancel()
	err = egrp.Wait()
	assert.NoError(t, err)
}

// TestDiskUsageDisabled verifies that the calculator doesn't run when disabled
func TestDiskUsageDisabled(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Disable disk usage calculation
	require.NoError(t, param.Set(param.Origin_EnableDiskUsageCalculation.GetName(), false))

	// Create context and errgroup
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	egrp := &errgroup.Group{}

	// Launch the disk usage calculator (should do nothing)
	origin.LaunchDiskUsageCalculator(ctx, egrp)

	// The calculator should have logged that it's disabled and returned immediately

	cancel()
	err := egrp.Wait()
	assert.NoError(t, err)
}

func TestDiskUsageSuccessPelican(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()
	origin.PelicanOriginDiskUsageBytes.Reset()
	origin.PelicanOriginDiskUsageObjects.Reset()
	origin.PelicanOriginDiskUsageCrawlErrors.Reset()
	// Single metrics cannot be reset easily, but it shouldn't matter for these tests as we check specific values

	// Setup a federation with Director, Registry, and Origin
	originConfig := `
Origin:
  StorageType: posix
  Exports:
    - StoragePrefix: /foo
      FederationPrefix: /test
      Capabilities:
        PublicReads: true
        Listings: true
`

	fed := fed_test_utils.NewFedTest(t, originConfig)

	// Create a file in the origin's storage
	exportPath := fed.Exports[0].StoragePrefix
	testFile := filepath.Join(exportPath, "test.txt")
	testContent := []byte("hello world")
	err := os.WriteFile(testFile, testContent, 0644)
	require.NoError(t, err)

	// Verify discovery URL is set
	discoveryUrl := param.Federation_DiscoveryUrl.GetString()
	require.NotEmpty(t, discoveryUrl)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run the calculation forcing PelicanFS-based crawling
	// (instead of the default POSIX directory walk)
	err = origin.CalculateDiskUsage(ctx, true)
	require.NoError(t, err)

	// Verification
	// Check the metrics
	// PelicanOriginDiskUsageBytes should have the size of the file
	// We need to get the metric value for label "/test"
	metricBytes := origin.PelicanOriginDiskUsageBytes.WithLabelValues("/test")
	valBytes := testutil.ToFloat64(metricBytes)
	assert.Equal(t, float64(len(testContent)+len("Hello, World!")), valBytes, "Disk usage bytes should match file size")

	metricCount := origin.PelicanOriginDiskUsageObjects.WithLabelValues("/test")
	valCount := testutil.ToFloat64(metricCount)
	assert.Equal(t, float64(2), valCount, "Disk usage object count should be 2")

	// Check that we didn't have errors
	metricErrors := origin.PelicanOriginDiskUsageCrawlErrors.WithLabelValues("/test")
	valErrors := testutil.ToFloat64(metricErrors)
	assert.Equal(t, 0.0, valErrors, "Disk usage crawl errors should be 0")
}
