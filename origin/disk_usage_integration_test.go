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

package origin

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

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// TestDiskUsageIntegration tests the complete disk usage calculation flow
func TestDiskUsageIntegration(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

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
	LaunchDiskUsageCalculator(ctx, egrp)

	// Wait a bit for the initial calculation to complete
	time.Sleep(500 * time.Millisecond)

	// Check that metrics were updated
	bytesMetric := PelicanOriginDiskUsageBytes.WithLabelValues("/test")
	bytesValue := testutil.ToFloat64(bytesMetric)
	assert.Equal(t, float64(10), bytesValue, "Expected 10 bytes (5 + 5)")

	objectsMetric := PelicanOriginDiskUsageObjects.WithLabelValues("/test")
	objectsValue := testutil.ToFloat64(objectsMetric)
	assert.Equal(t, float64(2), objectsValue, "Expected 2 objects")

	// Check that the crawl duration metric was set
	durationValue := testutil.ToFloat64(PelicanOriginDiskUsageCrawlDuration)
	assert.Greater(t, durationValue, float64(0), "Crawl duration should be greater than 0")

	// Check that the last crawl timestamp was set
	timestampValue := testutil.ToFloat64(PelicanOriginDiskUsageLastCrawlTimestamp)
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
	LaunchDiskUsageCalculator(ctx, egrp)

	// Wait a bit
	time.Sleep(200 * time.Millisecond)

	// The calculator should have logged that it's disabled and returned immediately

	cancel()
	err := egrp.Wait()
	assert.NoError(t, err)
}
