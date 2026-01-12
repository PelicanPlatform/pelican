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

package metrics

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

func TestGetFilesystemUsage(t *testing.T) {
	ctx := context.Background()

	// Test with /tmp which should always exist
	usage, totalBytes, usedBytes, err := getFilesystemUsage(ctx, "/tmp")

	require.NoError(t, err, "Should successfully get filesystem usage for /tmp")
	assert.GreaterOrEqual(t, usage, 0.0, "Usage percentage should be non-negative")
	assert.LessOrEqual(t, usage, 100.0, "Usage percentage should not exceed 100")
	assert.Greater(t, totalBytes, uint64(0), "Total bytes should be positive")
	assert.LessOrEqual(t, usedBytes, totalBytes, "Used bytes should not exceed total bytes")

	t.Logf("Filesystem usage for /tmp: %.2f%% (%d/%d bytes)", usage, usedBytes, totalBytes)
}

func TestGetFilesystemUsageInvalidPath(t *testing.T) {
	ctx := context.Background()
	_, _, _, err := getFilesystemUsage(ctx, "/nonexistent/path/that/does/not/exist")
	assert.Error(t, err, "Should return error for non-existent path")
}

func TestGetFilesystemUsageWithCustomFunction(t *testing.T) {
	// Save original implementation
	originalImpl := getFilesystemUsageImpl
	defer func() { getFilesystemUsageImpl = originalImpl }()

	// Override with custom implementation
	getFilesystemUsageImpl = func(path string) (usagePercent float64, totalBytes uint64, usedBytes uint64, err error) {
		return 75.0, 1000000, 750000, nil
	}

	usage, totalBytes, usedBytes, err := getFilesystemUsage(context.Background(), "/any/path")
	require.NoError(t, err)
	assert.Equal(t, 75.0, usage)
	assert.Equal(t, uint64(1000000), totalBytes)
	assert.Equal(t, uint64(750000), usedBytes)
}

func TestCheckStorageHealthOK(t *testing.T) {
	// Save original implementation
	originalImpl := getFilesystemUsageImpl
	defer func() { getFilesystemUsageImpl = originalImpl }()

	err := param.Reset()
	require.NoError(t, err)
	config.ResetConfig()
	defer config.ResetConfig()

	// Set up test configuration
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.sqlite")

	err = param.MultiSet(map[string]interface{}{
		param.Server_DbLocation.GetName():                   dbPath,
		param.Monitoring_StorageWarningThreshold.GetName():  80,
		param.Monitoring_StorageCriticalThreshold.GetName(): 90,
	})
	require.NoError(t, err)

	// Override with custom implementation to simulate 50% usage (OK status)
	getFilesystemUsageImpl = func(path string) (usagePercent float64, totalBytes uint64, usedBytes uint64, err error) {
		return 50.0, 1000000, 500000, nil
	}

	modules := server_structs.ServerType(0)
	checkStorageHealth(context.Background(), modules)

	statusStr, err := GetComponentStatus(Server_StorageHealth)
	require.NoError(t, err)
	assert.Equal(t, StatusOK.String(), statusStr)
}

func TestCheckStorageHealthWarning(t *testing.T) {
	// Save original implementation
	originalImpl := getFilesystemUsageImpl
	defer func() { getFilesystemUsageImpl = originalImpl }()

	err := param.Reset()
	require.NoError(t, err)
	config.ResetConfig()
	defer config.ResetConfig()

	// Set up test configuration
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.sqlite")

	err = param.MultiSet(map[string]interface{}{
		param.Server_DbLocation.GetName():                   dbPath,
		param.Monitoring_StorageWarningThreshold.GetName():  80,
		param.Monitoring_StorageCriticalThreshold.GetName(): 90,
	})
	require.NoError(t, err)

	// Override with custom implementation to simulate 85% usage (Warning status)
	getFilesystemUsageImpl = func(path string) (usagePercent float64, totalBytes uint64, usedBytes uint64, err error) {
		return 85.0, 1000000, 850000, nil
	}

	modules := server_structs.ServerType(0)
	checkStorageHealth(context.Background(), modules)

	statusStr, err := GetComponentStatus(Server_StorageHealth)
	require.NoError(t, err)
	assert.Equal(t, StatusWarning.String(), statusStr)
}

func TestCheckStorageHealthCritical(t *testing.T) {
	// Save original implementation
	originalImpl := getFilesystemUsageImpl
	defer func() { getFilesystemUsageImpl = originalImpl }()

	err := param.Reset()
	require.NoError(t, err)
	config.ResetConfig()
	defer config.ResetConfig()

	// Set up test configuration
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.sqlite")

	err = param.MultiSet(map[string]interface{}{
		param.Server_DbLocation.GetName():                   dbPath,
		param.Monitoring_StorageWarningThreshold.GetName():  80,
		param.Monitoring_StorageCriticalThreshold.GetName(): 90,
	})
	require.NoError(t, err)

	// Override with custom implementation to simulate 95% usage (Critical status)
	getFilesystemUsageImpl = func(path string) (usagePercent float64, totalBytes uint64, usedBytes uint64, err error) {
		return 95.0, 1000000, 950000, nil
	}

	modules := server_structs.ServerType(0)
	checkStorageHealth(context.Background(), modules)

	statusStr, err := GetComponentStatus(Server_StorageHealth)
	require.NoError(t, err)
	assert.Equal(t, StatusCritical.String(), statusStr)
}

func TestGetPathsToCheckLogging(t *testing.T) {
	tests := []struct {
		name          string
		logLocation   string
		shouldInclude bool
	}{
		{
			name:          "Regular log file",
			logLocation:   "/var/log/pelican/pelican.log",
			shouldInclude: true,
		},
		{
			name:          "/dev/null",
			logLocation:   "/dev/null",
			shouldInclude: false,
		},
		{
			name:          "Empty string (stdout)",
			logLocation:   "",
			shouldInclude: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := param.Reset()
			require.NoError(t, err)
			config.ResetConfig()
			defer config.ResetConfig()

			err = param.MultiSet(map[string]interface{}{
				param.Logging_LogLocation.GetName():     tt.logLocation,
				param.Server_DbLocation.GetName():       "", // Disable other checks
				param.Monitoring_DataLocation.GetName(): "",
			})
			require.NoError(t, err)

			modules := server_structs.ServerType(0)
			paths := getPathsToCheck(modules)

			if tt.shouldInclude {
				assert.NotEmpty(t, paths, "Expected paths to include log directory")
				expectedDir := filepath.Dir(tt.logLocation)
				assert.Contains(t, paths, expectedDir)
			} else {
				assert.Empty(t, paths, "Expected no paths for %s", tt.logLocation)
			}
		})
	}
}

func TestGetPathsToCheckModuleDBs(t *testing.T) {
	err := param.Reset()
	require.NoError(t, err)
	config.ResetConfig()
	defer config.ResetConfig()

	tempDir := t.TempDir()

	// Set up DB locations for all modules
	err = param.MultiSet(map[string]interface{}{
		param.Server_DbLocation.GetName():       filepath.Join(tempDir, "server.sqlite"),
		param.Origin_DbLocation.GetName():       filepath.Join(tempDir, "origin", "origin.sqlite"),
		param.Registry_DbLocation.GetName():     filepath.Join(tempDir, "registry", "registry.sqlite"),
		param.Director_DbLocation.GetName():     filepath.Join(tempDir, "director", "director.sqlite"),
		param.Cache_DbLocation.GetName():        filepath.Join(tempDir, "cache", "cache.sqlite"),
		param.Logging_LogLocation.GetName():     "", // Disable log check
		param.Monitoring_DataLocation.GetName(): "", // Disable monitoring check
	})
	require.NoError(t, err)

	// Test with no modules enabled
	modules := server_structs.ServerType(0)
	paths := getPathsToCheck(modules)
	// Should only have Server.DbLocation
	assert.Len(t, paths, 1)
	assert.Contains(t, paths, tempDir)

	// Test with Origin enabled
	modules = server_structs.ServerType(0)
	modules.Set(server_structs.OriginType)
	paths = getPathsToCheck(modules)
	// Should have Server.DbLocation and Origin.DbLocation
	assert.GreaterOrEqual(t, len(paths), 2)
	assert.Contains(t, paths, filepath.Join(tempDir, "origin"))

	// Test with all modules enabled
	modules = server_structs.ServerType(0)
	modules.Set(server_structs.OriginType)
	modules.Set(server_structs.RegistryType)
	modules.Set(server_structs.DirectorType)
	modules.Set(server_structs.CacheType)
	paths = getPathsToCheck(modules)
	// Should have all DB locations
	assert.GreaterOrEqual(t, len(paths), 5)
	assert.Contains(t, paths, tempDir) // Server
	assert.Contains(t, paths, filepath.Join(tempDir, "origin"))
	assert.Contains(t, paths, filepath.Join(tempDir, "registry"))
	assert.Contains(t, paths, filepath.Join(tempDir, "director"))
	assert.Contains(t, paths, filepath.Join(tempDir, "cache"))
}

func TestGetPathsToCheckPrometheusConditional(t *testing.T) {
	tests := []struct {
		name               string
		enablePrometheus   bool
		monitoringDataPath string
		shouldInclude      bool
	}{
		{
			name:               "Prometheus enabled with path",
			enablePrometheus:   true,
			monitoringDataPath: "/var/lib/pelican/prometheus",
			shouldInclude:      true,
		},
		{
			name:               "Prometheus disabled with path",
			enablePrometheus:   false,
			monitoringDataPath: "/var/lib/pelican/prometheus",
			shouldInclude:      false,
		},
		{
			name:               "Prometheus enabled without path",
			enablePrometheus:   true,
			monitoringDataPath: "",
			shouldInclude:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := param.Reset()
			require.NoError(t, err)
			config.ResetConfig()
			defer config.ResetConfig()

			err = param.MultiSet(map[string]interface{}{
				param.Monitoring_EnablePrometheus.GetName(): tt.enablePrometheus,
				param.Monitoring_DataLocation.GetName():     tt.monitoringDataPath,
				param.Server_DbLocation.GetName():           "", // Disable other checks
				param.Logging_LogLocation.GetName():         "",
			})
			require.NoError(t, err)

			modules := server_structs.ServerType(0)
			paths := getPathsToCheck(modules)

			if tt.shouldInclude {
				assert.NotEmpty(t, paths)
				assert.Contains(t, paths, tt.monitoringDataPath)
			} else {
				// Should either be empty or not contain the monitoring path
				if len(paths) > 0 {
					assert.NotContains(t, paths, tt.monitoringDataPath)
				}
			}
		})
	}
}

func TestCheckStorageHealthMultiplePaths(t *testing.T) {
	// Save original implementation
	originalImpl := getFilesystemUsageImpl
	defer func() { getFilesystemUsageImpl = originalImpl }()

	err := param.Reset()
	require.NoError(t, err)
	config.ResetConfig()
	defer config.ResetConfig()

	tempDir := t.TempDir()

	// Create subdirectories for different components
	originDir := filepath.Join(tempDir, "origin")
	registryDir := filepath.Join(tempDir, "registry")
	err = os.MkdirAll(originDir, 0755)
	require.NoError(t, err)
	err = os.MkdirAll(registryDir, 0755)
	require.NoError(t, err)

	// Set up DB locations
	err = param.MultiSet(map[string]interface{}{
		param.Server_DbLocation.GetName():                   filepath.Join(tempDir, "server.sqlite"),
		param.Origin_DbLocation.GetName():                   filepath.Join(originDir, "origin.sqlite"),
		param.Registry_DbLocation.GetName():                 filepath.Join(registryDir, "registry.sqlite"),
		param.Logging_LogLocation.GetName():                 "",
		param.Monitoring_DataLocation.GetName():             "",
		param.Monitoring_StorageWarningThreshold.GetName():  80,
		param.Monitoring_StorageCriticalThreshold.GetName(): 90,
	})
	require.NoError(t, err)

	// Enable origin and registry modules
	modules := server_structs.ServerType(0)
	modules.Set(server_structs.OriginType)
	modules.Set(server_structs.RegistryType)

	// Override with custom implementation
	getFilesystemUsageImpl = func(path string) (usagePercent float64, totalBytes uint64, usedBytes uint64, err error) {
		return 60.0, 1000000, 600000, nil
	}

	checkStorageHealth(context.Background(), modules)

	statusStr, err := GetComponentStatus(Server_StorageHealth)
	require.NoError(t, err)
	assert.Equal(t, StatusOK.String(), statusStr)
}

func TestCheckStorageHealthInvalidThresholds(t *testing.T) {
	tests := []struct {
		name              string
		warningThreshold  int
		criticalThreshold int
		usage             float64
		expectedStatus    HealthStatusEnum
	}{
		{
			name:              "Inverted thresholds",
			warningThreshold:  95,
			criticalThreshold: 80,
			usage:             85.0,
			expectedStatus:    StatusWarning, // Should use defaults (80/90), so 85% is warning
		},
		{
			name:              "Negative warning threshold",
			warningThreshold:  -5,
			criticalThreshold: 90,
			usage:             85.0,
			expectedStatus:    StatusWarning, // Should use default warning (80)
		},
		{
			name:              "Out of range critical threshold",
			warningThreshold:  80,
			criticalThreshold: 150,
			usage:             85.0,
			expectedStatus:    StatusWarning, // Should use default critical (90)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original implementation
			originalImpl := getFilesystemUsageImpl
			defer func() { getFilesystemUsageImpl = originalImpl }()

			err := param.Reset()
			require.NoError(t, err)
			config.ResetConfig()
			defer config.ResetConfig()

			tempDir := t.TempDir()
			dbPath := filepath.Join(tempDir, "test.sqlite")

			err = param.MultiSet(map[string]interface{}{
				param.Server_DbLocation.GetName():                   dbPath,
				param.Monitoring_StorageWarningThreshold.GetName():  tt.warningThreshold,
				param.Monitoring_StorageCriticalThreshold.GetName(): tt.criticalThreshold,
			})
			require.NoError(t, err)

			// Override with custom implementation
			getFilesystemUsageImpl = func(path string) (usagePercent float64, totalBytes uint64, usedBytes uint64, err error) {
				return tt.usage, 1000000, uint64(tt.usage * 10000), nil
			}

			modules := server_structs.ServerType(0)
			checkStorageHealth(context.Background(), modules)

			statusStr, err := GetComponentStatus(Server_StorageHealth)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedStatus.String(), statusStr)
		})
	}
}

func TestCheckStorageHealthCriticalUpgradesFromWarning(t *testing.T) {
	// Save original implementation
	originalImpl := getFilesystemUsageImpl
	defer func() { getFilesystemUsageImpl = originalImpl }()

	err := param.Reset()
	require.NoError(t, err)
	config.ResetConfig()
	defer config.ResetConfig()

	tempDir := t.TempDir()

	dir1 := filepath.Join(tempDir, "dir1")
	dir2 := filepath.Join(tempDir, "dir2")
	err = os.MkdirAll(dir1, 0755)
	require.NoError(t, err)
	err = os.MkdirAll(dir2, 0755)
	require.NoError(t, err)

	err = param.MultiSet(map[string]interface{}{
		param.Server_DbLocation.GetName():                   filepath.Join(dir1, "server.sqlite"),
		param.Origin_DbLocation.GetName():                   filepath.Join(dir2, "origin.sqlite"),
		param.Logging_LogLocation.GetName():                 "",
		param.Monitoring_DataLocation.GetName():             "",
		param.Monitoring_StorageWarningThreshold.GetName():  80,
		param.Monitoring_StorageCriticalThreshold.GetName(): 90,
	})
	require.NoError(t, err)

	modules := server_structs.ServerType(0)
	modules.Set(server_structs.OriginType)

	callCount := 0
	// Override with custom implementation
	getFilesystemUsageImpl = func(path string) (usagePercent float64, totalBytes uint64, usedBytes uint64, err error) {
		callCount++
		if callCount == 1 {
			return 85.0, 1000000, 850000, nil
		}
		return 95.0, 1000000, 950000, nil
	}

	checkStorageHealth(context.Background(), modules)

	statusStr, err := GetComponentStatus(Server_StorageHealth)
	require.NoError(t, err)
	assert.Equal(t, StatusCritical.String(), statusStr, "Critical status should override warning status")
}
