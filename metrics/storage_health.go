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
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

const (
	// firstCheckDelay is the delay before the first storage health check runs
	firstCheckDelay = 5 * time.Second
)

// getFilesystemUsageImpl is a package-level variable that holds the function to get filesystem usage.
// It can be overridden in tests to inject custom implementations.
var getFilesystemUsageImpl = func(path string) (usagePercent float64, totalBytes uint64, usedBytes uint64, err error) {
	var stat syscall.Statfs_t
	if err = syscall.Statfs(path, &stat); err != nil {
		err = errors.Wrapf(err, "unable to determine filesystem usage for path %s", path)
		return
	}

	// Calculate usage
	totalBytes = stat.Blocks * uint64(stat.Bsize)
	availableBytes := stat.Bavail * uint64(stat.Bsize)
	usedBytes = totalBytes - availableBytes

	if totalBytes > 0 {
		usagePercent = float64(usedBytes) / float64(totalBytes) * 100.0
	}

	return
}

// getFilesystemUsage returns the percentage of storage used for a given path.
// Returns usage percentage (0-100), total bytes, used bytes, and any error.
func getFilesystemUsage(ctx context.Context, path string) (usagePercent float64, totalBytes uint64, usedBytes uint64, err error) {
	return getFilesystemUsageImpl(path)
}

// getPathsToCheck returns a deduplicated list of filesystem paths that should be checked
// for storage consumption. It gathers paths from various configuration parameters.
func getPathsToCheck(modules server_structs.ServerType) []string {
	pathsMap := make(map[string]bool)
	var paths []string

	// Add logging location if configured and not /dev/null
	// Empty string means stdout, so we skip it
	if logPath := param.Logging_LogLocation.GetString(); logPath != "" && logPath != "/dev/null" {
		// Get the directory containing the log file
		logDir := filepath.Dir(logPath)
		pathsMap[logDir] = true
	}

	// Add Server.DbLocation (always used)
	if dbPath := param.Server_DbLocation.GetString(); dbPath != "" {
		dbDir := filepath.Dir(dbPath)
		pathsMap[dbDir] = true
	}

	// Add module-specific database locations
	if modules.IsEnabled(server_structs.RegistryType) {
		if dbPath := param.Registry_DbLocation.GetString(); dbPath != "" {
			dbDir := filepath.Dir(dbPath)
			pathsMap[dbDir] = true
		}
	}
	if modules.IsEnabled(server_structs.OriginType) {
		if dbPath := param.Origin_DbLocation.GetString(); dbPath != "" {
			dbDir := filepath.Dir(dbPath)
			pathsMap[dbDir] = true
		}
	}
	if modules.IsEnabled(server_structs.DirectorType) {
		if dbPath := param.Director_DbLocation.GetString(); dbPath != "" {
			dbDir := filepath.Dir(dbPath)
			pathsMap[dbDir] = true
		}
	}
	if modules.IsEnabled(server_structs.CacheType) {
		if dbPath := param.Cache_DbLocation.GetString(); dbPath != "" {
			dbDir := filepath.Dir(dbPath)
			pathsMap[dbDir] = true
		}
	}

	// Add monitoring data location only if Prometheus is enabled
	if param.Monitoring_EnablePrometheus.GetBool() {
		if monitoringPath := param.Monitoring_DataLocation.GetString(); monitoringPath != "" {
			pathsMap[monitoringPath] = true
		}
	}

	// Convert map keys to slice
	for path := range pathsMap {
		paths = append(paths, path)
	}

	return paths
}

// checkStorageHealth checks the storage usage for all configured paths and updates
// the health status accordingly.
func checkStorageHealth(ctx context.Context, modules server_structs.ServerType) {
	paths := getPathsToCheck(modules)

	if len(paths) == 0 {
		log.Debug("No paths configured for storage health check")
		SetComponentHealthStatus(Server_StorageHealth, StatusOK, "No paths configured for monitoring")
		return
	}

	warningThreshold := param.Monitoring_StorageWarningThreshold.GetInt()
	criticalThreshold := param.Monitoring_StorageCriticalThreshold.GetInt()

	// Validate thresholds
	if warningThreshold < 0 || warningThreshold > 100 {
		log.Warningf("Invalid warning threshold %d%%, using default 80%%", warningThreshold)
		warningThreshold = 80
	}
	if criticalThreshold < 0 || criticalThreshold > 100 {
		log.Warningf("Invalid critical threshold %d%%, using default 90%%", criticalThreshold)
		criticalThreshold = 90
	}
	if warningThreshold >= criticalThreshold {
		log.Warningf("Warning threshold (%d%%) must be less than critical threshold (%d%%), using defaults", warningThreshold, criticalThreshold)
		warningThreshold = 80
		criticalThreshold = 90
	}

	// Track the worst status found
	worstStatus := StatusOK
	var statusMessages []string

	for _, path := range paths {
		usage, totalBytes, usedBytes, err := getFilesystemUsage(ctx, path)
		if err != nil {
			log.Warningf("Failed to check storage for path %s: %v", path, err)
			// Only downgrade status if currently better than warning
			if worstStatus > StatusWarning {
				worstStatus = StatusWarning
			}
			statusMessages = append(statusMessages, fmt.Sprintf("Failed to check %s: %v", path, err))
			continue
		}

		log.Debugf("Storage check for %s: %.2f%% used (%d/%d bytes)", path, usage, usedBytes, totalBytes)

		// Determine status for this path
		if usage >= float64(criticalThreshold) {
			worstStatus = StatusCritical
			statusMessages = append(statusMessages, fmt.Sprintf("%s: %.1f%% used (critical threshold: %d%%)", path, usage, criticalThreshold))
		} else if usage >= float64(warningThreshold) {
			// Only downgrade status if currently better than warning
			if worstStatus > StatusWarning {
				worstStatus = StatusWarning
			}
			// Always report warning-level paths in the status message
			statusMessages = append(statusMessages, fmt.Sprintf("%s: %.1f%% used (warning threshold: %d%%)", path, usage, warningThreshold))
		}
	}

	// Set the overall status
	switch worstStatus {
	case StatusOK:
		SetComponentHealthStatus(Server_StorageHealth, StatusOK, "All monitored filesystems have adequate storage")
	case StatusWarning:
		msg := "Storage usage is elevated: " + strings.Join(statusMessages, "; ")
		SetComponentHealthStatus(Server_StorageHealth, StatusWarning, msg)
	case StatusCritical:
		msg := "Storage usage is critical: " + strings.Join(statusMessages, "; ")
		SetComponentHealthStatus(Server_StorageHealth, StatusCritical, msg)
	}
}

// LaunchStorageHealthMonitor starts a goroutine that periodically checks filesystem
// storage consumption for configured paths and updates health status accordingly.
func LaunchStorageHealthMonitor(ctx context.Context, egrp *errgroup.Group, modules server_structs.ServerType) {
	checkInterval := param.Monitoring_StorageHealthCheckInterval.GetDuration()

	if checkInterval <= 0 {
		log.Debug("Storage health check disabled (interval <= 0)")
		return
	}

	ticker := time.NewTicker(checkInterval)
	firstCheck := time.After(firstCheckDelay)

	egrp.Go(func() error {
		defer ticker.Stop()
		log.Debugf("Storage health monitor started with interval: %s", checkInterval)

		for {
			select {
			case <-firstCheck:
				checkStorageHealth(ctx, modules)
			case <-ticker.C:
				checkStorageHealth(ctx, modules)
			case <-ctx.Done():
				log.Info("Storage health monitor has been terminated")
				return nil
			}
		}
	})
}
