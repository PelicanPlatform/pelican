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

//go:build !windows

package metrics

import (
	"context"
	"fmt"
	"path/filepath"
	"syscall"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/param"
)

const (
	// firstCheckDelay is the delay before the first storage health check runs
	firstCheckDelay = 5 * time.Second
)

// getFilesystemUsage returns the percentage of storage used for a given path.
// Returns usage percentage (0-100), total bytes, used bytes, and any error.
func getFilesystemUsage(path string) (usagePercent float64, totalBytes uint64, usedBytes uint64, err error) {
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

// getPathsToCheck returns a deduplicated list of filesystem paths that should be checked
// for storage consumption. It gathers paths from various configuration parameters.
func getPathsToCheck() []string {
	pathsMap := make(map[string]bool)
	var paths []string

	// Add logging location if configured
	if logPath := param.Logging_LogLocation.GetString(); logPath != "" {
		// Get the directory containing the log file
		logDir := filepath.Dir(logPath)
		pathsMap[logDir] = true
	}

	// Add database location
	if dbPath := param.Server_DbLocation.GetString(); dbPath != "" {
		dbDir := filepath.Dir(dbPath)
		pathsMap[dbDir] = true
	}

	// Add monitoring data location
	if monitoringPath := param.Monitoring_DataLocation.GetString(); monitoringPath != "" {
		pathsMap[monitoringPath] = true
	}

	// Convert map keys to slice
	for path := range pathsMap {
		paths = append(paths, path)
	}

	return paths
}

// checkStorageHealth checks the storage usage for all configured paths and updates
// the health status accordingly.
func checkStorageHealth() {
	paths := getPathsToCheck()
	
	if len(paths) == 0 {
		log.Debug("No paths configured for storage health check")
		SetComponentHealthStatus(Server_StorageHealth, StatusOK, "No paths configured for monitoring")
		return
	}

	warningThreshold := param.Monitoring_StorageWarningThreshold.GetInt()
	criticalThreshold := param.Monitoring_StorageCriticalThreshold.GetInt()

	// Track the worst status found
	worstStatus := StatusOK
	var statusMessages []string

	for _, path := range paths {
		usage, totalBytes, usedBytes, err := getFilesystemUsage(path)
		if err != nil {
			log.Warningf("Failed to check storage for path %s: %v", path, err)
			worstStatus = StatusWarning
			statusMessages = append(statusMessages, fmt.Sprintf("Failed to check %s: %v", path, err))
			continue
		}

		log.Debugf("Storage check for %s: %.2f%% used (%d/%d bytes)", path, usage, usedBytes, totalBytes)

		// Determine status for this path
		if usage >= float64(criticalThreshold) {
			if worstStatus < StatusCritical || worstStatus == StatusOK {
				worstStatus = StatusCritical
			}
			statusMessages = append(statusMessages, fmt.Sprintf("%s: %.1f%% used (critical threshold: %d%%)", path, usage, criticalThreshold))
		} else if usage >= float64(warningThreshold) {
			if worstStatus < StatusWarning || worstStatus == StatusOK {
				worstStatus = StatusWarning
			}
			statusMessages = append(statusMessages, fmt.Sprintf("%s: %.1f%% used (warning threshold: %d%%)", path, usage, warningThreshold))
		}
	}

	// Set the overall status
	if worstStatus == StatusOK {
		SetComponentHealthStatus(Server_StorageHealth, StatusOK, "All monitored filesystems have adequate storage")
	} else if worstStatus == StatusWarning {
		msg := "Storage usage is elevated: "
		for i, m := range statusMessages {
			if i > 0 {
				msg += "; "
			}
			msg += m
		}
		SetComponentHealthStatus(Server_StorageHealth, StatusWarning, msg)
	} else if worstStatus == StatusCritical {
		msg := "Storage usage is critical: "
		for i, m := range statusMessages {
			if i > 0 {
				msg += "; "
			}
			msg += m
		}
		SetComponentHealthStatus(Server_StorageHealth, StatusCritical, msg)
	}
}

// LaunchStorageHealthMonitor starts a goroutine that periodically checks filesystem
// storage consumption for configured paths and updates health status accordingly.
func LaunchStorageHealthMonitor(ctx context.Context, egrp *errgroup.Group) {
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
				checkStorageHealth()
			case <-ticker.C:
				checkStorageHealth()
			case <-ctx.Done():
				log.Info("Storage health monitor has been terminated")
				return nil
			}
		}
	})
}
