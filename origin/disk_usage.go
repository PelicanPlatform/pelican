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
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"

	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

var (
	// Prometheus metrics for disk usage
	PelicanOriginDiskUsageBytes = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_origin_disk_usage_bytes",
		Help: "Total disk usage in bytes for each origin export prefix",
	}, []string{"prefix"})

	PelicanOriginDiskUsageObjects = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_origin_disk_usage_objects",
		Help: "Total number of objects for each origin export prefix",
	}, []string{"prefix"})

	PelicanOriginDiskUsageCrawlDuration = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pelican_origin_disk_usage_crawl_duration_seconds",
		Help: "Duration of the last disk usage crawl in seconds",
	})

	PelicanOriginDiskUsageLastCrawlTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pelican_origin_disk_usage_last_crawl_timestamp",
		Help: "Unix timestamp of the last disk usage crawl",
	})

	// Health component for disk usage calculation
	Origin_DiskUsage metrics.HealthStatusComponent = "disk-usage"
)

// diskUsageResult stores the results of a disk usage calculation for one export
type diskUsageResult struct {
	prefix string
	bytes  uint64
	count  uint64
}

// tryGetCephXattr attempts to read Ceph extended attributes for fast recursive counting
// Returns (bytes, count, ok) where ok indicates if Ceph xattrs were found
func tryGetCephXattr(path string) (uint64, uint64, bool) {
	// Try to get ceph.dir.rbytes (recursive bytes)
	bytesData := make([]byte, 32)
	bytesSize, err := unix.Getxattr(path, "ceph.dir.rbytes", bytesData)
	if err != nil {
		log.Debugf("Failed to get ceph.dir.rbytes xattr for %s: %v", path, err)
		return 0, 0, false
	}

	// Try to get ceph.dir.rfiles (recursive file count)
	filesData := make([]byte, 32)
	filesSize, err := unix.Getxattr(path, "ceph.dir.rfiles", filesData)
	if err != nil {
		log.Debugf("Failed to get ceph.dir.rfiles xattr for %s: %v", path, err)
		return 0, 0, false
	}

	// Parse the values (they're stored as decimal strings)
	bytesStr := string(bytesData[:bytesSize])
	filesStr := string(filesData[:filesSize])

	bytes, err := strconv.ParseUint(bytesStr, 10, 64)
	if err != nil {
		log.Debugf("Failed to parse ceph.dir.rbytes value '%s': %v", bytesStr, err)
		return 0, 0, false
	}

	count, err := strconv.ParseUint(filesStr, 10, 64)
	if err != nil {
		log.Debugf("Failed to parse ceph.dir.rfiles value '%s': %v", filesStr, err)
		return 0, 0, false
	}

	log.Debugf("Successfully read Ceph xattrs for %s: %d bytes, %d files", path, bytes, count)
	return bytes, count, true
}

// calculateDiskUsagePOSIX calculates disk usage for a POSIX filesystem by walking the directory
func calculateDiskUsagePOSIX(ctx context.Context, storagePath string, limiter *rate.Limiter) (uint64, uint64, error) {
	var totalBytes uint64
	var totalCount uint64

	err := filepath.WalkDir(storagePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Log but don't fail on individual file errors
			log.Warnf("Error accessing %s: %v", path, err)
			return nil
		}

		// Check context for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Apply rate limiting
		if err := limiter.Wait(ctx); err != nil {
			return err
		}

		// Get file info
		info, err := d.Info()
		if err != nil {
			log.Warnf("Error getting info for %s: %v", path, err)
			return nil
		}

		// Only count regular files
		if info.Mode().IsRegular() {
			totalBytes += uint64(info.Size())
			totalCount++
		}

		return nil
	})

	return totalBytes, totalCount, err
}

// calculateDiskUsageForExport calculates disk usage for a single export
func calculateDiskUsageForExport(ctx context.Context, export server_utils.OriginExport, limiter *rate.Limiter) (diskUsageResult, error) {
	result := diskUsageResult{
		prefix: export.FederationPrefix,
	}

	storageType := param.Origin_StorageType.GetString()
	if storageType != string(server_structs.OriginStoragePosix) {
		// For non-POSIX backends, we would need to implement XRootD-based crawling
		// For now, skip non-POSIX backends
		log.Debugf("Skipping disk usage calculation for non-POSIX backend %s", storageType)
		return result, nil
	}

	storagePath := export.StoragePrefix
	log.Infof("Calculating disk usage for export %s (storage path: %s)", export.FederationPrefix, storagePath)

	// First, try Ceph xattrs for fast path
	if bytes, count, ok := tryGetCephXattr(storagePath); ok {
		log.Infof("Used Ceph xattrs for %s: %d bytes, %d objects", export.FederationPrefix, bytes, count)
		result.bytes = bytes
		result.count = count
		return result, nil
	}

	// Fall back to directory walk
	log.Debugf("Ceph xattrs not available, walking directory for %s", export.FederationPrefix)
	bytes, count, err := calculateDiskUsagePOSIX(ctx, storagePath, limiter)
	if err != nil {
		return result, errors.Wrapf(err, "failed to calculate disk usage for %s", export.FederationPrefix)
	}

	result.bytes = bytes
	result.count = count
	return result, nil
}

// calculateDiskUsage performs disk usage calculation for all exports
func calculateDiskUsage(ctx context.Context) error {
	startTime := time.Now()
	log.Info("Starting disk usage calculation for origin exports")

	// Get the configured rate limit (operations per second)
	rateLimit := param.Origin_DiskUsageCalculationRateLimit.GetInt()
	limiter := rate.NewLimiter(rate.Limit(rateLimit), rateLimit*2) // Burst is 2x the rate

	// Get all exports
	exports, err := server_utils.GetOriginExports()
	if err != nil {
		return errors.Wrap(err, "failed to get origin exports")
	}

	if len(exports) == 0 {
		log.Debug("No exports configured, skipping disk usage calculation")
		return nil
	}

	// Calculate usage for each export
	for _, export := range exports {
		result, err := calculateDiskUsageForExport(ctx, export, limiter)
		if err != nil {
			log.Errorf("Failed to calculate disk usage for export %s: %v", export.FederationPrefix, err)
			continue
		}

		// Update Prometheus metrics
		PelicanOriginDiskUsageBytes.WithLabelValues(result.prefix).Set(float64(result.bytes))
		PelicanOriginDiskUsageObjects.WithLabelValues(result.prefix).Set(float64(result.count))

		log.Infof("Disk usage for %s: %d bytes (%d MB), %d objects",
			result.prefix, result.bytes, result.bytes/(1024*1024), result.count)
	}

	duration := time.Since(startTime)
	PelicanOriginDiskUsageCrawlDuration.Set(duration.Seconds())
	PelicanOriginDiskUsageLastCrawlTimestamp.Set(float64(time.Now().Unix()))

	log.Infof("Disk usage calculation completed in %v", duration)

	// Update health status based on crawl time
	interval := param.Origin_DiskUsageCalculationInterval.GetDuration()
	percentTime := (duration.Seconds() / interval.Seconds()) * 100

	if percentTime > 30 {
		metrics.SetComponentHealthStatus(Origin_DiskUsage, metrics.StatusCritical,
			fmt.Sprintf("Disk usage crawl took %.1f%% of interval (%.1fs out of %.1fs)",
				percentTime, duration.Seconds(), interval.Seconds()))
	} else if percentTime > 10 {
		metrics.SetComponentHealthStatus(Origin_DiskUsage, metrics.StatusWarning,
			fmt.Sprintf("Disk usage crawl took %.1f%% of interval (%.1fs out of %.1fs)",
				percentTime, duration.Seconds(), interval.Seconds()))
	} else {
		metrics.SetComponentHealthStatus(Origin_DiskUsage, metrics.StatusOK,
			fmt.Sprintf("Disk usage crawl completed in %.1fs (%.1f%% of interval)",
				duration.Seconds(), percentTime))
	}

	return nil
}

// LaunchDiskUsageCalculator starts the periodic disk usage calculator
func LaunchDiskUsageCalculator(ctx context.Context, egrp *errgroup.Group) {
	if !param.Origin_EnableDiskUsageCalculation.GetBool() {
		log.Debug("Disk usage calculation is disabled")
		return
	}

	interval := param.Origin_DiskUsageCalculationInterval.GetDuration()
	log.Infof("Starting periodic disk usage calculator with interval %v", interval)

	// Set initial health status
	metrics.SetComponentHealthStatus(Origin_DiskUsage, metrics.StatusWarning, "Disk usage calculation initializing")

	egrp.Go(func() error {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// Run immediately on startup
		if err := calculateDiskUsage(ctx); err != nil {
			log.Errorf("Initial disk usage calculation failed: %v", err)
			metrics.SetComponentHealthStatus(Origin_DiskUsage, metrics.StatusCritical,
				fmt.Sprintf("Disk usage calculation failed: %v", err))
		}

		for {
			select {
			case <-ctx.Done():
				log.Info("Disk usage calculator shutting down")
				return nil
			case <-ticker.C:
				if err := calculateDiskUsage(ctx); err != nil {
					log.Errorf("Disk usage calculation failed: %v", err)
					metrics.SetComponentHealthStatus(Origin_DiskUsage, metrics.StatusCritical,
						fmt.Sprintf("Disk usage calculation failed: %v", err))
				}
			}
		}
	})
}
