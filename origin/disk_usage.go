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
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"github.com/pkg/xattr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
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

	PelicanOriginDiskUsageCrawlDuration = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_origin_disk_usage_crawl_duration_seconds_total",
		Help: "Total time spent calculating disk usage in seconds",
	})

	PelicanOriginDiskUsageLastCrawlTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pelican_origin_disk_usage_last_crawl_timestamp_seconds",
		Help: "Unix timestamp of the most recent disk usage crawl activity",
	})

	PelicanOriginDiskUsageCrawlErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_origin_disk_usage_crawl_errors_total",
		Help: "Total number of errors encountered during disk usage crawl",
	}, []string{"prefix"})

	// Health component for disk usage calculation
	OriginCache_DiskUsage metrics.HealthStatusComponent = "disk-usage"
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
	bytesData, err := xattr.Get(path, "ceph.dir.rbytes")
	if err != nil {
		log.Debugf("Failed to get ceph.dir.rbytes xattr for %s: %v", path, err)
		return 0, 0, false
	}

	// Try to get ceph.dir.rfiles (recursive file count)
	filesData, err := xattr.Get(path, "ceph.dir.rfiles")
	if err != nil {
		log.Debugf("Failed to get ceph.dir.rfiles xattr for %s: %v", path, err)
		return 0, 0, false
	}

	// Parse the values (they're stored as decimal strings)
	bytesStr := string(bytesData)
	filesStr := string(filesData)

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
		if limiter != nil {
			if err := limiter.Wait(ctx); err != nil {
				return err
			}
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

// calculateDiskUsagePelican calculates disk usage using the Pelican client FS interface
// This is used for non-POSIX backends (e.g. XRootD, S3, etc.) where we can't walk the local filesystem
func calculateDiskUsagePelican(ctx context.Context, export server_utils.OriginExport, limiter *rate.Limiter, tokenPath string) (uint64, uint64, error) {
	var totalBytes uint64
	var totalCount uint64

	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return 0, 0, errors.Wrap(err, "failed to get federation info for disk usage calculation")
	}

	if fedInfo.DiscoveryEndpoint == "" {
		return 0, 0, errors.New("federation discovery URL is not configured")
	}

	discoveryUrlStr := fedInfo.DiscoveryEndpoint
	discoveryUrl, err := url.Parse(discoveryUrlStr)
	if err != nil {
		return 0, 0, errors.Wrap(err, "failed to parse federation discovery URL")
	}
	// Use pelican:// scheme to ensure we use the Pelican client logic
	discoveryUrl.Scheme = "pelican"

	pfs := client.NewPelicanFSWithPrefix(ctx, discoveryUrl.String(), client.WithTokenLocation(tokenPath))

	err = fs.WalkDir(pfs, export.FederationPrefix, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			PelicanOriginDiskUsageCrawlErrors.WithLabelValues(export.FederationPrefix).Inc()
			log.Warnf("Error accessing %s: %v", path, err)
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if limiter != nil {
			if err := limiter.Wait(ctx); err != nil {
				return err
			}
		}

		if !d.IsDir() {
			info, err := d.Info()
			if err == nil {
				totalBytes += uint64(info.Size())
				totalCount++
			}
		}

		return nil
	})

	return totalBytes, totalCount, err
}

// calculateDiskUsageForExport calculates disk usage for a single export
func calculateDiskUsageForExport(ctx context.Context, export server_utils.OriginExport, limiter *rate.Limiter, tokenPath string, forcePelican bool) (diskUsageResult, error) {
	result := diskUsageResult{
		prefix: export.FederationPrefix,
	}

	storageType := param.Origin_StorageType.GetString()
	if forcePelican || storageType != string(server_structs.OriginStoragePosix) {
		log.Debugf("Using PelicanFS for disk usage calculation of backend %s", storageType)
		bytes, count, err := calculateDiskUsagePelican(ctx, export, limiter, tokenPath)
		if err != nil {
			return result, errors.Wrapf(err, "failed to calculate disk usage for %s via PelicanFS", export.FederationPrefix)
		}
		result.bytes = bytes
		result.count = count
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

// CalculateDiskUsage performs disk usage calculation for all exports
func CalculateDiskUsage(ctx context.Context, forcePelican bool) error {
	// Save the last crawl timestamp to the database AT START to prevent repeated crashes
	if database.ServerDatabase != nil {
		err := database.CreateOrUpdateCounter("origin_last_disk_usage_crawl", int(time.Now().Unix()))
		if err != nil {
			log.Warningf("Failed to update last disk usage crawl timestamp in database: %v", err)
		}
	}

	// Use an errgroup to manage background goroutines (metrics updater, token refresher)
	var egrp errgroup.Group
	// Create a cancelable context to ensure background tasks stop when we return
	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		_ = egrp.Wait()
	}()

	// Setup disk usage token if needed (for non-POSIX backends or forced PelicanFS)
	storageType := param.Origin_StorageType.GetString()
	usePelican := forcePelican || storageType != string(server_structs.OriginStoragePosix)

	var tokenPath string
	if usePelican {
		var err error
		tokenPath, err = setupDiskUsageToken(ctx, &egrp)
		if err != nil {
			return errors.Wrap(err, "failed to setup disk usage token")
		}
	}

	startTime := time.Now()
	log.Info("Starting disk usage calculation for origin exports")

	// Update duration metric and last crawl timestamp periodically while running
	done := make(chan struct{})
	defer close(done)
	egrp.Go(func() error {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		lastTick := startTime
		for {
			select {
			case <-done:
				now := time.Now()
				PelicanOriginDiskUsageCrawlDuration.Add(now.Sub(lastTick).Seconds())
				PelicanOriginDiskUsageLastCrawlTimestamp.Set(float64(now.Unix()))
				return nil
			case now := <-ticker.C:
				PelicanOriginDiskUsageCrawlDuration.Add(now.Sub(lastTick).Seconds())
				PelicanOriginDiskUsageLastCrawlTimestamp.Set(float64(now.Unix()))
				lastTick = now
			}
		}
	})

	// Get the configured rate limit (operations per second)
	rateLimit := param.Origin_DiskUsageCalculationRateLimit.GetInt()
	var limiter *rate.Limiter
	if rateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(rateLimit), rateLimit*2) // Burst is 2x the rate
	}

	// Get all exports
	exports, err := server_utils.GetOriginExports()
	if err != nil {
		return errors.Wrap(err, "failed to get origin exports")
	}

	var collections []database.Collection
	if database.ServerDatabase != nil {
		collections, err = database.GetAllCollections(database.ServerDatabase)
		if err != nil {
			log.Warningf("Failed to get collections for disk usage: %v", err)
		}
	}

	if len(exports) == 0 && len(collections) == 0 {
		log.Debug("No exports or collections configured, skipping disk usage calculation")
		return nil
	}

	// Helper to process an item
	processItem := func(export server_utils.OriginExport, forceCtxPelican bool) {
		result, err := calculateDiskUsageForExport(ctx, export, limiter, tokenPath, forceCtxPelican)
		if err != nil {
			log.Errorf("Failed to calculate disk usage for prefix %s: %v", export.FederationPrefix, err)
			return
		}

		// Update Prometheus metrics
		PelicanOriginDiskUsageBytes.WithLabelValues(result.prefix).Set(float64(result.bytes))
		PelicanOriginDiskUsageObjects.WithLabelValues(result.prefix).Set(float64(result.count))

		log.Infof("Disk usage for %s: %d bytes (%d MB), %d objects",
			result.prefix, result.bytes, result.bytes/(1024*1024), result.count)
	}

	// Track processed prefixes to avoid duplicates
	processedPrefixes := make(map[string]bool)

	// Calculate usage for each export
	for _, export := range exports {
		processItem(export, forcePelican)
		processedPrefixes[export.FederationPrefix] = true
	}

	// Calculate usage for each collection
	for _, col := range collections {
		if _, ok := processedPrefixes[col.Namespace]; ok {
			continue
		}

		export := server_utils.OriginExport{
			FederationPrefix: col.Namespace,
		}
		// Collections always use Pelican FS as they are virtual
		processItem(export, true)
		processedPrefixes[col.Namespace] = true
	}

	duration := time.Since(startTime)

	log.Infof("Disk usage calculation completed in %v", duration)

	// Update health status based on crawl time
	interval := param.Origin_DiskUsageCalculationInterval.GetDuration()
	percentTime := (duration.Seconds() / interval.Seconds()) * 100

	if percentTime > 30 {
		metrics.SetComponentHealthStatus(OriginCache_DiskUsage, metrics.StatusCritical,
			fmt.Sprintf("Disk usage crawl took %.1f%% of interval (%.1fs out of %.1fs)",
				percentTime, duration.Seconds(), interval.Seconds()))
	} else if percentTime > 10 {
		metrics.SetComponentHealthStatus(OriginCache_DiskUsage, metrics.StatusWarning,
			fmt.Sprintf("Disk usage crawl took %.1f%% of interval (%.1fs out of %.1fs)",
				percentTime, duration.Seconds(), interval.Seconds()))
	} else {
		metrics.SetComponentHealthStatus(OriginCache_DiskUsage, metrics.StatusOK,
			fmt.Sprintf("Disk usage crawl completed in %.1fs (%.1f%% of interval)",
				duration.Seconds(), percentTime))
	}

	return nil
}

// setupDiskUsageToken creates a temporary token file and starts a refresher
func setupDiskUsageToken(ctx context.Context, egrp *errgroup.Group) (string, error) {
	// Create a temp file for the token
	f, err := os.CreateTemp("", "pelican-disk-usage-token-*")
	if err != nil {
		return "", errors.Wrap(err, "failed to create temp token file")
	}
	f.Close()
	tokenPath := f.Name()

	// Function to generate and write token
	updateToken := func() error {
		tokenConfig := token.NewWLCGToken()
		tokenConfig.Lifetime = 30 * time.Minute
		tokenConfig.Subject = "origin-disk-usage"
		tokenConfig.AddAudienceAny()
		tokenConfig.AddRawScope("storage.read:/")

		tc, err := tokenConfig.CreateToken()
		if err != nil {
			return errors.Wrap(err, "failed to create disk usage token")
		}

		// Write to temp file first
		tmpFile, err := os.CreateTemp(filepath.Dir(tokenPath), "token-update-*")
		if err != nil {
			return errors.Wrap(err, "failed to create temp file for token update")
		}

		tmpName := tmpFile.Name()
		defer os.Remove(tmpName)

		if _, err := tmpFile.WriteString(tc); err != nil {
			tmpFile.Close()
			return errors.Wrap(err, "failed to write token to temp file")
		}
		tmpFile.Close()

		// Atomic rename
		if err := os.Rename(tmpName, tokenPath); err != nil {
			return errors.Wrap(err, "failed to rename token file")
		}
		return nil
	}

	// Initial token
	if err := updateToken(); err != nil {
		os.Remove(tokenPath)
		return "", err
	}

	// Start refresher
	egrp.Go(func() error {
		ticker := time.NewTicker(20 * time.Minute)
		defer ticker.Stop()
		defer os.Remove(tokenPath)

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				if err := updateToken(); err != nil {
					log.Errorf("Failed to update disk usage token: %v", err)
				}
			}
		}
	})

	return tokenPath, nil
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
	metrics.SetComponentHealthStatus(OriginCache_DiskUsage, metrics.StatusWarning, "Disk usage calculation initializing")

	egrp.Go(func() error {
		// Wait before first crawl to allow system to stabilize
		initialDelay := param.Origin_DiskUsageCalculationDelay.GetDuration()
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(initialDelay):
		}

		// Check database to see if we need to delay the first run further
		var delay time.Duration
		if database.ServerDatabase != nil {
			var counter database.Counter
			if err := database.ServerDatabase.First(&counter, "key = ?", "origin_last_disk_usage_crawl").Error; err == nil {
				lastCrawlTime := time.Unix(int64(counter.Value), 0)
				timeSinceLast := time.Since(lastCrawlTime)
				if timeSinceLast < interval {
					delay = time.Until(lastCrawlTime.Add(interval))
					log.Infof("Last disk usage crawl was %v ago; waiting %v before next crawl to maintain %v interval",
						timeSinceLast.Round(time.Second), delay.Round(time.Second), interval)
				}
			}
		}

		if delay > 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(delay):
			}
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// Run immediately (after delays)
		if err := CalculateDiskUsage(ctx, false); err != nil {
			log.Errorf("Initial disk usage calculation failed: %v", err)
			metrics.SetComponentHealthStatus(OriginCache_DiskUsage, metrics.StatusCritical,
				fmt.Sprintf("Disk usage calculation failed: %v", err))
		}

		for {
			select {
			case <-ctx.Done():
				log.Info("Disk usage calculator shutting down")
				return nil
			case <-ticker.C:
				if err := CalculateDiskUsage(ctx, false); err != nil {
					log.Errorf("Disk usage calculation failed: %v", err)
					metrics.SetComponentHealthStatus(OriginCache_DiskUsage, metrics.StatusCritical,
						fmt.Sprintf("Disk usage calculation failed: %v", err))
				}
			}
		}
	})
}
