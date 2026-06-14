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
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/htb"
	"github.com/pelicanplatform/pelican/metrics"
)

// autoCreateDirFs wraps an afero.Fs to automatically create parent directories
// when opening a file for writing
type autoCreateDirFs struct {
	afero.Fs
}

// newAutoCreateDirFs creates a new filesystem that auto-creates parent directories
func newAutoCreateDirFs(fs afero.Fs) afero.Fs {
	return &autoCreateDirFs{Fs: fs}
}

// OpenFile wraps the underlying OpenFile and auto-creates parent directories if needed
func (fs *autoCreateDirFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	file, err := fs.Fs.OpenFile(name, flag, perm)

	// If opening for write failed with "no such file or directory", create parent dirs and retry
	if err != nil && os.IsNotExist(err) && (flag&os.O_CREATE != 0 || flag&os.O_WRONLY != 0 || flag&os.O_RDWR != 0) {
		dir := filepath.Dir(name)
		if dir != "" && dir != "." && dir != "/" {
			if mkdirErr := fs.Fs.MkdirAll(dir, 0755); mkdirErr == nil {
				// Retry opening the file after creating parent directories
				file, err = fs.Fs.OpenFile(name, flag, perm)
			}
		}
	}

	return file, err
}

type (
	// contextKey is used to store user/group info in the context
	contextKey int

	// userInfo contains information about the authenticated user
	userInfo struct {
		User   string
		Groups []string
	}
)

const (
	userInfoKey contextKey = iota
)

// setUserInfo stores user info in context
func setUserInfo(ctx context.Context, ui *userInfo) context.Context {
	return context.WithValue(ctx, userInfoKey, ui)
}

// getUserInfo retrieves user info from context
func getUserInfo(ctx context.Context) *userInfo {
	ui, ok := ctx.Value(userInfoKey).(*userInfo)
	if !ok {
		return nil
	}
	return ui
}

// usernameFromContext extracts the authenticated username from the context.
// Returns an empty string when no user information is present.
func usernameFromContext(ctx context.Context) string {
	if ui := getUserInfo(ctx); ui != nil && ui.User != "" {
		return ui.User
	}
	return ""
}

// operationMetrics holds the unified metrics for tracking a filesystem operation.
type operationMetrics struct {
	total         *prometheus.CounterVec
	timeHistogram *prometheus.HistogramVec
	slowTotal     *prometheus.CounterVec
	slowHistogram *prometheus.HistogramVec
}

// trackOperation returns a cleanup function that records metrics for a filesystem operation.
// It captures the start time when called and records elapsed duration when the
// returned cleanup function runs.  All metrics use the unified pelican_storage_*
// namespace with backend="posixv2" label.
//
// Usage:
//
//	defer trackOperation(opMetrics, username)()
func trackOperation(om operationMetrics, username string) func() {
	start := time.Now()

	// Increment operation counter
	if om.total != nil {
		om.total.WithLabelValues(metrics.BackendPOSIXv2, username).Inc()
	}

	return func() {
		elapsed := time.Since(start)
		elapsedSec := elapsed.Seconds()

		// Record operation timing
		if om.timeHistogram != nil {
			om.timeHistogram.WithLabelValues(metrics.BackendPOSIXv2, username).Observe(elapsedSec)
		}

		// Track slow operations (>2s)
		if elapsed >= metrics.SlowOperationThreshold {
			if om.slowTotal != nil {
				om.slowTotal.WithLabelValues(metrics.BackendPOSIXv2, username).Inc()
			}
			if om.slowHistogram != nil {
				om.slowHistogram.WithLabelValues(metrics.BackendPOSIXv2, username).Observe(elapsedSec)
			}
		}
	}
}

// aferoFileSystem wraps an afero.Fs to implement webdav.FileSystem
type aferoFileSystem struct {
	fs          afero.Fs
	prefix      string
	logger      func(*http.Request, error)
	rateLimiter *htb.HTB // Optional rate limiter for IO operations

	// obs is the per-export object-metadata observation config.
	// nil when TrackAccess is off for this namespace. When set,
	// Stat / RemoveAll / Rename consult it on every call to keep
	// the local DB in sync with backend reality.
	obs *observationConfig
}

// newAferoFileSystem creates a new aferoFileSystem
func newAferoFileSystem(fs afero.Fs, prefix string, logger func(*http.Request, error)) *aferoFileSystem {
	return &aferoFileSystem{
		fs:     fs,
		prefix: prefix,
		logger: logger,
	}
}

// setObservation installs the object-metadata observation hooks.
// Called by InitializeHandlers when TrackAccess is on for the
// namespace; nil-tolerant.
func (afs *aferoFileSystem) setObservation(obs *observationConfig) {
	afs.obs = obs
}

// newAferoFileSystemWithRateLimiter creates a new aferoFileSystem with rate limiting
func newAferoFileSystemWithRateLimiter(fs afero.Fs, prefix string, logger func(*http.Request, error), rateLimiter *htb.HTB) *aferoFileSystem {
	return &aferoFileSystem{
		fs:          fs,
		prefix:      prefix,
		logger:      logger,
		rateLimiter: rateLimiter,
	}
}

// Mkdir implements webdav.FileSystem
func (afs *aferoFileSystem) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	defer trackOperation(operationMetrics{
		total:         metrics.StorageMkdirsTotal,
		timeHistogram: metrics.StorageMkdirTime,
		slowTotal:     metrics.StorageSlowMkdirsTotal,
		slowHistogram: metrics.StorageSlowMkdirTime,
	}, usernameFromContext(ctx))()

	fullPath := afs.fullPath(name)
	// Use webdav logger if available
	return afs.fs.MkdirAll(fullPath, perm)
}

// OpenFile implements webdav.FileSystem
func (afs *aferoFileSystem) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	fullPath := afs.fullPath(name)
	username := usernameFromContext(ctx)
	if afs.logger != nil {
		afs.logger(nil, nil) // Use the logger provided by webdav
	}

	// Track open operation metrics — the deferred closure captures the
	// start time now and records elapsed duration when OpenFile returns.
	defer trackOperation(operationMetrics{
		total:         metrics.StorageOpensTotal,
		timeHistogram: metrics.StorageOpenTime,
		slowTotal:     metrics.StorageSlowOpensTotal,
		slowHistogram: metrics.StorageSlowOpenTime,
	}, username)()

	// WORKAROUND: When attempting to upload a file to a path that is actually a directory/collection,
	// the underlying filesystem will correctly return EISDIR (syscall.EISDIR on Unix).
	// However, the golang.org/x/net/webdav handler has the following error handling logic:
	//
	//   if os.IsNotExist(err) {
	//       return http.StatusConflict, err  // 409
	//   }
	//   return http.StatusNotFound, err      // 404
	//
	// This means EISDIR gets mapped to 404 Not Found instead of 409 Conflict, which is incorrect
	// per WebDAV RFC 4918. When a client attempts to PUT a file to a URL that represents a collection,
	// the server should return 409 Conflict, not 404 Not Found.
	//
	// To work around this handler limitation, we check if the target is a directory before attempting
	// to open it with write flags (O_WRONLY, O_RDWR, O_CREATE, O_TRUNC). If so, we return an error
	// that satisfies os.IsNotExist() so the handler returns the correct 409 status code.
	//
	// This is semantically incorrect (the directory DOES exist), but necessary because the webdav
	// handler doesn't distinguish between "path doesn't exist" and "path is wrong type" errors.
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC) != 0 {
		info, statErr := afs.fs.Stat(fullPath)
		if statErr == nil && info.IsDir() {
			// Return a "not exist" error instead of "is a directory" error to trigger
			// the webdav handler's 409 Conflict response instead of 404 Not Found
			return nil, os.ErrNotExist
		}
	}

	file, err := afs.fs.OpenFile(fullPath, flag, perm)
	if err != nil {
		if flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC) != 0 {
			metrics.StorageOpenErrorsTotal.WithLabelValues(metrics.BackendPOSIXv2, username).Inc()
		}
		return nil, err
	}

	// Extract username from context for rate limiting
	userID := "unauthenticated"
	if afs.rateLimiter != nil {
		// Try to get user info from context
		if ui := getUserInfo(ctx); ui != nil && ui.User != "" {
			userID = ui.User
		}
		// Try to get issuer from context and append to make unique per-issuer
		if issuer, ok := ctx.Value(issuerContextKey{}).(string); ok && issuer != "" {
			userID = fmt.Sprintf("%s@%s", userID, issuer)
		}
	}

	// Wrap the file with metrics tracking
	metricsWrappedFile := newMetricsFile(file, afs.rateLimiter, userID, username, ctx)

	return &aferoFile{
		File:        metricsWrappedFile,
		fs:          afs.fs,
		name:        fullPath,
		logger:      afs.logger,
		rateLimiter: afs.rateLimiter,
		userID:      userID,
		ctx:         ctx,
	}, nil
}

// RemoveAll implements webdav.FileSystem. On success against a
// TrackAccess-enabled namespace, fires RecordDelete (durable) so the
// soft-delete + history snapshot lands.
func (afs *aferoFileSystem) RemoveAll(ctx context.Context, name string) error {
	defer trackOperation(operationMetrics{
		total:         metrics.StorageUnlinksTotal,
		timeHistogram: metrics.StorageUnlinkTime,
		slowTotal:     metrics.StorageSlowUnlinksTotal,
		slowHistogram: metrics.StorageSlowUnlinkTime,
	}, usernameFromContext(ctx))()

	fullPath := afs.fullPath(name)
	if err := afs.fs.RemoveAll(fullPath); err != nil {
		return err
	}
	if afs.obs != nil {
		fedPath := joinFederationPath(afs.obs.namespace, name)
		afs.obs.cache.Invalidate(afs.obs.namespace, fedPath)
		// RecordDelete reads the live row inside the DAO; if no
		// row exists, it's a silent no-op (we never saw the path
		// before).
		if recErr := afs.obs.dao.RecordDelete(ctx, ObjectMetadataEventInput{
			Namespace:  afs.obs.namespace,
			ObjectPath: fedPath,
			Actor:      usernameFromContext(ctx),
		}); recErr != nil {
			log.Debugf("object-metadata: RecordDelete(%s,%s) failed: %v", afs.obs.namespace, fedPath, recErr)
		}
	}
	return nil
}

// Rename implements webdav.FileSystem. On success against a
// TrackAccess-enabled namespace, fires RecordRename (durable) and
// invalidates both the old and new cache entries.
func (afs *aferoFileSystem) Rename(ctx context.Context, oldName, newName string) error {
	defer trackOperation(operationMetrics{
		total:         metrics.StorageRenamesTotal,
		timeHistogram: metrics.StorageRenameTime,
		slowTotal:     metrics.StorageSlowRenamesTotal,
		slowHistogram: metrics.StorageSlowRenameTime,
	}, usernameFromContext(ctx))()

	oldPath := afs.fullPath(oldName)
	newPath := afs.fullPath(newName)
	if err := afs.fs.Rename(oldPath, newPath); err != nil {
		return err
	}
	if afs.obs != nil {
		oldFed := joinFederationPath(afs.obs.namespace, oldName)
		newFed := joinFederationPath(afs.obs.namespace, newName)
		afs.obs.cache.Invalidate(afs.obs.namespace, oldFed)
		afs.obs.cache.Invalidate(afs.obs.namespace, newFed)
		if recErr := afs.obs.dao.RecordRename(ctx, afs.obs.namespace, oldFed, afs.obs.namespace, newFed, usernameFromContext(ctx)); recErr != nil {
			log.Debugf("object-metadata: RecordRename(%s, %s→%s) failed: %v", afs.obs.namespace, oldFed, newFed, recErr)
		}
	}
	return nil
}

// Stat implements webdav.FileSystem.
//
// The returned FileInfo is wrapped by withBackendETag so the metadata
// publish path can ask it for an ETag without baking a particular
// convention into the publisher. See backend_etag.go.
//
// When object-metadata observation is enabled for this namespace AND
// the request context is *not* in listing mode (PROPFIND Depth>=1),
// the call also drives change-detection: cache lookup → live-row
// LookupLive → enqueue external_observe / external_modify /
// external_delete via the write-behind batcher. Listing-mode skips
// the entire observation ladder to keep PROPFIND of a large cold
// directory as cheap as today.
func (afs *aferoFileSystem) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	defer trackOperation(operationMetrics{
		total:         metrics.StorageStatsTotal,
		timeHistogram: metrics.StorageStatTime,
		slowTotal:     metrics.StorageSlowStatsTotal,
		slowHistogram: metrics.StorageSlowStatTime,
	}, usernameFromContext(ctx))()

	fullPath := afs.fullPath(name)
	info, err := afs.fs.Stat(fullPath)
	if err != nil {
		// ENOENT may indicate an external_delete; let observation
		// decide. Skipped for listing mode (and when observation
		// is off for the namespace).
		if afs.obs != nil && !isListingMode(ctx) && os.IsNotExist(err) {
			afs.obs.handleENOENT(ctx, joinFederationPath(afs.obs.namespace, name))
		}
		return nil, err
	}
	wrapped := withBackendETag(info)
	if afs.obs != nil && !isListingMode(ctx) {
		afs.obs.handleStatSuccess(ctx, joinFederationPath(afs.obs.namespace, name), wrapped)
	}
	return wrapped, nil
}

// fullPath converts a webdav path to a full filesystem path
func (afs *aferoFileSystem) fullPath(name string) string {
	if afs.prefix == "" {
		return name
	}
	return path.Join(afs.prefix, name)
}

// aferoFile wraps an afero.File to implement webdav.File
type aferoFile struct {
	afero.File
	fs          afero.Fs
	name        string
	dirEntries  []os.FileInfo              // Cached directory entries for pagination
	dirOffset   int                        // Current offset in directory entries
	dirMutex    sync.Mutex                 // Mutex for concurrent access
	logger      func(*http.Request, error) // WebDAV logger
	rateLimiter *htb.HTB                   // Optional rate limiter
	userID      string                     // User ID for rate limiting
	ctx         context.Context            // Context from OpenFile for rate limiting
}

// Readdir implements webdav.File
func (af *aferoFile) Readdir(count int) ([]os.FileInfo, error) {
	af.dirMutex.Lock()
	defer af.dirMutex.Unlock()

	// On first call or when count <= 0, read all entries
	if af.dirEntries == nil {
		entries, err := afero.ReadDir(af.fs, af.name)
		if err != nil {
			return nil, err
		}
		af.dirEntries = entries
		af.dirOffset = 0
	}

	// If count <= 0, return all remaining entries and reset
	if count <= 0 {
		result := af.dirEntries[af.dirOffset:]
		af.dirOffset = len(af.dirEntries)
		return result, nil
	}

	// Return up to count entries from current offset
	remaining := len(af.dirEntries) - af.dirOffset
	if remaining == 0 {
		// No more entries, return io.EOF
		return nil, io.EOF
	}

	if count > remaining {
		count = remaining
	}

	result := af.dirEntries[af.dirOffset : af.dirOffset+count]
	af.dirOffset += count

	return result, nil
}

// Stat implements webdav.File. Wraps with a backend-aware ETag (see
// aferoFileSystem.Stat).
func (af *aferoFile) Stat() (os.FileInfo, error) {
	info, err := af.File.Stat()
	if err != nil {
		return nil, err
	}
	return withBackendETag(info), nil
}
