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
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/htb"
	"github.com/pelicanplatform/pelican/metrics"
)

// SizeHintFs is optionally implemented by an afero.Fs whose write path can do
// better when the object's final size is known up front.
//
// afero.Fs has no context and no size argument, so a backend that would
// benefit -- pstore picks its storage tier from the size, and buffers to
// discover it otherwise -- cannot see the Content-Length the handler already
// has. This carries it across that gap.
//
// A size of -1 means unknown, which is what a chunked-encoding PUT gives.
type SizeHintFs interface {
	OpenFileSized(name string, flag int, perm os.FileMode, size int64) (afero.File, error)
}

// ConditionalWriteFs is optionally implemented by an afero.Fs that can enforce
// an HTTP conditional-write precondition (RFC 9110 §13.1) atomically, at the
// moment the new version is installed.
//
// checkPutPreconditions evaluates If-Match / If-None-Match before the write
// begins, which is inherently a stat-then-write race: two concurrent
// "If-None-Match: *" PUTs both observe an absent object and both commit. A
// backend that can re-check the condition inside its commit transaction --
// pstore does -- closes that race, so the handler hands the parsed condition
// down here rather than keeping it to itself.
//
// The condition is expressed with plain scalars rather than a shared struct so
// that a backend package does not have to import origin_serve to implement it.
// requireAbsent is "If-None-Match: *"; requireETag is a single-tag "If-Match",
// carrying the entity tag exactly as the client sent it (the backend, which
// minted it, is the only layer that knows how to interpret it). size is the
// Content-Length hint, or -1 when unknown, matching SizeHintFs.
type ConditionalWriteFs interface {
	OpenFileConditional(name string, flag int, perm os.FileMode, size int64,
		requireAbsent bool, requireETag string) (afero.File, error)
}

// writeCondition is a parsed conditional-write precondition on its way from
// the PUT handler to a ConditionalWriteFs.
type writeCondition struct {
	// requireAbsent demands the object not exist (If-None-Match: *).
	requireAbsent bool
	// requireETag demands the object still carry this entity tag (If-Match
	// with exactly one tag; a list or "*" cannot be expressed).
	requireETag string
}

// isSet reports whether anything needs to be enforced at commit.
func (wc writeCondition) isSet() bool {
	return wc.requireAbsent || wc.requireETag != ""
}

type writeConditionKey struct{}

// contextWithWriteCondition carries a precondition down to the filesystem.
//
// afero.Fs has neither a context nor a place for this, so it travels the same
// way the content-length hint does (see ContextWithContentLength): the WebDAV
// handler passes the request context straight to FileSystem.OpenFile.
func contextWithWriteCondition(ctx context.Context, cond writeCondition) context.Context {
	return context.WithValue(ctx, writeConditionKey{}, cond)
}

// writeConditionFromCtx returns the precondition attached to ctx, if any.
func writeConditionFromCtx(ctx context.Context) (writeCondition, bool) {
	cond, ok := ctx.Value(writeConditionKey{}).(writeCondition)
	return cond, ok && cond.isSet()
}

// writeAborter is implemented by a backend file whose Close would otherwise
// commit whatever bytes happened to arrive.
//
// golang.org/x/net/webdav's handlePut calls f.Close() before it looks at the
// error from io.Copy, so a client that disconnects halfway through an
// overwrite has its truncated body committed over the previous version. A
// backend that builds a new version and swaps it in at Close -- pstore -- can
// discard it instead, but only if it is told the write failed before Close
// runs.
type writeAborter interface {
	// AbortWrite records that the data written so far is incomplete, so that
	// Close discards the pending version rather than installing it.
	AbortWrite(err error)
}

// writeGuard connects a failed request-body read to the open backend file.
//
// The failure is observed by the handler (reading r.Body) and has to be acted
// on by the filesystem (closing the file), and neither has a reference to the
// other: webdav.handlePut opens the file itself, from a context the handler
// supplied. The guard is that reference, planted in the context on the way
// down and populated by aferoFileSystem.OpenFile on the way back.
type writeGuard struct {
	mu   sync.Mutex
	file writeAborter
	err  error
}

// register records the file a PUT is writing to. A failure that arrived before
// the file was opened is applied immediately, so the two orderings agree.
func (g *writeGuard) register(f afero.File) {
	aborter, ok := f.(writeAborter)
	if !ok {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.file = aborter
	if g.err != nil {
		aborter.AbortWrite(g.err)
	}
}

// fail marks the write as incomplete.
func (g *writeGuard) fail(err error) {
	if err == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.err == nil {
		g.err = err
	}
	if g.file != nil {
		g.file.AbortWrite(err)
	}
}

// failed reports whether the body read failed.
func (g *writeGuard) failed() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.err
}

type writeGuardKey struct{}

// contextWithWriteGuard attaches a guard so the filesystem can register the
// file it opens for this request.
func contextWithWriteGuard(ctx context.Context, g *writeGuard) context.Context {
	return context.WithValue(ctx, writeGuardKey{}, g)
}

// writeGuardFromCtx returns the guard attached to ctx, if any.
func writeGuardFromCtx(ctx context.Context) *writeGuard {
	g, _ := ctx.Value(writeGuardKey{}).(*writeGuard)
	return g
}

// guardedBody records a request-body read failure on the guard, so that the
// file the body was being copied into is discarded rather than committed.
type guardedBody struct {
	io.ReadCloser
	guard *writeGuard
}

func (b *guardedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && err != io.EOF {
		b.guard.fail(err)
	}
	return n, err
}

// autoCreateDirFs wraps an afero.Fs to automatically create parent directories
// when opening a file for writing
type autoCreateDirFs struct {
	afero.Fs
}

// OpenFileSized forwards the size hint to the wrapped filesystem, creating
// parent directories on the same terms as OpenFile.
//
// Without this the wrapper would silently swallow the hint for every backend
// it wraps, since a type assertion against autoCreateDirFs would fail.
func (fs *autoCreateDirFs) OpenFileSized(name string, flag int, perm os.FileMode, size int64) (afero.File, error) {
	inner, ok := fs.Fs.(SizeHintFs)
	if !ok {
		return fs.OpenFile(name, flag, perm)
	}

	file, err := inner.OpenFileSized(name, flag, perm, size)
	if err != nil && os.IsNotExist(err) && (flag&os.O_CREATE != 0 || flag&os.O_WRONLY != 0 || flag&os.O_RDWR != 0) {
		dir := filepath.Dir(name)
		if dir != "" && dir != "." && dir != "/" {
			if mkdirErr := fs.Fs.MkdirAll(dir, 0755); mkdirErr == nil {
				file, err = inner.OpenFileSized(name, flag, perm, size)
			}
		}
	}
	return file, err
}

// OpenFileConditional forwards a conditional write, creating parent
// directories on the same terms as OpenFile.
//
// As with OpenFileSized, the wrapper has to forward explicitly: a type
// assertion against autoCreateDirFs would fail and the condition would be
// silently dropped, which is the one outcome a conditional write must never
// have.
func (fs *autoCreateDirFs) OpenFileConditional(name string, flag int, perm os.FileMode, size int64,
	requireAbsent bool, requireETag string) (afero.File, error) {
	inner, ok := fs.Fs.(ConditionalWriteFs)
	if !ok {
		if size >= 0 {
			return fs.OpenFileSized(name, flag, perm, size)
		}
		return fs.OpenFile(name, flag, perm)
	}

	open := func() (afero.File, error) {
		return inner.OpenFileConditional(name, flag, perm, size, requireAbsent, requireETag)
	}
	file, err := open()
	if err != nil && os.IsNotExist(err) && (flag&os.O_CREATE != 0 || flag&os.O_WRONLY != 0 || flag&os.O_RDWR != 0) {
		dir := filepath.Dir(name)
		if dir != "" && dir != "." && dir != "/" {
			if mkdirErr := fs.Fs.MkdirAll(dir, 0755); mkdirErr == nil {
				file, err = open()
			}
		}
	}
	return file, err
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

	fullPath, err := afs.fullPath(name)
	if err != nil {
		return err
	}
	// Use webdav logger if available
	return afs.fs.MkdirAll(fullPath, perm)
}

// OpenFile implements webdav.FileSystem
func (afs *aferoFileSystem) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	fullPath, pathErr := afs.fullPath(name)
	if pathErr != nil {
		return nil, pathErr
	}
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

	// Hand the backend the expected size when the handler knows it and the
	// filesystem can use it, and the conditional-write precondition when the
	// handler parsed one.  Everything else behaves exactly as before.
	file, err := afs.openBacking(ctx, fullPath, flag, perm)
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

	// Let a failed request body reach this file, so a PUT that dies mid-stream
	// is discarded instead of being committed by webdav's unconditional
	// f.Close().  The raw backend file is registered rather than a wrapper:
	// the wrappers below are this package's and know nothing about aborting.
	if guard := writeGuardFromCtx(ctx); guard != nil {
		guard.register(file)
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
		obs:         afs.obs,
		webdavName:  name,
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

	fullPath, err := afs.fullPath(name)
	if err != nil {
		return err
	}
	if err := afs.fs.RemoveAll(fullPath); err != nil {
		return err
	}
	// POSC-internal removals (reaped stale temp files, transactional
	// rollback of a refused commit) must not be observed: they are not
	// real object deletions and must not emit object.deleted.
	if afs.obs != nil && !isPoscInternal(ctx) {
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
		// Publish an object.deleted webhook (best-effort, async) when enabled.
		if afs.obs.onDelete != nil {
			afs.obs.onDelete(ctx, fedPath)
		}
	}
	return nil
}

// openBacking opens the underlying file, using the richest interface the
// backend implements: a conditional write when the request carried a
// precondition, a size-hinted write when the handler knows the length, and a
// plain OpenFile otherwise.
func (afs *aferoFileSystem) openBacking(ctx context.Context, fullPath string, flag int, perm os.FileMode) (afero.File, error) {
	hint := contentLengthFromCtx(ctx)

	if cond, ok := writeConditionFromCtx(ctx); ok {
		if conditional, can := afs.fs.(ConditionalWriteFs); can {
			return conditional.OpenFileConditional(fullPath, flag, perm, hint,
				cond.requireAbsent, cond.requireETag)
		}
		// The backend cannot enforce the condition at commit; the handler's
		// early check already rejected the common case, and there is nothing
		// further this layer can do.
	}

	if sized, ok := afs.fs.(SizeHintFs); ok && hint >= 0 {
		return sized.OpenFileSized(fullPath, flag, perm, hint)
	}
	return afs.fs.OpenFile(fullPath, flag, perm)
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

	oldPath, err := afs.fullPath(oldName)
	if err != nil {
		return err
	}
	newPath, err := afs.fullPath(newName)
	if err != nil {
		return err
	}
	if err := afs.fs.Rename(oldPath, newPath); err != nil {
		return err
	}
	// The POSC temp→final rename is internal plumbing, not a user MOVE;
	// the commit is recorded by the close hook, so skip observation here.
	if afs.obs != nil && !isPoscInternal(ctx) {
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

	fullPath, err := afs.fullPath(name)
	if err != nil {
		return nil, err
	}
	info, err := afs.fs.Stat(fullPath)
	if err != nil {
		// ENOENT may indicate an external_delete; let observation
		// decide. Skipped for listing mode (and when observation
		// is off for the namespace).
		if afs.obs != nil && !isListingMode(ctx) && !isPoscInternal(ctx) && os.IsNotExist(err) {
			afs.obs.handleENOENT(ctx, joinFederationPath(afs.obs.namespace, name))
		}
		return nil, err
	}
	wrapped := withBackendETag(info)
	if afs.obs != nil && !isListingMode(ctx) && !isPoscInternal(ctx) {
		afs.obs.handleStatSuccess(ctx, joinFederationPath(afs.obs.namespace, name), wrapped)
	}
	return wrapped, nil
}

// fullPath converts a WebDAV path to a full filesystem path, refusing any that
// would leave the export's storage prefix.
//
// This is the containment boundary for every prefix-joined backend, and it has
// to be, because there is nothing behind it: pstore's prefix is a logical
// namespace path, so there is no os.Root to catch an escape the way the POSIX
// backend has. golang.org/x/net/webdav cleans the request *path* but hands the
// Destination header of a COPY or MOVE to Rename / RemoveAll / OpenFile after
// no more than a strings.TrimPrefix, so "Destination: /<prefix>/../../other"
// arrived here with its dot-segments intact and path.Join happily resolved it
// into a neighbouring export -- with MOVE's RFC 4918 §9.9.3 "DELETE the
// destination first" turning that into cross-tenant data loss.
//
// The check mirrors the one handleCopyTPC already applies to its own
// destination (see tpc_handler.go): normalize, then require the result to
// still lie under the prefix.
func (afs *aferoFileSystem) fullPath(name string) (string, error) {
	if afs.prefix == "" {
		// Nothing to escape: this filesystem is already rooted at the export
		// (server_utils.NewOsRootFs, a BasePathFs, or a remote endpoint), and
		// that root is what confines it.
		return name, nil
	}
	return confineToPrefix(afs.prefix, name)
}

// confineToPrefix joins a request-relative path onto a storage prefix and
// refuses any result that does not remain under it.
//
// It is shared by every place that maps an untrusted, request-supplied path
// into a prefixed namespace -- the WebDAV filesystem above and the pstore
// checksummer -- because "path.Join normalizes the dot-segments away and lands
// somewhere else" is the same bug wherever it appears.
func confineToPrefix(prefix, name string) (string, error) {
	cleanPrefix := path.Clean("/" + strings.TrimPrefix(prefix, "/"))
	joined := path.Join(cleanPrefix, name)
	if !hasPathPrefix(joined, cleanPrefix) {
		// os.ErrPermission rather than ErrNotExist: the path is refused, and
		// saying "not found" for a path that may well exist invites probing.
		return "", &os.PathError{Op: "open", Path: name, Err: os.ErrPermission}
	}
	return joined, nil
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

	// obs and webdavName are populated when the enclosing
	// aferoFileSystem has observation enabled — they let DeadProps()
	// look up the current row for this path and surface
	// Pelican-specific properties on PROPFIND. Nil / empty
	// otherwise; DeadProps() returns no props in that case.
	obs        *observationConfig
	webdavName string
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
