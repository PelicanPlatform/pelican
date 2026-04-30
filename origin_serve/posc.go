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

// File posc.go implements a Persist-On-Successful-Close layer for the V2
// (POSIXv2) origin's webdav.FileSystem stack. Uploads with O_CREATE intent
// are staged at a hidden in-progress filename under a per-export POSC
// directory; the file is renamed into place only when its handle is
// successfully Close()'d. Failed/abandoned uploads are reaped by a
// background expiry goroutine after a configurable timeout.
//
// This is the Go port of the C++ POSC layer in the xrootd-s3-http plug-in
// (see Posc.cc / Posc.hh). The algorithm is the same; the Go version
// simplifies a few things because golang.org/x/net/webdav exposes a single
// OpenFile rather than the split Create/Open in XRootD's OSS layer.

package origin_serve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"golang.org/x/net/webdav"
)

// PoscMetricsHooks is a small set of optional hooks the POSC layer calls
// for observability. Wired up by the metrics package; the layer functions
// fine if these are nil.
type PoscMetricsHooks struct {
	IncActive func()
	DecActive func()
	IncExpire func()
	// IncRollbackFailed is called when the close hook fails AND the
	// best-effort RemoveAll of the just-renamed final path also
	// fails. Invoked at most once per close. Receives no namespace
	// label here — the metrics package translates it through the
	// closure that built the POSC layer.
	IncRollbackFailed func()
}

// poscFileSystem wraps a webdav.FileSystem and provides POSC semantics:
// creates are redirected to a hidden in-progress file, then renamed into
// place on a successful Close. Stat/ReadDir/Mkdir/Rename/RemoveAll on
// any path inside the POSC prefix is hidden from clients.
type poscFileSystem struct {
	inner      webdav.FileSystem
	poscPrefix string // POSC directory, expressed relative to the webdav.FileSystem namespace, eg "/.pelican-posc"

	// touchFS is an optional sibling of inner that exposes a Chtimes
	// operation. The webdav.FileSystem interface has no
	// utimes-equivalent so the keepalive thread needs a side
	// channel. When nil the keepalive falls back to a Stat (which
	// is wrong but harmless on backends where the OS auto-tracks
	// mtime via writes).
	touchFS afero.Fs

	fileTimeout time.Duration
	keepalive   time.Duration
	clock       func() time.Time

	mu       sync.Mutex
	openHead *poscFile

	cancel context.CancelFunc
	wg     sync.WaitGroup

	activeCount atomic.Int64

	hooks *PoscMetricsHooks

	// closeHook is invoked from poscFile.Close() after the temp→final
	// rename has succeeded. It is the seam used to plug in metadata
	// publishing and is nil by default. Receives the absolute (relative
	// to the webdav.FileSystem namespace) destination path.
	closeHook func(ctx context.Context, finalPath string, info os.FileInfo) error
}

// SetTouchFS installs an optional sibling afero.Fs used only by the
// keepalive goroutine to refresh mtime via Chtimes. The supplied fs
// must be the *same* underlying storage layer the webdav inner is
// reading from (typically the OsRootFs / autoCreateDirFs the rest of
// the chain wraps). Pass nil to disable.
func (p *poscFileSystem) SetTouchFS(fs afero.Fs) { p.touchFS = fs }

// newPoscFileSystem constructs a POSC-wrapping webdav.FileSystem. The
// background expiry goroutine starts immediately and is shut down when
// the supplied ctx is cancelled or Stop() is called.
func newPoscFileSystem(ctx context.Context, inner webdav.FileSystem, poscPrefix string, fileTimeout, keepalive time.Duration) *poscFileSystem {
	if fileTimeout <= 0 {
		fileTimeout = time.Hour
	}
	if keepalive <= 0 || keepalive >= fileTimeout {
		keepalive = fileTimeout - fileTimeout/4 // small safety margin
	}

	posc := &poscFileSystem{
		inner:       inner,
		poscPrefix:  cleanPoscPrefix(poscPrefix),
		fileTimeout: fileTimeout,
		keepalive:   keepalive,
		clock:       time.Now,
	}

	childCtx, cancel := context.WithCancel(ctx)
	posc.cancel = cancel
	posc.wg.Add(1)
	go posc.expireLoop(childCtx)
	return posc
}

// SetCloseHook installs a callback invoked after every successful POSC
// commit (the rename into final position). The hook receives the destination
// path; returning a non-nil error fails the close.
func (p *poscFileSystem) SetCloseHook(fn func(ctx context.Context, finalPath string, info os.FileInfo) error) {
	p.closeHook = fn
}

// SetMetricsHooks wires up Prometheus counters/gauges. May be called once
// at construction; nil-tolerant.
func (p *poscFileSystem) SetMetricsHooks(h *PoscMetricsHooks) {
	p.hooks = h
}

// Stop terminates the expiry goroutine and waits for it to finish. Safe
// to call more than once.
func (p *poscFileSystem) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
}

// cleanPoscPrefix normalizes a configured posc prefix into a clean
// /-prefixed path within the webdav.FileSystem namespace.
func cleanPoscPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		prefix = ".pelican-posc"
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	return path.Clean(prefix)
}

// inPoscDir reports whether name lies inside the POSC directory.
// It treats the prefix and prefix/* matches identically: both are hidden.
func (p *poscFileSystem) inPoscDir(name string) bool {
	cleaned := path.Clean("/" + strings.TrimLeft(name, "/"))
	if cleaned == p.poscPrefix {
		return true
	}
	return strings.HasPrefix(cleaned, p.poscPrefix+"/")
}

// Mkdir implements webdav.FileSystem.
func (p *poscFileSystem) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	if p.inPoscDir(name) {
		// Mirror the C++ POSC behavior: Mkdir inside the POSC prefix is
		// reported as EIO (rather than ENOENT), since ENOENT would imply
		// the parent doesn't exist.
		return &os.PathError{Op: "mkdir", Path: name, Err: syscall.EIO}
	}
	return p.inner.Mkdir(ctx, name, perm)
}

// OpenFile implements webdav.FileSystem.
func (p *poscFileSystem) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	if p.inPoscDir(name) {
		return nil, &os.PathError{Op: "open", Path: name, Err: syscall.ENOENT}
	}

	// Pass through reads / opens that don't request file creation.
	if flag&(os.O_CREATE|os.O_TRUNC) == 0 {
		return p.inner.OpenFile(ctx, name, flag, perm)
	}

	// Stage the upload at a unique temp filename; rename it into place
	// only on successful Close().
	user := usernameFromContext(ctx)
	if user == "" {
		user = "anonymous"
	}
	if err := p.ensureUserDir(ctx, user); err != nil {
		log.Debugf("POSC: failed to ensure user temp dir for %q: %v", user, err)
		return nil, err
	}

	// Ensure the *final* path's parent directory exists before
	// staging. Without POSC, the autoCreateDirFs layer creates
	// missing parents on the OpenFile of the final path itself; with
	// POSC redirecting writes to a hidden staging dir, the final
	// parent never gets created on the open path — but the rename
	// at Close() will then fail with ENOENT. Mirror the C++ POSC
	// (Posc.cc::Open) and create the parent up-front.
	cleanedFinal := path.Clean("/" + strings.TrimLeft(name, "/"))
	if parent := path.Dir(cleanedFinal); parent != "" && parent != "." && parent != "/" {
		if err := p.inner.Mkdir(ctx, parent, 0755); err != nil && !errors.Is(err, os.ErrExist) {
			// MkdirAll-on-Mkdir: most webdav.FileSystem
			// implementations layered atop autoCreateDirFs make
			// Mkdir act recursively. If Mkdir fails for a reason
			// other than "already exists", check if the directory
			// is actually present (could be a race or already-
			// recursive layer below); only return on a real miss.
			if _, statErr := p.inner.Stat(ctx, parent); statErr != nil {
				return nil, err
			}
		}
	}

	stagingPerm := perm
	if stagingPerm == 0 {
		stagingPerm = 0644
	}
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		tempPath := p.generateTempPath(user)
		stagingFlags := flag | os.O_EXCL | os.O_CREATE
		stagingFlags &^= os.O_TRUNC // O_EXCL+O_TRUNC is undefined; we just opened a brand-new file.
		// Open the staging file with the *requested* permission so
		// the post-rename file matches what the client asked for.
		// The staging *directory* is 0700 per-user, which is what
		// keeps in-progress files from being discoverable by other
		// users, regardless of the per-file mode here.
		f, err := p.inner.OpenFile(ctx, tempPath, stagingFlags, stagingPerm)
		if err == nil {
			pf := &poscFile{
				File:     f,
				fs:       p,
				ctx:      ctx,
				tempPath: tempPath,
				finalPath: path.Clean("/" + strings.TrimLeft(name, "/")),
				perm:     perm,
				mtime:    p.clock(),
			}
			p.registerOpen(pf)
			if p.hooks != nil && p.hooks.IncActive != nil {
				p.hooks.IncActive()
			}
			p.activeCount.Add(1)
			return pf, nil
		}
		// EEXIST is expected: retry with a new random name. ENOENT
		// means the per-user subdir vanished between ensureUserDir and
		// open — also retry. Other errors propagate immediately.
		lastErr = err
		if !(errors.Is(err, os.ErrExist) || errors.Is(err, os.ErrNotExist)) {
			break
		}
		if errors.Is(err, os.ErrNotExist) {
			_ = p.ensureUserDir(ctx, user)
		}
	}
	if lastErr == nil {
		lastErr = errors.New("posc: exhausted retries creating temp file")
	}
	return nil, lastErr
}

func (p *poscFileSystem) ensureUserDir(ctx context.Context, user string) error {
	dir := path.Join(p.poscPrefix, user)
	// Mkdir on the inner is allowed for paths inside the posc prefix
	// only via this helper (because we always go through p.inner.Mkdir
	// directly here, not through p.Mkdir which would refuse). The
	// underlying afero.Fs has no opinions about hidden directories.
	if err := p.inner.Mkdir(ctx, dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		// The autoCreateDirFs in the layer below will silently no-op
		// on already-exists; if we still get an error here it's an
		// actual problem (permission denied, etc).
		_, statErr := p.inner.Stat(ctx, dir)
		if statErr != nil {
			return err
		}
	}
	return nil
}

// generateTempPath returns a unique-with-high-probability staging filename
// inside the per-user POSC subdirectory. Uniqueness is *probabilistic*; the
// caller must retry on EEXIST (mirroring the C++ implementation).
func (p *poscFileSystem) generateTempPath(user string) string {
	now := p.clock().Unix()
	r := rand.Int63()
	return path.Join(p.poscPrefix, user, fmt.Sprintf("in_progress.%d.%d", now, r%1000000))
}

// RemoveAll implements webdav.FileSystem.
func (p *poscFileSystem) RemoveAll(ctx context.Context, name string) error {
	if p.inPoscDir(name) {
		return &os.PathError{Op: "remove", Path: name, Err: syscall.ENOENT}
	}
	return p.inner.RemoveAll(ctx, name)
}

// Rename implements webdav.FileSystem.
func (p *poscFileSystem) Rename(ctx context.Context, oldName, newName string) error {
	if p.inPoscDir(oldName) || p.inPoscDir(newName) {
		return &os.PathError{Op: "rename", Path: oldName, Err: syscall.ENOENT}
	}
	return p.inner.Rename(ctx, oldName, newName)
}

// Stat implements webdav.FileSystem.
func (p *poscFileSystem) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	if p.inPoscDir(name) {
		return nil, &os.PathError{Op: "stat", Path: name, Err: syscall.ENOENT}
	}
	return p.inner.Stat(ctx, name)
}

// registerOpen / unregisterOpen maintain a doubly-linked list of currently
// open POSC handles so the keepalive thread can walk them and refresh mtimes.
func (p *poscFileSystem) registerOpen(f *poscFile) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.openHead != nil {
		p.openHead.prev = f
	}
	f.next = p.openHead
	p.openHead = f
}

func (p *poscFileSystem) unregisterOpen(f *poscFile) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if f.prev != nil {
		f.prev.next = f.next
	}
	if f.next != nil {
		f.next.prev = f.prev
	}
	if p.openHead == f {
		p.openHead = f.next
	}
	f.prev, f.next = nil, nil
}

// snapshotOpen returns a copy of the open-handle list under the lock.
func (p *poscFileSystem) snapshotOpen() []*poscFile {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []*poscFile
	for f := p.openHead; f != nil; f = f.next {
		out = append(out, f)
	}
	return out
}

// expireLoop periodically removes stale temp files. It runs every 5s
// (matching the C++ implementation) which is small relative to typical
// FileTimeout (1h default).
func (p *poscFileSystem) expireLoop(ctx context.Context) {
	defer p.wg.Done()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			p.touchOpenFiles(ctx)
			p.expireFiles(ctx)
		}
	}
}

// touchOpenFiles walks the in-memory list of open POSC files and refreshes
// the mtime of any whose last refresh was more than `keepalive` ago.
func (p *poscFileSystem) touchOpenFiles(ctx context.Context) {
	now := p.clock()
	for _, f := range p.snapshotOpen() {
		f.touchIfStale(ctx, now, p.keepalive)
	}
}

// expireFiles walks each per-user POSC subdirectory and removes
// in-progress.* files whose mtime is older than fileTimeout.
func (p *poscFileSystem) expireFiles(ctx context.Context) {
	rootHandle, err := p.inner.OpenFile(ctx, p.poscPrefix, os.O_RDONLY, 0)
	if err != nil {
		// The POSC dir hasn't been created yet — that's normal on a
		// freshly-launched origin with no uploads.
		return
	}
	defer rootHandle.Close()

	users, err := rootHandle.Readdir(-1)
	if err != nil && err != io.EOF {
		log.Debugf("POSC: readdir on prefix %q failed: %v", p.poscPrefix, err)
		return
	}

	cutoff := p.clock().Add(-p.fileTimeout)
	for _, u := range users {
		if !u.IsDir() {
			continue
		}
		userDir := path.Join(p.poscPrefix, u.Name())
		uh, err := p.inner.OpenFile(ctx, userDir, os.O_RDONLY, 0)
		if err != nil {
			continue
		}
		entries, err := uh.Readdir(-1)
		uh.Close()
		if err != nil && err != io.EOF {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasPrefix(e.Name(), "in_progress.") {
				continue
			}
			if e.ModTime().After(cutoff) {
				continue
			}
			full := path.Join(userDir, e.Name())
			if err := p.inner.RemoveAll(ctx, full); err != nil {
				log.Debugf("POSC: removing stale %q failed: %v", full, err)
				continue
			}
			if p.hooks != nil && p.hooks.IncExpire != nil {
				p.hooks.IncExpire()
			}
			log.Debugf("POSC: removed stale temp file %q", full)
		}
	}
}

// poscFile wraps a webdav.File whose underlying storage path is a temp
// staging file. On Close(), the temp file is renamed into its final place;
// any failure removes the temp file and surfaces an error.
type poscFile struct {
	webdav.File
	fs        *poscFileSystem
	ctx       context.Context
	tempPath  string
	finalPath string
	perm      os.FileMode
	mtime     time.Time
	mu        sync.Mutex
	closed    bool

	// in-flight bookkeeping
	bytesWritten int64

	prev *poscFile
	next *poscFile
}

// markActivity bumps the in-memory last-write timestamp so the keepalive
// thread can decide whether to refresh the temp file's mtime.
func (f *poscFile) markActivity() {
	f.mu.Lock()
	f.mtime = f.fs.clock()
	f.mu.Unlock()
}

// touchIfStale, called from the keepalive goroutine, updates the temp
// file's filesystem mtime if it has been more than `keepalive` since
// the last write. We use the optional sibling afero.Fs (set via
// SetTouchFS) and call Chtimes; on failure or if no touchFS was
// configured, the next write will keep the file alive on its own.
func (f *poscFile) touchIfStale(ctx context.Context, now time.Time, keepalive time.Duration) {
	f.mu.Lock()
	stale := now.Sub(f.mtime) > keepalive
	closed := f.closed
	tempPath := f.tempPath
	f.mu.Unlock()
	if !stale || closed || tempPath == "" {
		return
	}
	if f.fs.touchFS != nil {
		if err := f.fs.touchFS.Chtimes(tempPath, now, now); err != nil {
			log.Debugf("POSC: keepalive Chtimes of %q failed: %v", tempPath, err)
		}
	} else if _, err := f.fs.inner.Stat(ctx, tempPath); err != nil {
		log.Debugf("POSC: keepalive stat of %q failed: %v", tempPath, err)
	}
	f.markActivity()
}

// Write tracks activity for the keepalive thread.
func (f *poscFile) Write(p []byte) (int, error) {
	n, err := f.File.Write(p)
	if n > 0 {
		f.bytesWritten += int64(n)
		f.markActivity()
	}
	return n, err
}

// Close commits the upload: it closes the underlying file, optionally
// chmods to the requested mode, then renames the staging file into its
// final destination. On any failure the temp file is removed and an
// error is returned to the caller.
func (f *poscFile) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	temp := f.tempPath
	final := f.finalPath
	f.mu.Unlock()

	defer func() {
		f.fs.unregisterOpen(f)
		if f.fs.hooks != nil && f.fs.hooks.DecActive != nil {
			f.fs.hooks.DecActive()
		}
		f.fs.activeCount.Add(-1)
	}()

	if err := f.File.Close(); err != nil {
		_ = f.fs.inner.RemoveAll(f.ctx, temp)
		return err
	}

	// The staging file was opened with the requested perm directly
	// (see OpenFile), so no Chmod is needed before the rename — the
	// final object inherits the right mode.

	// Optional Content-Length verification: if the request middleware
	// stashed an expected size on the context, refuse to commit a
	// truncated/oversized upload. Mirrors the C++ POSC's `oss.asize`
	// check.
	if expected := expectedContentLengthFromContext(f.ctx); expected > 0 {
		if info, err := f.fs.inner.Stat(f.ctx, temp); err == nil {
			if info.Size() != expected {
				_ = f.fs.inner.RemoveAll(f.ctx, temp)
				return fmt.Errorf("posc: staged size %d does not match Content-Length %d", info.Size(), expected)
			}
		}
	}

	// Rename temp → final. If the destination already exists as a
	// directory the os layer returns EISDIR; surface it unchanged so
	// the webdav handler can map to 409 Conflict.
	if err := f.fs.inner.Rename(f.ctx, temp, final); err != nil {
		_ = f.fs.inner.RemoveAll(f.ctx, temp)
		return err
	}

	if f.fs.closeHook != nil {
		info, statErr := f.fs.inner.Stat(f.ctx, final)
		if statErr != nil {
			log.Debugf("POSC: stat after rename failed for %q: %v", final, statErr)
		}
		if err := f.fs.closeHook(f.ctx, final, info); err != nil {
			// Transactional rollback: the publish refused the
			// commit, so the object should not be visible. Best-
			// effort delete; if even that fails, count it.
			if rmErr := f.fs.inner.RemoveAll(f.ctx, final); rmErr != nil {
				log.Warnf("POSC: rollback delete of %q after close-hook error failed: %v", final, rmErr)
				if f.fs.hooks != nil && f.fs.hooks.IncRollbackFailed != nil {
					f.fs.hooks.IncRollbackFailed()
				}
			}
			return err
		}
	}
	return nil
}

// activePoscFiles is a Prometheus-friendly accessor used by tests / metrics.
func (p *poscFileSystem) activePoscFiles() int64 { return p.activeCount.Load() }
