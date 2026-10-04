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

package local_cache

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/utils"
)

// Layout of a shared-filesystem target's directory.  The backend's keys all
// live under posixObjectsDir, so a listing of the keys can never wander into
// the names view or into half-written files: the consistency sweep's notion
// of "every object on the target" is that one subtree by construction.
const (
	posixObjectsDir = "objects"
	posixNamesDir   = "names"
	posixTempDir    = ".pelican-tmp"

	// posixFileMode and posixDirMode are what every file and directory the
	// cache creates ends up with, whatever the process umask: readable by
	// every user of the filesystem -- that is the point of the target -- and
	// writable only by the cache.  They are applied with an explicit chmod
	// after creation, since the mode passed to open/mkdir is filtered
	// through the umask and a restrictive umask would lock clients out.
	posixFileMode fs.FileMode = 0o644
	posixDirMode  fs.FileMode = 0o755
)

// posixTierBackend is a TierBackend over a directory on a filesystem the
// cache shares with its clients -- an NFS, Lustre, GPFS or CephFS mount.
//
// It is native rather than gocloud's fileblob, which was the obvious
// alternative.  fileblob writes files 0600 and keeps attributes in sidecar
// files, has no way to pin a read to the copy that was written, and hands out
// http URLs through a signer; this target exists precisely so that other
// users can open the files directly, under predictable names, through
// file:// redirects and the names view (tierNameView).  Matching all of that
// is less code than adapting fileblob to it.
//
// Every operation goes through an os.Root opened on the directory, so even a
// symlink planted inside the tree cannot make the cache read or write outside
// it.  Writes go to a temporary file in posixTempDir and are renamed into
// place, so a reader -- the cache, a redirected client, or someone browsing
// the names view -- never sees a partial object.
//
// A filesystem has no entity tag, so the backend synthesizes one from the
// file's inode, size and modification time (see posixETag).  Every write
// creates a new inode, and an in-place modification changes the mtime, so
// any change to an object changes its tag; that is what lets reads be pinned
// to the copy that was uploaded, as they are against an object store.
type posixTierBackend struct {
	dir     string // absolute directory, as configured
	root    *os.Root
	fs      *posixFS // root, with every call bounded; use this, not root
	display string

	// inflight holds the temporary names in use by writes now in progress,
	// so that reaping leftovers never removes a file out from under its
	// writer.
	inflight sync.Map
}

var (
	_ TierBackend           = (*posixTierBackend)(nil)
	_ TierRedirector        = (*posixTierBackend)(nil)
	_ TierStaleUploadReaper = (*posixTierBackend)(nil)
)

// newPosixTierBackend opens (creating if need be) the target's directory and
// its fixed subdirectories, and refuses one whose permissions would let
// another user tamper with what the cache publishes.  It gives up, rather
// than hanging startup, if the filesystem does not answer.
func newPosixTierBackend(cfg TierTargetConfig) (*posixTierBackend, error) {
	b, err := runWithDeadline(posixStartupTimeout, func() (*posixTierBackend, error) {
		return openPosixTierBackend(cfg)
	}, nil, func(late *posixTierBackend, err error) {
		if err == nil {
			_ = late.Close()
		}
	})
	if errors.Is(err, errTargetNotResponding) {
		return nil, errors.Wrapf(err, "cache tier target %s did not answer while being opened; is its filesystem "+
			"mounted and reachable?", cfg.DisplayURL())
	}
	return b, err
}

func openPosixTierBackend(cfg TierTargetConfig) (*posixTierBackend, error) {
	display := cfg.DisplayURL()
	u, err := url.Parse(cfg.ProviderURL)
	if err != nil {
		return nil, errors.Wrapf(err, "cache tier target %s is not a valid URL", display)
	}
	base := filepath.Clean(utils.FileURLToPath(u))
	dir := cfg.SharedFilesystemDir()
	if !filepath.IsAbs(base) || dir == "" || !filepath.IsAbs(dir) {
		return nil, errors.Errorf("cache tier target %s does not name an absolute directory", display)
	}
	// The named directory is created only if its parent exists: a missing
	// parent usually means the shared filesystem is not mounted, and
	// creating it would hide that by writing to the local disk instead.
	// Prefix components below it are the cache's to create.
	if err := makeTargetDir(base, display); err != nil {
		return nil, err
	}
	cur := base
	if prefix := trimTierPrefix(cfg.Prefix); prefix != "" {
		for _, component := range strings.Split(prefix, "/") {
			cur = filepath.Join(cur, component)
			if err := makeTargetDir(cur, display); err != nil {
				return nil, err
			}
		}
	}
	if err := checkSecurePath(dir); err != nil {
		return nil, errors.Wrapf(err, "refusing cache tier target %s", display)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open cache tier target %s", display)
	}
	b := &posixTierBackend{dir: dir, root: root, fs: newPosixFS(root), display: display}
	for _, sub := range []string{posixObjectsDir, posixNamesDir, posixTempDir} {
		if _, err := b.mkdir(sub); err != nil {
			_ = root.Close()
			return nil, err
		}
	}
	if err := b.checkPermissions(); err != nil {
		_ = root.Close()
		return nil, err
	}
	if err := b.fs.sameDirectory(dir); err != nil {
		_ = root.Close()
		return nil, err
	}
	return b, nil
}

// makeTargetDir creates one directory of the target's path, if missing,
// with posixDirMode whatever the umask.
func makeTargetDir(dir, display string) error {
	err := os.Mkdir(dir, posixDirMode)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return errors.Wrapf(err, "failed to create %s for cache tier target %s", dir, display)
	}
	if err := os.Chmod(dir, posixDirMode); err != nil {
		return errors.Wrapf(err, "failed to set permissions on %s for cache tier target %s", dir, display)
	}
	return nil
}

func (b *posixTierBackend) DisplayURL() string { return b.display }

func (b *posixTierBackend) Close() error { return b.root.Close() }

// objectPath maps a key to its path relative to the root.  Keys are
// slash-separated and must stay inside the objects tree; fs.ValidPath rejects
// "..", empty and absolute elements, and the root would refuse them anyway.
func (b *posixTierBackend) objectPath(key string) (string, error) {
	if key == "" || key == "." || !fs.ValidPath(key) {
		return "", errors.Errorf("invalid key %q for cache tier target %s", key, b.display)
	}
	return posixObjectsDir + "/" + key, nil
}

// mkdir creates one directory below the root with posixDirMode, reporting
// whether it was created (false: it already existed as a directory).
func (b *posixTierBackend) mkdir(name string) (bool, error) {
	err := b.fs.Mkdir(name, posixDirMode)
	if err == nil {
		if err := b.fs.Chmod(name, posixDirMode); err != nil {
			return true, errors.Wrapf(err, "failed to set permissions on %s in cache tier target %s", name, b.display)
		}
		// Make the new entry durable, or a crash could lose the directory
		// -- and with it every object later renamed into it.
		b.syncDir(path.Dir(name))
		return true, nil
	}
	if errors.Is(err, fs.ErrExist) {
		if info, statErr := b.fs.Lstat(name); statErr == nil && info.IsDir() {
			return false, nil
		}
	}
	return false, errors.Wrapf(err, "failed to create %s in cache tier target %s", name, b.display)
}

// mkdirAll creates every missing directory on the way to name, each with
// posixDirMode.  Directories that already exist are left alone; the cache
// created them, with the same mode.
func (b *posixTierBackend) mkdirAll(name string) error {
	if name == "." || name == "" {
		return nil
	}
	if info, err := b.fs.Lstat(name); err == nil && info.IsDir() {
		return nil
	}
	if err := b.mkdirAll(path.Dir(name)); err != nil {
		return err
	}
	_, err := b.mkdir(name)
	return err
}

// newTempName reserves a fresh name in the temporary directory.  The caller
// must call release when it is done with the name, whatever became of it.
func (b *posixTierBackend) newTempName(kind string) (name string, release func()) {
	name = posixTempDir + "/" + kind + "-" + uuid.NewString()
	b.inflight.Store(name, struct{}{})
	return name, func() { b.inflight.Delete(name) }
}

// checkPermissions refuses a target that someone other than the cache could
// write to.  Anyone who can write the root or one of its fixed directories
// can plant a symlink in the names view -- pointing users who trust it at a
// file of the attacker's choosing -- or swap an object's bytes; the cache's
// own containment (os.Root) protects only the cache, not the people reading
// the tree.  It runs at startup and on every liveness probe, so a permission
// change made while the cache runs takes the target out of rotation.
func (b *posixTierBackend) checkPermissions() error {
	if runtime.GOOS == "windows" {
		return nil // mode bits do not describe Windows ACLs
	}
	for _, name := range []string{".", posixObjectsDir, posixNamesDir, posixTempDir} {
		var (
			info os.FileInfo
			err  error
		)
		if name == "." {
			info, err = b.fs.Stat(name)
		} else {
			// The subdirectories must be real directories: a symlink would
			// let whoever controls its target control the tree.
			info, err = b.fs.Lstat(name)
		}
		if err != nil {
			return errors.Wrapf(err, "failed to check %s in cache tier target %s", name, b.display)
		}
		where := filepath.Join(b.dir, name)
		if !info.IsDir() {
			return errors.Errorf("%s in cache tier target %s is not a directory", where, b.display)
		}
		if perm := info.Mode().Perm(); perm&0o022 != 0 {
			return errors.Errorf("%s is writable by users other than the cache (mode %#o); anyone who can write it "+
				"could replace cached objects or plant links in the names view that other users trust.  "+
				"Remove the group and other write bits (chmod go-w %s)", where, perm, where)
		}
		if uid, _, err := utils.FileOwnerIDs(info); err == nil && uid != os.Geteuid() {
			return errors.Errorf("%s is owned by uid %d, but the cache runs as uid %d; its owner could change its "+
				"permissions and tamper with what the cache publishes.  Make the cache's user its owner", where, uid, os.Geteuid())
		}
	}
	return nil
}

// checkHealth is the backend's part of the liveness probe: the directory
// must still be one only the cache can write, its path must still lead
// only through directories no one else can rearrange, and that path must
// still name the directory the cache holds open.  The last is what catches
// a target swapped out from under the cache -- or a filesystem mounted over
// it -- which the cache itself would never notice, since it works through
// its open handle while clients and names-view readers go by path.
func (b *posixTierBackend) checkHealth() error {
	if err := b.checkPermissions(); err != nil {
		return err
	}
	if err := posixCallErr(b.fs, func() error { return checkSecurePath(b.dir) }); err != nil {
		return err
	}
	return b.fs.sameDirectory(b.dir)
}

// posixETag synthesizes an entity tag for a file from its inode, size and
// modification time.  The inode changes with every write the cache makes
// (each is a new file renamed into place) and the mtime with any write made
// in place, so the tag changes whenever the bytes could have.  Where the
// platform reports no inode it is zero and size and mtime carry the tag.
func posixETag(info os.FileInfo) string {
	_, ino, _ := utils.FileVFSID(info)
	return fmt.Sprintf("%x-%x-%x", ino, info.Size(), info.ModTime().UnixNano())
}

func posixObjectInfo(info os.FileInfo) TierObjectInfo {
	return TierObjectInfo{Size: info.Size(), ETag: posixETag(info), ModTime: info.ModTime()}
}

// contextReader stops a copy when its context is cancelled, which io.Copy
// has no other way to notice.
type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (c contextReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// Put writes the object to a temporary file, sets its mode, flushes it to
// stable storage, and only then renames it into place.  The rename is atomic,
// so the key names either the previous object or the complete new one.
func (b *posixTierBackend) Put(ctx context.Context, key, _ string, size int64, body io.Reader) (TierObjectInfo, error) {
	dest, err := b.objectPath(key)
	if err != nil {
		return TierObjectInfo{}, err
	}
	tmp, release := b.newTempName("put")
	defer release()

	// Created owner-only: until it is complete nobody else has any business
	// reading it.  The final mode is set explicitly below.
	f, err := b.fs.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return TierObjectInfo{}, errors.Wrapf(err, "failed to create a temporary file on cache tier target %s", b.display)
	}
	committed := false
	defer func() {
		if !committed {
			_ = f.Close()
			_ = b.fs.Remove(tmp)
		}
	}()

	n, err := io.Copy(f, contextReader{ctx: ctx, r: body})
	if err == nil && n != size {
		err = errors.Errorf("expected %d bytes, read %d", size, n)
	}
	if err != nil {
		return TierObjectInfo{}, errors.Wrapf(err, "failed to write %s to cache tier target %s", key, b.display)
	}
	if err := f.Chmod(posixFileMode); err != nil {
		return TierObjectInfo{}, errors.Wrapf(err, "failed to set permissions on %s in cache tier target %s", key, b.display)
	}
	// Without the flush, a crash after the rename could leave the key naming
	// a file whose data never reached the disk -- on a shared filesystem,
	// that is a file every client would read as garbage.
	if err := f.Sync(); err != nil {
		return TierObjectInfo{}, errors.Wrapf(err, "failed to flush %s to cache tier target %s", key, b.display)
	}
	if err := b.mkdirAll(path.Dir(dest)); err != nil {
		return TierObjectInfo{}, err
	}
	if err := b.fs.Rename(tmp, dest); err != nil {
		if errors.Is(err, syscall.EXDEV) {
			return TierObjectInfo{}, errors.Errorf("cannot move %s into place on cache tier target %s: %s and %s are "+
				"on different filesystems (a separate fileset or project?), and a rename cannot cross them; keep the "+
				"whole target directory on one filesystem", key, b.display, posixTempDir, posixObjectsDir)
		}
		return TierObjectInfo{}, errors.Wrapf(err, "failed to move %s into place on cache tier target %s", key, b.display)
	}
	committed = true
	// The descriptor still refers to the file now at dest, so this describes
	// exactly what was written -- no window for another writer to slip in
	// between the rename and a lookup by name.
	info, statErr := f.Stat()
	closeErr := f.Close()
	if statErr != nil {
		return TierObjectInfo{}, errors.Wrapf(statErr, "failed to confirm the write of %s to cache tier target %s", key, b.display)
	}
	if closeErr != nil {
		return TierObjectInfo{}, errors.Wrapf(closeErr, "failed to write %s to cache tier target %s", key, b.display)
	}
	if info.Size() != size {
		return TierObjectInfo{}, errors.Errorf("write of %s to cache tier target %s stored %d bytes; expected %d",
			key, b.display, info.Size(), size)
	}
	b.syncDir(path.Dir(dest))
	return posixObjectInfo(info), nil
}

// syncDir makes a rename into dir durable.  Best effort: not every
// filesystem (or platform) supports syncing a directory, and the object is
// already complete either way.
func (b *posixTierBackend) syncDir(dir string) {
	d, err := b.fs.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// OpenRange opens the object and, when expect carries an entity tag, checks
// the tag against the open descriptor -- the file that will actually be
// read, so a replacement cannot slip in between the check and the read.
func (b *posixTierBackend) OpenRange(_ context.Context, key string, offset int64, expect *TierObjectInfo) (io.ReadCloser, error) {
	name, err := b.objectPath(key)
	if err != nil {
		return nil, err
	}
	f, err := b.fs.Open(name)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open %s on cache tier target %s", key, b.display)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, errors.Wrapf(err, "failed to open %s on cache tier target %s", key, b.display)
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, errors.Errorf("%s on cache tier target %s is not a regular file", key, b.display)
	}
	if expect != nil && expect.ETag != "" && posixETag(info) != expect.ETag {
		_ = f.Close()
		return nil, errors.Wrapf(ErrTierObjectChanged, "%s on cache tier target %s", key, b.display)
	}
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			_ = f.Close()
			return nil, errors.Wrapf(err, "failed to seek %s on cache tier target %s", key, b.display)
		}
	}
	return f, nil
}

func (b *posixTierBackend) Stat(_ context.Context, key string) (TierObjectInfo, bool, error) {
	name, err := b.objectPath(key)
	if err != nil {
		return TierObjectInfo{}, false, err
	}
	info, err := b.fs.Stat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return TierObjectInfo{}, false, nil
	}
	if err != nil {
		return TierObjectInfo{}, false, errors.Wrapf(err, "failed to stat %s on cache tier target %s", key, b.display)
	}
	if !info.Mode().IsRegular() {
		return TierObjectInfo{}, false, errors.Errorf("%s on cache tier target %s is not a regular file", key, b.display)
	}
	return posixObjectInfo(info), true, nil
}

func (b *posixTierBackend) Delete(_ context.Context, key string) error {
	name, err := b.objectPath(key)
	if err != nil {
		return err
	}
	if err := b.fs.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return errors.Wrapf(err, "failed to delete %s from cache tier target %s", key, b.display)
	}
	return nil
}

// List walks the objects tree in ascending key order.
//
// A plain depth-first walk of sorted directory entries is not quite that:
// it visits everything under "a/" before "a-b", although '-' sorts before
// '/'.  Sorting each directory's entries as their names would appear inside
// a key -- a directory as "name/" -- makes the walk order exactly the key
// order, which the sweep's merge join needs.  Only regular files are keys;
// anything else in the tree is not the cache's and is ignored.
func (b *posixTierBackend) List(ctx context.Context, fn func(key string, size int64, modified time.Time) error) error {
	return b.listDir(ctx, posixObjectsDir, "", fn)
}

func (b *posixTierBackend) listDir(ctx context.Context, dir, keyPrefix string, fn func(string, int64, time.Time) error) error {
	entries, err := b.fs.ReadDirInfo(dir)
	if err != nil {
		return errors.Wrapf(err, "failed to list %s on cache tier target %s", dir, b.display)
	}
	sortKey := func(e fs.FileInfo) string {
		if e.IsDir() {
			return e.Name() + "/"
		}
		return e.Name()
	}
	sort.Slice(entries, func(i, j int) bool { return sortKey(entries[i]) < sortKey(entries[j]) })
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch {
		case e.IsDir():
			if err := b.listDir(ctx, dir+"/"+e.Name(), keyPrefix+e.Name()+"/", fn); err != nil {
				return err
			}
		case e.Mode().IsRegular():
			if err := fn(keyPrefix+e.Name(), e.Size(), e.ModTime()); err != nil {
				return err
			}
		}
	}
	return nil
}

// RedirectURL returns the object's path as a file:// URL (RFC 8089).
//
// It names the object itself, never a link in the names view: the path holds
// no symlinks the cache made, so a client confining itself with os.Root --
// which refuses absolute symlinks -- can follow it under a root naming either
// this directory or its objects tree.  The URL needs no signature or expiry;
// the filesystem's own permissions are the authorization.
func (b *posixTierBackend) RedirectURL(_ context.Context, key string, _ time.Duration, _ *TierObjectInfo) (string, error) {
	name, err := b.objectPath(key)
	if err != nil {
		return "", err
	}
	return utils.PathToFileURL(filepath.Join(b.dir, filepath.FromSlash(name))).String(), nil
}

// probeRedirect reports the URL shape this backend redirects to.  A
// shared-filesystem target can always redirect; whether a given client can
// follow it is that client's to say (X-Pelican-Accept-Redirect).
func (b *posixTierBackend) probeRedirect(ctx context.Context) (string, bool) {
	u, err := b.RedirectURL(ctx, tierRedirectProbeKey, time.Minute, nil)
	return u, err == nil
}

// ReapStaleUploads removes temporary files -- objects and links whose write
// never finished, typically because the process died mid-write -- that are
// older than maxAge.  They are invisible to listings but still take space.
// Files belonging to writes this process still has in progress are spared
// whatever their age.
func (b *posixTierBackend) ReapStaleUploads(ctx context.Context, maxAge time.Duration) (int, error) {
	entries, err := b.fs.ReadDirInfo(posixTempDir)
	if err != nil {
		return 0, errors.Wrapf(err, "failed to list temporary files on cache tier target %s", b.display)
	}
	cutoff := time.Now().Add(-maxAge)
	reaped := 0
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return reaped, err
		}
		name := posixTempDir + "/" + e.Name()
		if _, busy := b.inflight.Load(name); busy {
			continue
		}
		if e.ModTime().After(cutoff) {
			continue
		}
		if err := b.fs.RemoveAll(name); err != nil {
			log.Warnf("Failed to remove stale temporary file %s on cache tier target %s: %v", e.Name(), b.display, err)
			continue
		}
		reaped++
	}
	return reaped, nil
}
