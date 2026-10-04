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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/utils"
)

// A shared filesystem fails differently from an object store.  When an NFS
// server goes away, a hard mount -- the default -- blocks every system call
// on it indefinitely, and no context can interrupt a blocked stat or read.
// Called directly, one hung mount would wedge the uploader workers, the
// sweep, every request proxied from the target, and the liveness probe
// itself, which would then never report the target as down.
//
// So every call into the filesystem goes through posixFS, which runs it on
// its own goroutine and stops waiting after a deadline.  A call that misses
// its deadline is abandoned -- left blocked, to finish whenever the kernel
// lets it -- and while any abandoned call is outstanding the filesystem is
// presumed hung: further calls fail at once instead of piling up more stuck
// goroutines.  When the stuck calls finally return, the filesystem is usable
// again with no intervention.

// errTargetNotResponding reports a call abandoned at its deadline, or
// refused because an earlier one is still blocked.
var errTargetNotResponding = errors.New("the tiering target is not responding")

const (
	// posixOpTimeout bounds one filesystem call.  It is long, because a
	// single fsync of a large object on a busy server can legitimately take
	// a while; the liveness probe has a much shorter deadline of its own and
	// is what takes a hung target out of rotation promptly.
	posixOpTimeout = time.Minute
	// posixStartupTimeout bounds opening the target at startup, so a mount
	// that is hung when the cache starts fails startup instead of hanging it.
	posixStartupTimeout = time.Minute
)

// runWithDeadline runs fn on its own goroutine and waits for it for at most
// timeout.  If the deadline passes first it returns errTargetNotResponding
// and leaves fn running: abandon is called at that moment, and late -- on
// fn's goroutine -- once fn finally returns, so that whatever fn acquired
// (an open file, say) can be released.  Either hook may be nil.
func runWithDeadline[T any](timeout time.Duration, fn func() (T, error), abandon func(), late func(T, error)) (T, error) {
	type outcome struct {
		val T
		err error
	}
	var (
		mu       sync.Mutex
		finished bool
		gaveUp   bool
	)
	done := make(chan outcome, 1)
	go func() {
		val, err := fn()
		mu.Lock()
		finished = true
		abandoned := gaveUp
		mu.Unlock()
		if abandoned {
			if late != nil {
				late(val, err)
			}
			return
		}
		done <- outcome{val, err}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case o := <-done:
		return o.val, o.err
	case <-timer.C:
	}
	mu.Lock()
	if finished {
		// It returned just as the timer fired; its result is on the way.
		mu.Unlock()
		o := <-done
		return o.val, o.err
	}
	gaveUp = true
	if abandon != nil {
		abandon()
	}
	mu.Unlock()
	var zero T
	return zero, errors.Wrapf(errTargetNotResponding, "no answer within %s", timeout)
}

// posixFS is an os.Root whose every call is bounded; see the note above.
type posixFS struct {
	root    *os.Root
	timeout time.Duration
	// stuck counts abandoned calls that have not yet returned.
	stuck atomic.Int64
}

func newPosixFS(root *os.Root) *posixFS {
	return &posixFS{root: root, timeout: posixOpTimeout}
}

// posixCall runs one call with the deadline and the stuck-call circuit
// breaker.  late, if set, sees the result of a call that was abandoned.
func posixCall[T any](p *posixFS, fn func() (T, error), late func(T, error)) (T, error) {
	if n := p.stuck.Load(); n > 0 {
		var zero T
		return zero, errors.Wrapf(errTargetNotResponding, "%d earlier call(s) still blocked", n)
	}
	return runWithDeadline(p.timeout, fn, func() { p.stuck.Add(1) }, func(v T, err error) {
		p.stuck.Add(-1)
		if late != nil {
			late(v, err)
		}
	})
}

// posixCallErr is posixCall for calls that return only an error.
func posixCallErr(p *posixFS, fn func() error) error {
	_, err := posixCall(p, func() (struct{}, error) { return struct{}{}, fn() }, nil)
	return err
}

func (p *posixFS) Stat(name string) (fs.FileInfo, error) {
	return posixCall(p, func() (fs.FileInfo, error) { return p.root.Stat(name) }, nil)
}

func (p *posixFS) Lstat(name string) (fs.FileInfo, error) {
	return posixCall(p, func() (fs.FileInfo, error) { return p.root.Lstat(name) }, nil)
}

func (p *posixFS) Readlink(name string) (string, error) {
	return posixCall(p, func() (string, error) { return p.root.Readlink(name) }, nil)
}

func (p *posixFS) Symlink(oldname, newname string) error {
	return posixCallErr(p, func() error { return p.root.Symlink(oldname, newname) })
}

func (p *posixFS) Rename(oldname, newname string) error {
	return posixCallErr(p, func() error { return p.root.Rename(oldname, newname) })
}

func (p *posixFS) Remove(name string) error {
	return posixCallErr(p, func() error { return p.root.Remove(name) })
}

func (p *posixFS) RemoveAll(name string) error {
	return posixCallErr(p, func() error { return p.root.RemoveAll(name) })
}

func (p *posixFS) Mkdir(name string, perm fs.FileMode) error {
	return posixCallErr(p, func() error { return p.root.Mkdir(name, perm) })
}

func (p *posixFS) Chmod(name string, mode fs.FileMode) error {
	return posixCallErr(p, func() error { return p.root.Chmod(name, mode) })
}

// ReadDir lists a directory.  The entries carry only their types; Info on
// one would be another, unbounded, call.
func (p *posixFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return posixCall(p, func() ([]fs.DirEntry, error) { return fs.ReadDir(p.root.FS(), name) }, nil)
}

// ReadDirInfo lists a directory with each entry's lstat information.
func (p *posixFS) ReadDirInfo(name string) ([]fs.FileInfo, error) {
	return posixCall(p, func() ([]fs.FileInfo, error) {
		entries, err := fs.ReadDir(p.root.FS(), name)
		if err != nil {
			return nil, err
		}
		infos := make([]fs.FileInfo, 0, len(entries))
		for _, e := range entries {
			info, err := e.Info()
			if errors.Is(err, fs.ErrNotExist) {
				continue // removed since the directory was read
			}
			if err != nil {
				return nil, err
			}
			infos = append(infos, info)
		}
		return infos, nil
	}, nil)
}

// OpenFile opens a file whose later calls are bounded too.  A file opened
// only after its call was abandoned is closed when the open returns.
func (p *posixFS) OpenFile(name string, flag int, perm fs.FileMode) (*posixFile, error) {
	f, err := posixCall(p, func() (*os.File, error) { return p.root.OpenFile(name, flag, perm) },
		func(f *os.File, err error) {
			if err == nil {
				_ = f.Close()
			}
		})
	if err != nil {
		return nil, err
	}
	return &posixFile{p: p, f: f}, nil
}

func (p *posixFS) Open(name string) (*posixFile, error) {
	return p.OpenFile(name, os.O_RDONLY, 0)
}

// sameDirectory reports whether the path dir still names the directory the
// root holds open, comparing device and inode.  A mismatch means something
// was renamed, mounted or linked over the path since the cache opened it --
// and every reader that goes by path (redirected clients, the names view)
// would see that instead.
func (p *posixFS) sameDirectory(dir string) error {
	return posixCallErr(p, func() error {
		held, err := p.root.Stat(".")
		if err != nil {
			return err
		}
		byPath, err := os.Stat(dir)
		if err != nil {
			return errors.Wrapf(err, "%s no longer resolves", dir)
		}
		heldDev, heldIno, ok1 := utils.FileVFSID(held)
		pathDev, pathIno, ok2 := utils.FileVFSID(byPath)
		if !ok1 || !ok2 {
			return nil // the platform cannot tell
		}
		if heldDev != pathDev || heldIno != pathIno {
			return errors.Errorf("%s is no longer the directory the cache opened (something was renamed, mounted "+
				"or linked over it); clients reading by path would not see the cache's files", dir)
		}
		return nil
	})
}

// posixFile is an open file whose calls are bounded like posixFS's.
//
// An abandoned read or write is still running on its own goroutine, so it
// must not touch the caller's buffer: the caller would reuse that buffer
// the moment the call returned.  Reads and writes therefore go through a
// private buffer, and a file with an abandoned call is not used again.
type posixFile struct {
	p      *posixFS
	f      *os.File
	buf    []byte
	broken bool
}

func (f *posixFile) scratch(n int) []byte {
	if cap(f.buf) < n {
		f.buf = make([]byte, n)
	}
	return f.buf[:n]
}

func (f *posixFile) check() error {
	if f.broken {
		return errors.Wrap(errTargetNotResponding, "an earlier call on this file was abandoned")
	}
	return nil
}

// noteAbandon retires the file after an abandoned call: its goroutine still
// owns the private buffer.
func (f *posixFile) noteAbandon(err error) {
	if errors.Is(err, errTargetNotResponding) {
		f.broken = true
		f.buf = nil
	}
}

func (f *posixFile) Read(b []byte) (int, error) {
	if err := f.check(); err != nil {
		return 0, err
	}
	buf := f.scratch(len(b))
	n, err := posixCall(f.p, func() (int, error) { return f.f.Read(buf) }, nil)
	f.noteAbandon(err)
	copy(b, buf[:n])
	return n, err
}

func (f *posixFile) Write(b []byte) (int, error) {
	if err := f.check(); err != nil {
		return 0, err
	}
	buf := f.scratch(len(b))
	copy(buf, b)
	n, err := posixCall(f.p, func() (int, error) { return f.f.Write(buf) }, nil)
	f.noteAbandon(err)
	return n, err
}

// Seek only moves the descriptor's offset; it does not reach the server.
func (f *posixFile) Seek(offset int64, whence int) (int64, error) {
	if err := f.check(); err != nil {
		return 0, err
	}
	return f.f.Seek(offset, whence)
}

func (f *posixFile) Stat() (fs.FileInfo, error) {
	if err := f.check(); err != nil {
		return nil, err
	}
	info, err := posixCall(f.p, func() (fs.FileInfo, error) { return f.f.Stat() }, nil)
	f.noteAbandon(err)
	return info, err
}

func (f *posixFile) Chmod(mode fs.FileMode) error {
	if err := f.check(); err != nil {
		return err
	}
	err := posixCallErr(f.p, func() error { return f.f.Chmod(mode) })
	f.noteAbandon(err)
	return err
}

func (f *posixFile) Sync() error {
	if err := f.check(); err != nil {
		return err
	}
	err := posixCallErr(f.p, f.f.Sync)
	f.noteAbandon(err)
	return err
}

// Close releases the descriptor.  A broken file's close is issued on a
// goroutine of its own: the descriptor must still be released, but the call
// that broke it may be blocked yet, and the caller must not wait on it.
func (f *posixFile) Close() error {
	if f.broken {
		go func() { _ = f.f.Close() }()
		return nil
	}
	return posixCallErr(f.p, f.f.Close)
}

// checkSecurePath refuses a directory that someone other than root or the
// cache could make the path point somewhere else.  It applies the rule
// OpenSSH (StrictModes) and sudo use for files they trust: every component
// from / down to dir -- following symlinks, whose own location is checked
// too -- must be owned by root or by the cache's user, and a directory must
// not be writable by group or other unless it is sticky (as /tmp is), since
// whoever can write a directory can rename its entries and put their own in
// their place.
//
// That matters here because the cache's own access is through a handle and
// cannot be redirected, but everyone else's is by path: a client following
// a file:// redirect, and a person browsing the names view.  Swapping the
// target directory would hand them the swapper's files under the cache's
// name.
func checkSecurePath(dir string) error {
	euid := os.Geteuid()
	check := func(p string, info fs.FileInfo) error {
		uid, _, err := utils.FileOwnerIDs(info)
		if err != nil {
			return nil // the platform cannot tell
		}
		if uid != 0 && uid != euid {
			return errors.Errorf("%s is owned by uid %d, which is neither root nor the cache's user (uid %d); its owner "+
				"could replace the cache's directory with one of their own, which clients and names-view readers "+
				"would then trust.  Put the target under a directory owned by root or by the cache's user", p, uid, euid)
		}
		if info.IsDir() {
			perm := info.Mode()
			if perm.Perm()&0o022 != 0 && perm&fs.ModeSticky == 0 {
				return errors.Errorf("%s is writable by users other than its owner (mode %#o) and is not sticky; any of "+
					"them could rename the cache's directory and put their own in its place, which clients and "+
					"names-view readers would then trust.  Put the target under a directory the cache's user owns, "+
					"reached only through directories that only root or the cache's user can write -- or set the "+
					"sticky bit on %s (chmod +t), so that its other users cannot rename entries they do not own", p, perm.Perm(), p)
			}
		}
		return nil
	}

	const maxLinks = 40
	followed := 0
	cur := string(filepath.Separator)
	info, err := os.Lstat(cur)
	if err != nil {
		return err
	}
	if err := check(cur, info); err != nil {
		return err
	}
	pending := splitPath(dir)
	for len(pending) > 0 {
		name := pending[0]
		pending = pending[1:]
		switch name {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, name)
		info, err := os.Lstat(next)
		if err != nil {
			return err
		}
		if info.Mode()&fs.ModeSymlink == 0 && onlyTrivial(pending) {
			// The target directory itself; checkPermissions holds it to the
			// stricter rule (the cache's user owns it, no one else writes).
			return nil
		}
		if err := check(next, info); err != nil {
			return err
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			cur = next
			continue
		}
		if followed++; followed > maxLinks {
			return errors.Errorf("too many symbolic links resolving %s", dir)
		}
		dest, err := os.Readlink(next)
		if err != nil {
			return err
		}
		if filepath.IsAbs(dest) {
			cur = string(filepath.Separator)
		}
		pending = append(splitPath(dest), pending...)
	}
	return nil
}

// onlyTrivial reports whether the remaining components lead nowhere further.
func onlyTrivial(components []string) bool {
	for _, c := range components {
		if c != "" && c != "." {
			return false
		}
	}
	return true
}

// splitPath splits a path into its components.
func splitPath(p string) []string {
	return strings.Split(filepath.ToSlash(p), "/")
}
