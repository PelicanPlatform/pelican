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

// The afero.Fs face of a store.
//
// origin_serve already adapts any afero.Fs into a webdav.FileSystem and layers
// on Prometheus metrics, HTB rate limiting, multiuser wrapping, and directory
// pagination (origin_serve/filesystem.go).  Implementing afero.Fs is therefore
// all pstore needs to be servable, and this file is deliberately a thin
// translation over Store rather than a second implementation of anything.
//
// Where POSIX semantics and object-store semantics disagree, pstore follows
// what WebDAV and the Pelican client actually exercise: no chmod, no chown, no
// symlinks, no truncate of an existing object, and no writing at an offset.

package pstore

import (
	"context"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/afero"
	"golang.org/x/net/webdav"
)

// FS adapts a Store to afero.Fs.
type FS struct {
	store *Store
}

// Ensure the adapter really satisfies the interfaces the origin needs.
var (
	_ afero.Fs   = (*FS)(nil)
	_ afero.File = (*file)(nil)
)

// NewFS returns an afero.Fs backed by the store.
func NewFS(s *Store) *FS { return &FS{store: s} }

// Name identifies the filesystem in afero diagnostics.
func (fs *FS) Name() string { return "pstore" }

// Create makes (or replaces) an object and returns it open for writing,
// creating any missing parent directories.
//
// Auto-creating parents is what lets a client PUT into a prefix that does not
// exist yet, which is how uploads normally arrive -- no explicit MKCOL. The
// origin has a shared afero wrapper that does this, but it derives the parent
// with filepath, and a pstore path is a namespace path that is always
// slash-separated: on Windows the wrapper would ask for a directory literally
// named "\a\b\c". Doing it here keeps the separator right on every platform.
func (fs *FS) Create(name string) (afero.File, error) {
	w, err := fs.createWithParents(name)
	if err != nil {
		return nil, pathError("create", name, err)
	}
	return &file{fs: fs, name: name, w: w}, nil
}

// createWithParents opens a write handle, creating missing parents on the
// first attempt that reports the parent absent.
func (fs *FS) createWithParents(name string) (*WriteHandle, error) {
	return fs.createSizedWithParents(name, -1)
}

// createSizedWithParents is createWithParents with an optional size hint.
func (fs *FS) createSizedWithParents(name string, size int64) (*WriteHandle, error) {
	open := func() (*WriteHandle, error) {
		if size >= 0 {
			return fs.store.CreateSized(name, size)
		}
		return fs.store.Create(name)
	}

	w, err := open()
	if err == nil || !errors.Is(err, ErrNotExist) {
		return w, err
	}

	parent := path.Dir(name)
	if parent == "." || parent == "/" || parent == "" {
		return nil, err
	}
	if mkErr := fs.store.MkdirAll(parent); mkErr != nil {
		// Report why the create failed, not why the recovery did, unless the
		// recovery hit something meaningfully different.
		if errors.Is(mkErr, ErrDraining) || errors.Is(mkErr, ErrNotDir) {
			return nil, mkErr
		}
		return nil, err
	}
	return open()
}

// Mkdir creates a directory.  perm is ignored: pstore has no per-entry
// permissions, since access control is the origin's authorization layer.
func (fs *FS) Mkdir(name string, _ os.FileMode) error {
	return pathError("mkdir", name, fs.store.Mkdir(name))
}

// MkdirAll creates a directory and any missing ancestors.
func (fs *FS) MkdirAll(path string, _ os.FileMode) error {
	return pathError("mkdir", path, fs.store.MkdirAll(path))
}

// Open opens an object or directory for reading.
func (fs *FS) Open(name string) (afero.File, error) {
	return fs.OpenFile(name, os.O_RDONLY, 0)
}

// OpenFile opens a path with the given flags.
//
// Objects are immutable, so the write flags all mean the same thing: build a
// new version and swap it in at Close.  O_APPEND is refused rather than
// silently truncating, since there is no way to honor it.
func (fs *FS) OpenFile(name string, flag int, _ os.FileMode) (afero.File, error) {
	writing := flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC|os.O_APPEND) != 0

	if !writing {
		// Try the object first.  Opening a file is the common case by a wide
		// margin, and OpenRead already resolves the entry, so leading with
		// Stat would cost every read an extra lookup to answer a question
		// OpenRead has to answer anyway.  A directory reports ErrIsDir, which
		// is the one case that needs the second lookup.
		r, err := fs.store.OpenRead(name)
		if err == nil {
			return &file{fs: fs, name: name, r: r}, nil
		}
		if !errors.Is(err, ErrIsDir) {
			return nil, pathError("open", name, err)
		}
		d, sErr := fs.store.Stat(name)
		if sErr != nil {
			return nil, pathError("open", name, sErr)
		}
		return &file{fs: fs, name: name, dir: d}, nil
	}

	if flag&os.O_APPEND != 0 {
		// Appending would require reading the existing object back and
		// rewriting it, which is not what any Pelican caller wants.
		return nil, pathError("open", name, ErrNotSupported)
	}
	if flag&os.O_EXCL != 0 && flag&os.O_CREATE != 0 {
		w, err := fs.createWithParents(name)
		if err != nil {
			return nil, pathError("open", name, err)
		}
		w.RequireAbsent()
		return &file{fs: fs, name: name, w: w}, nil
	}
	return fs.Create(name)
}

// OpenFileSized is OpenFile with the object's expected length, which lets the
// write path pick its storage tier immediately instead of buffering to
// discover it.  It implements origin_serve's size-hint interface.
//
// The size is advisory: the object is stored at whatever length actually
// arrives, so a wrong or absent hint costs nothing but the buffering it would
// have avoided.
func (fs *FS) OpenFileSized(name string, flag int, perm os.FileMode, size int64) (afero.File, error) {
	writing := flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC|os.O_APPEND) != 0
	if !writing || size < 0 {
		return fs.OpenFile(name, flag, perm)
	}
	if flag&os.O_APPEND != 0 {
		return nil, pathError("open", name, ErrNotSupported)
	}

	w, err := fs.createSizedWithParents(name, size)
	if err != nil {
		return nil, pathError("open", name, err)
	}
	if flag&os.O_EXCL != 0 && flag&os.O_CREATE != 0 {
		w.RequireAbsent()
	}
	return &file{fs: fs, name: name, w: w}, nil
}

// OpenFileConditional is OpenFileSized with an HTTP conditional-write
// precondition attached, implementing origin_serve's ConditionalWriteFs.
//
// The precondition is enforced by Close, inside the single transaction that
// resolves the existing entry and installs the new one, which is the only
// place it can be enforced without a race.  Checking it here, at open time,
// would be exactly the stat-then-write the caller is trying to avoid: two
// concurrent "If-None-Match: *" PUTs would both find the path absent and both
// commit.
//
// requireETag carries the client's entity tag verbatim; an object's tag is its
// generation, so the tag is unwrapped rather than compared as a string.
func (fs *FS) OpenFileConditional(name string, flag int, perm os.FileMode, size int64,
	requireAbsent bool, requireETag string) (afero.File, error) {
	f, err := fs.OpenFileSized(name, flag, perm, size)
	if err != nil {
		return nil, err
	}
	pf, ok := f.(*file)
	if !ok || pf.w == nil {
		// Not a write; there is nothing to make conditional.
		return f, nil
	}
	if requireAbsent {
		pf.w.RequireAbsent()
	}
	if gen := generationFromETag(requireETag); gen != "" {
		pf.w.RequireGeneration(gen)
	}
	return f, nil
}

// generationFromETag recovers the generation an entity tag was minted from, so
// that a client's If-Match can be enforced against the index.  It is the
// inverse of etagFor, tolerant of the weak-comparison prefix a proxy may add.
func generationFromETag(tag string) string {
	tag = strings.TrimSpace(tag)
	tag = strings.TrimPrefix(tag, "W/")
	return strings.Trim(tag, `"`)
}

// Remove deletes an object, or an empty directory.
func (fs *FS) Remove(name string) error {
	return pathError("remove", name, fs.store.Remove(name))
}

// RemoveAll deletes a path and everything beneath it.
func (fs *FS) RemoveAll(path string) error {
	return pathError("removeall", path, fs.store.RemoveAll(path))
}

// Rename moves an entry.
func (fs *FS) Rename(oldname, newname string) error {
	if err := fs.store.Rename(oldname, newname); err != nil {
		return &os.LinkError{Op: "rename", Old: oldname, New: newname, Err: err}
	}
	return nil
}

// Stat returns file information for a path.
func (fs *FS) Stat(name string) (os.FileInfo, error) {
	d, err := fs.store.Stat(name)
	if err != nil {
		return nil, pathError("stat", name, err)
	}
	return newFileInfo(baseName(name), d), nil
}

// Chmod is not supported: pstore stores no per-entry permissions.
func (fs *FS) Chmod(name string, _ os.FileMode) error {
	return pathError("chmod", name, ErrNotSupported)
}

// Chown is not supported: pstore stores no per-entry ownership.
func (fs *FS) Chown(name string, _, _ int) error {
	return pathError("chown", name, ErrNotSupported)
}

// Chtimes is not supported: an object's mtime is set when its version is
// committed.
func (fs *FS) Chtimes(name string, _, _ time.Time) error {
	return pathError("chtimes", name, ErrNotSupported)
}

// ---------------------------------------------------------------------------
// File handles
// ---------------------------------------------------------------------------

// file is an open object or directory.  Exactly one of r, w, or dir is set.
type file struct {
	fs   *FS
	name string

	r   *ReadHandle
	w   *WriteHandle
	dir *Dirent

	// dirCursor is the last name handed to the caller, so the next Readdir
	// page resumes from the index rather than from a buffered slice.
	dirCursor string
	// dirDone records that the index is exhausted, so further calls report
	// EOF without rescanning.
	dirDone bool

	// writeErr is sticky: once the data destined for this object is known to
	// be incomplete, Close must discard the pending version rather than
	// install it.  See AbortWrite.
	writeErr error
	// writeMu guards writeErr, which is set from the goroutine reading the
	// request body as well as from Write.
	writeMu sync.Mutex

	closed bool
}

// Name returns the path the handle was opened with.
func (f *file) Name() string { return f.name }

// AbortWrite records that the bytes written so far do not make up the whole
// object, so that Close discards the pending version instead of installing it.
//
// It exists because the caller that discovers the failure is not the caller
// that closes the handle.  golang.org/x/net/webdav's handlePut does
//
//	_, copyErr := io.Copy(f, r.Body)
//	fi, statErr := f.Stat()
//	closeErr := f.Close()
//	if copyErr != nil { return http.StatusMethodNotAllowed, copyErr }
//
// -- Close runs before copyErr is ever looked at.  Since a pstore write builds
// a complete new version and swaps it in at Close, a client that disconnects
// partway through an overwrite would otherwise have its truncated body
// committed over a good object, on a store that is very likely the only copy
// of the data.  The origin wraps the request body so a read failure lands here
// first (see origin_serve's writeGuard).
func (f *file) AbortWrite(err error) {
	if f.w == nil {
		return
	}
	if err == nil {
		err = errors.New("the write was aborted before it completed")
	}
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	if f.writeErr == nil {
		f.writeErr = err
	}
}

// failedWrite returns the sticky write error, if any.
func (f *file) failedWrite() error {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	return f.writeErr
}

// Close releases the handle.  For a write handle this is where the new
// version is committed -- unless the data is known to be incomplete, in which
// case the pending version is discarded and the previous one survives
// untouched.
func (f *file) Close() error {
	if f.closed {
		return pathError("close", f.name, ErrClosed)
	}
	f.closed = true

	switch {
	case f.w != nil:
		if failed := f.failedWrite(); failed != nil {
			// Abort, not Close: installing a truncated version is silent data
			// loss, and the object's previous version is still correct.
			_ = f.w.Abort()
			return pathError("close", f.name, failed)
		}
		return pathError("close", f.name, f.w.Close())
	case f.r != nil:
		return pathError("close", f.name, f.r.Close())
	default:
		return nil
	}
}

func (f *file) Read(p []byte) (int, error) {
	if f.r == nil {
		return 0, pathError("read", f.name, badMode(f))
	}
	return f.r.Read(p)
}

func (f *file) ReadAt(p []byte, off int64) (int, error) {
	if f.r == nil {
		return 0, pathError("read", f.name, badMode(f))
	}
	return f.r.ReadAt(p, off)
}

func (f *file) Seek(offset int64, whence int) (int64, error) {
	if f.r == nil {
		// Seeking a write handle would imply a partial update.
		return 0, pathError("seek", f.name, ErrNotSupported)
	}
	return f.r.Seek(offset, whence)
}

func (f *file) Write(p []byte) (int, error) {
	if f.w == nil {
		return 0, pathError("write", f.name, badMode(f))
	}
	n, err := f.w.Write(p)
	if err != nil {
		// A refused write (the store is full, the block layer failed) leaves
		// the object short.  Remember it so Close cannot install the fragment
		// over a complete previous version.
		f.AbortWrite(err)
	}
	return n, err
}

// WriteAt is refused: objects are immutable and written sequentially.
//
// The refusal is recorded, because a caller that meant to write at an offset
// and was told no has not produced the object it intended; committing the
// sequential prefix it happened to write first would be worse than failing.
func (f *file) WriteAt([]byte, int64) (int, error) {
	err := pathError("write", f.name, ErrNotSupported)
	f.AbortWrite(err)
	return 0, err
}

func (f *file) WriteString(s string) (int, error) { return f.Write([]byte(s)) }

// Truncate supports exactly one case: truncating a freshly created,
// not-yet-written object to zero.
//
// That is how a zero-length file gets created through several ordinary code
// paths (afero.WriteFile with empty content, `: > file` semantics), and it
// costs nothing because a pending write is already empty.  Any other target
// length, or truncating after bytes have been written, would be a partial
// update, which objects here do not support.
func (f *file) Truncate(size int64) error {
	if f.w == nil {
		return pathError("truncate", f.name, badMode(f))
	}
	if size != 0 || f.w.Size() != 0 {
		return pathError("truncate", f.name, ErrNotSupported)
	}
	return nil
}

// Sync is a no-op: a version is durable once Close commits it.
func (f *file) Sync() error { return nil }

// Stat returns information about the open handle.
//
// For a write handle this reports the *pending* version rather than looking
// the path up, which matters more than it sounds: objects are immutable and
// the new version is only installed at Close, so the path may not exist yet or
// may still hold the previous version. webdav.handlePut stats the file before
// closing it and turns any error into 405 Method Not Allowed, so consulting
// the namespace here makes every create fail with a status that says the
// method is unsupported. An os.File would stat the open file, not the path;
// so does this.
func (f *file) Stat() (os.FileInfo, error) {
	switch {
	case f.dir != nil:
		return newFileInfo(baseName(f.name), f.dir), nil
	case f.r != nil:
		return newFileInfo(baseName(f.name), f.r.Dirent()), nil
	case f.w != nil:
		return newFileInfo(baseName(f.name), &Dirent{
			Type:       EntryFile,
			Generation: f.w.Generation(),
			Size:       f.w.Size(),
			MTimeNanos: time.Now().UnixNano(),
			Mode:       uint32(defaultFileMode),
		}), nil
	default:
		return f.fs.Stat(f.name)
	}
}

// Readdir returns directory entries, in name order.
//
// It follows the os.File contract: a positive count returns at most that many
// entries and io.EOF once exhausted, while count <= 0 returns everything
// remaining.
//
// A positive count is served straight from the index, one page per call,
// resuming from the last name returned.  Nothing is buffered, so a directory
// with a hundred thousand entries costs the caller only what it actually
// reads.  count <= 0 is materialized because the contract demands the whole
// remainder in one slice; callers that cannot afford that should paginate.
//
// The listing is not a snapshot: a concurrent write between pages will be
// seen if it sorts after the resume point, and missed if before.  That
// matches what a POSIX directory read gives and is what the WebDAV layer
// already assumes.
func (f *file) Readdir(count int) ([]os.FileInfo, error) {
	if f.dir == nil {
		return nil, pathError("readdir", f.name, ErrNotDir)
	}

	if count <= 0 {
		// os.File returns the remainder and a nil error, never io.EOF, for a
		// non-positive count -- including when the remainder is empty because
		// paginated calls already drained the handle.
		if f.dirDone {
			return []os.FileInfo{}, nil
		}
		entries, _, err := f.fs.store.List(f.name, f.dirCursor, 0)
		if err != nil {
			return nil, pathError("readdir", f.name, err)
		}
		f.dirDone = true
		if len(entries) > 0 {
			f.dirCursor = entries[len(entries)-1].Name
		}
		return toFileInfos(entries), nil
	}

	if f.dirDone {
		return nil, io.EOF
	}
	entries, more, err := f.fs.store.List(f.name, f.dirCursor, count)
	if err != nil {
		return nil, pathError("readdir", f.name, err)
	}
	if len(entries) == 0 {
		f.dirDone = true
		return nil, io.EOF
	}
	f.dirCursor = entries[len(entries)-1].Name
	if !more {
		// Remember that the index is exhausted so the next call reports EOF
		// without another scan.
		f.dirDone = true
	}
	return toFileInfos(entries), nil
}

// toFileInfos adapts a page of index entries for the caller.
func toFileInfos(entries []ListEntry) []os.FileInfo {
	infos := make([]os.FileInfo, 0, len(entries))
	for _, e := range entries {
		infos = append(infos, newFileInfo(e.Name, e.Dirent))
	}
	return infos
}

// Readdirnames returns the names of directory entries.
func (f *file) Readdirnames(n int) ([]string, error) {
	infos, err := f.Readdir(n)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(infos))
	for i, fi := range infos {
		names[i] = fi.Name()
	}
	return names, nil
}

// badMode reports the error for using a handle in the wrong direction.
func badMode(f *file) error {
	if f.dir != nil {
		return ErrIsDir
	}
	return ErrNotSupported
}

// ---------------------------------------------------------------------------
// FileInfo
// ---------------------------------------------------------------------------

// fileInfo adapts a dirent to os.FileInfo.
//
// What it carries is exactly what the directory entry carries: size, mode,
// modification time, and -- through ETag below and Sys() -- the object's
// generation.  That is deliberate, because a listing must not cost one
// metadata read per entry.
//
// Two things are therefore absent.  Access time lives on the object's
// metadata and is available via Store.AccessTime.  There is no separate
// creation time: objects are immutable, so a version's modification time is
// when that version was created.
type fileInfo struct {
	name   string
	dirent *Dirent
}

func newFileInfo(name string, d *Dirent) os.FileInfo {
	return &fileInfo{name: name, dirent: d}
}

func (fi *fileInfo) Name() string { return fi.name }

func (fi *fileInfo) Size() int64 {
	if fi.dirent.IsDir() {
		return 0
	}
	return fi.dirent.Size
}

func (fi *fileInfo) Mode() os.FileMode {
	if fi.dirent.IsDir() {
		return os.ModeDir | os.FileMode(fi.dirent.Mode).Perm()
	}
	return os.FileMode(fi.dirent.Mode).Perm()
}

func (fi *fileInfo) ModTime() time.Time { return time.Unix(0, fi.dirent.MTimeNanos) }
func (fi *fileInfo) IsDir() bool        { return fi.dirent.IsDir() }
func (fi *fileInfo) Sys() any           { return fi.dirent }

// ETag implements webdav.ETager so the handler advertises the object's
// generation rather than its default size-and-mtime approximation.  The
// generation is a strong validator minted per write, which is exactly what an
// entity tag should be.
//
// Directories have no generation, so they fall back to the handler's default.
func (fi *fileInfo) ETag(_ context.Context) (string, error) {
	if fi.dirent.IsDir() || fi.dirent.Generation == "" {
		return "", webdav.ErrNotImplemented
	}
	return etagFor(fi.dirent.Generation), nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// pathError wraps err in *os.PathError so callers can use errors.Is against
// the fs sentinels, which is what afero and the WebDAV handler expect.
func pathError(op, name string, err error) error {
	if err == nil {
		return nil
	}
	return &os.PathError{Op: op, Path: name, Err: errors.Cause(err)}
}

// baseName returns the final component of a path, for FileInfo.Name.
func baseName(name string) string {
	cleaned, err := cleanRelative(name)
	if err != nil {
		return name
	}
	if isRootPath(cleaned) {
		return "/"
	}
	_, base := splitPath(cleaned)
	return base
}
