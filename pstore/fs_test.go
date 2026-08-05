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

package pstore

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"testing"

	"github.com/pkg/errors"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/webdav"
)

func newTestFS(t *testing.T) *FS {
	t.Helper()
	return NewFS(newTestStore(t))
}

func TestFSWriteReadThroughAfero(t *testing.T) {
	fsys := newTestFS(t)

	content := []byte("hello pstore")
	require.NoError(t, afero.WriteFile(fsys, "/greeting", content, 0644))

	got, err := afero.ReadFile(fsys, "/greeting")
	require.NoError(t, err)
	assert.Equal(t, content, got)

	exists, err := afero.Exists(fsys, "/greeting")
	require.NoError(t, err)
	assert.True(t, exists)
}

// TestFSLargeFileThroughAfero pushes past the spill threshold so the streaming
// tier is exercised through the adapter rather than the store API directly.
func TestFSLargeFileThroughAfero(t *testing.T) {
	fsys := newTestFS(t)

	content := randomBytes(spillThreshold+(1<<20), 42)
	require.NoError(t, afero.WriteFile(fsys, "/big.bin", content, 0644))

	got, err := afero.ReadFile(fsys, "/big.bin")
	require.NoError(t, err)
	assert.True(t, bytes.Equal(content, got))
}

func TestFSStat(t *testing.T) {
	fsys := newTestFS(t)

	require.NoError(t, fsys.MkdirAll("/d", 0755))
	require.NoError(t, afero.WriteFile(fsys, "/d/f", []byte("12345"), 0644))

	fi, err := fsys.Stat("/d/f")
	require.NoError(t, err)
	assert.Equal(t, "f", fi.Name(), "Name is the final component, not the full path")
	assert.Equal(t, int64(5), fi.Size())
	assert.False(t, fi.IsDir())
	assert.False(t, fi.ModTime().IsZero())

	di, err := fsys.Stat("/d")
	require.NoError(t, err)
	assert.True(t, di.IsDir())
	assert.True(t, di.Mode().IsDir())
}

// TestFSStatErrorsAreRecognizable matters because the WebDAV handler and afero
// both branch on os.IsNotExist and errors.Is against the fs sentinels.
func TestFSStatErrorsAreRecognizable(t *testing.T) {
	fsys := newTestFS(t)

	_, err := fsys.Stat("/nope")
	require.Error(t, err)
	assert.True(t, os.IsNotExist(err), "os.IsNotExist must recognize the error")
	assert.ErrorIs(t, err, fs.ErrNotExist)

	var pathErr *os.PathError
	assert.ErrorAs(t, err, &pathErr, "errors are wrapped as *os.PathError")
	assert.Equal(t, "stat", pathErr.Op)
	assert.Equal(t, "/nope", pathErr.Path)
}

// TestFSETag checks the webdav.ETager contract: objects advertise their
// generation, directories defer to the handler's default.
func TestFSETag(t *testing.T) {
	fsys := newTestFS(t)

	require.NoError(t, afero.WriteFile(fsys, "/obj", []byte("x"), 0644))
	fi, err := fsys.Stat("/obj")
	require.NoError(t, err)

	tagger, ok := fi.(webdav.ETager)
	require.True(t, ok, "FileInfo must implement webdav.ETager")

	tag, err := tagger.ETag(t.Context())
	require.NoError(t, err)
	assert.NotEmpty(t, tag)
	assert.True(t, bytes.HasPrefix([]byte(tag), []byte(`"`)), "a strong ETag is quoted")

	// A new version must produce a new tag.
	require.NoError(t, afero.WriteFile(fsys, "/obj", []byte("y"), 0644))
	fi2, err := fsys.Stat("/obj")
	require.NoError(t, err)
	tag2, err := fi2.(webdav.ETager).ETag(t.Context())
	require.NoError(t, err)
	assert.NotEqual(t, tag, tag2)

	require.NoError(t, fsys.Mkdir("/dir", 0755))
	di, err := fsys.Stat("/dir")
	require.NoError(t, err)
	_, err = di.(webdav.ETager).ETag(t.Context())
	assert.ErrorIs(t, err, webdav.ErrNotImplemented,
		"a directory falls back to the handler's default tag")
}

// TestFSReaddirContract pins the os.File semantics the WebDAV layer relies on:
// a positive count paginates and ends in io.EOF, count <= 0 drains.
func TestFSReaddirContract(t *testing.T) {
	fsys := newTestFS(t)

	require.NoError(t, fsys.MkdirAll("/d/sub", 0755))
	for _, n := range []string{"a", "b", "c"} {
		require.NoError(t, afero.WriteFile(fsys, "/d/"+n, []byte(n), 0644))
	}

	t.Run("paginated", func(t *testing.T) {
		f, err := fsys.Open("/d")
		require.NoError(t, err)
		defer f.Close()

		var names []string
		for {
			batch, rErr := f.Readdir(2)
			if rErr == io.EOF {
				break
			}
			require.NoError(t, rErr)
			for _, fi := range batch {
				names = append(names, fi.Name())
			}
		}
		assert.Equal(t, []string{"a", "b", "c", "sub"}, names, "sorted, all entries, once each")
	})

	t.Run("drain", func(t *testing.T) {
		f, err := fsys.Open("/d")
		require.NoError(t, err)
		defer f.Close()

		all, err := f.Readdir(-1)
		require.NoError(t, err)
		require.Len(t, all, 4)
		assert.Equal(t, "sub", all[3].Name())
		assert.True(t, all[3].IsDir())
	})
}

// TestFSReadDirViaAfero exercises the helper the origin's adapter actually
// calls (origin_serve/filesystem.go uses afero.ReadDir).
func TestFSReadDirViaAfero(t *testing.T) {
	fsys := newTestFS(t)

	require.NoError(t, fsys.Mkdir("/d", 0755))
	for _, n := range []string{"z", "a", "m"} {
		require.NoError(t, afero.WriteFile(fsys, "/d/"+n, []byte(n), 0644))
	}

	infos, err := afero.ReadDir(fsys, "/d")
	require.NoError(t, err)
	names := make([]string, len(infos))
	for i, fi := range infos {
		names[i] = fi.Name()
	}
	assert.Equal(t, []string{"a", "m", "z"}, names)
}

func TestFSReaddirOnFileFails(t *testing.T) {
	fsys := newTestFS(t)

	require.NoError(t, afero.WriteFile(fsys, "/f", []byte("x"), 0644))
	f, err := fsys.Open("/f")
	require.NoError(t, err)
	defer f.Close()

	_, err = f.Readdir(-1)
	assert.Error(t, err)
}

func TestFSWalk(t *testing.T) {
	fsys := newTestFS(t)

	require.NoError(t, fsys.MkdirAll("/tree/a/b", 0755))
	require.NoError(t, afero.WriteFile(fsys, "/tree/f1", []byte("1"), 0644))
	require.NoError(t, afero.WriteFile(fsys, "/tree/a/b/f2", []byte("2"), 0644))

	// Walked here rather than with afero.Walk, which builds child paths with
	// filepath.Join and so hands a backslash-separated path to a namespace
	// that only knows "/".  The origin's adapter joins with path.Join, so
	// production never takes that route.
	var seen []string
	var walk func(string)
	walk = func(dir string) {
		seen = append(seen, dir)
		entries, err := afero.ReadDir(fsys, dir)
		require.NoError(t, err)
		for _, e := range entries {
			child := dir + "/" + e.Name()
			if dir == "/" {
				child = "/" + e.Name()
			}
			if e.IsDir() {
				walk(child)
				continue
			}
			seen = append(seen, child)
		}
	}
	walk("/tree")

	assert.Equal(t, []string{"/tree", "/tree/a", "/tree/a/b", "/tree/a/b/f2", "/tree/f1"}, seen)
}

func TestFSSeekAndReadAt(t *testing.T) {
	fsys := newTestFS(t)

	content := []byte("0123456789")
	require.NoError(t, afero.WriteFile(fsys, "/f", content, 0644))

	f, err := fsys.Open("/f")
	require.NoError(t, err)
	defer f.Close()

	off, err := f.Seek(4, io.SeekStart)
	require.NoError(t, err)
	assert.Equal(t, int64(4), off)

	rest, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, "456789", string(rest))

	buf := make([]byte, 3)
	n, err := f.ReadAt(buf, 2)
	require.NoError(t, err)
	assert.Equal(t, 3, n)
	assert.Equal(t, "234", string(buf))
}

// TestFSOpenFileExclusive covers O_CREATE|O_EXCL, which maps onto the store's
// create-only precondition.
func TestFSOpenFileExclusive(t *testing.T) {
	fsys := newTestFS(t)

	f, err := fsys.OpenFile("/excl", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	require.NoError(t, err)
	_, err = f.Write([]byte("first"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	f2, err := fsys.OpenFile("/excl", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	require.NoError(t, err, "the conflict surfaces at Close, when the swap is attempted")
	_, err = f2.Write([]byte("second"))
	require.NoError(t, err)
	assert.ErrorIs(t, f2.Close(), fs.ErrExist)

	got, err := afero.ReadFile(fsys, "/excl")
	require.NoError(t, err)
	assert.Equal(t, "first", string(got))
}

// TestFSUnsupportedOperations documents the POSIX surface pstore declines,
// rather than pretending to implement it.
func TestFSUnsupportedOperations(t *testing.T) {
	fsys := newTestFS(t)

	require.NoError(t, afero.WriteFile(fsys, "/f", []byte("x"), 0644))

	assert.Error(t, fsys.Chmod("/f", 0600))
	assert.Error(t, fsys.Chown("/f", 0, 0))

	_, err := fsys.OpenFile("/f", os.O_WRONLY|os.O_APPEND, 0644)
	assert.Error(t, err, "appending would require rewriting the object")

	f, err := fsys.Create("/g")
	require.NoError(t, err)
	defer f.Close()
	_, err = f.WriteAt([]byte("x"), 5)
	assert.Error(t, err, "objects are written sequentially")
	_, err = f.Seek(0, io.SeekStart)
	assert.Error(t, err, "seeking a write handle would imply a partial update")
	assert.Error(t, f.Truncate(10), "truncating to a nonzero length is a partial update")
}

func TestFSRemoveAndRename(t *testing.T) {
	fsys := newTestFS(t)

	require.NoError(t, fsys.MkdirAll("/a/b", 0755))
	require.NoError(t, afero.WriteFile(fsys, "/a/b/f", []byte("data"), 0644))

	require.NoError(t, fsys.Rename("/a/b/f", "/a/moved"))
	got, err := afero.ReadFile(fsys, "/a/moved")
	require.NoError(t, err)
	assert.Equal(t, "data", string(got))

	require.NoError(t, fsys.Remove("/a/moved"))
	exists, err := afero.Exists(fsys, "/a/moved")
	require.NoError(t, err)
	assert.False(t, exists)

	require.NoError(t, fsys.RemoveAll("/a"))
	exists, err = afero.Exists(fsys, "/a")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestFSRenameErrorIsLinkError(t *testing.T) {
	fsys := newTestFS(t)

	err := fsys.Rename("/missing", "/dest")
	require.Error(t, err)
	var linkErr *os.LinkError
	assert.ErrorAs(t, err, &linkErr)
	assert.Equal(t, "rename", linkErr.Op)
}

// TestFSDirectoryWriteConflict covers the case the origin's adapter has a
// specific workaround for: a PUT aimed at an existing collection.
func TestFSDirectoryWriteConflict(t *testing.T) {
	fsys := newTestFS(t)

	require.NoError(t, fsys.Mkdir("/d", 0755))
	_, err := fsys.Create("/d")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrIsDir)
}

// TestFSStatOnOpenWriteHandle pins the behavior that webdav.handlePut
// depends on: it calls Stat between the last Write and Close.
//
// Under commit-at-close the object is not at its path yet, so consulting the
// namespace here fails -- and the handler turns any stat error into 405
// Method Not Allowed, which makes every create look like an unsupported
// method. An os.File stats the open file rather than the path; so must this.
func TestFSStatOnOpenWriteHandle(t *testing.T) {
	fsys := newTestFS(t)

	f, err := fsys.Create("/pending.txt")
	require.NoError(t, err)

	_, err = f.Write([]byte("twelve bytes"))
	require.NoError(t, err)

	// The path does not resolve yet...
	_, err = fsys.Stat("/pending.txt")
	assert.True(t, os.IsNotExist(err), "the object is not installed until Close")

	// ...but the handle still describes what is being written.
	fi, err := f.Stat()
	require.NoError(t, err, "stat on an open write handle must not consult the namespace")
	assert.Equal(t, int64(12), fi.Size())
	assert.False(t, fi.IsDir())
	assert.Equal(t, "pending.txt", fi.Name())

	require.NoError(t, f.Close())

	after, err := fsys.Stat("/pending.txt")
	require.NoError(t, err)
	assert.Equal(t, int64(12), after.Size())
}

// TestFSStatOnOverwriteHandleShowsPendingVersion is the same hazard for an
// overwrite: the path resolves, but to the *old* version, so reporting it
// would tell the handler the wrong size for the object it just wrote.
func TestFSStatOnOverwriteHandleShowsPendingVersion(t *testing.T) {
	fsys := newTestFS(t)

	require.NoError(t, afero.WriteFile(fsys, "/obj.txt", []byte("original-content"), 0644))

	f, err := fsys.Create("/obj.txt")
	require.NoError(t, err)
	_, err = f.Write([]byte("new"))
	require.NoError(t, err)

	fi, err := f.Stat()
	require.NoError(t, err)
	assert.Equal(t, int64(3), fi.Size(), "the handle reports the pending version, not the old one")

	require.NoError(t, f.Close())
}

// TestFSTruncateCreatesEmptyFile covers the one truncate that is meaningful
// here.  Several ordinary paths create a zero-length file by truncating a
// freshly opened handle, and a pending write is already empty, so this costs
// nothing and avoids failing writes that should obviously work.
func TestFSTruncateCreatesEmptyFile(t *testing.T) {
	fsys := newTestFS(t)

	f, err := fsys.Create("/empty.txt")
	require.NoError(t, err)
	require.NoError(t, f.Truncate(0), "truncating an unwritten handle to zero is allowed")
	require.NoError(t, f.Close())

	fi, err := fsys.Stat("/empty.txt")
	require.NoError(t, err)
	assert.Zero(t, fi.Size())

	// afero.WriteFile with empty content goes through this path.
	require.NoError(t, afero.WriteFile(fsys, "/empty2.txt", nil, 0644))
	fi2, err := fsys.Stat("/empty2.txt")
	require.NoError(t, err)
	assert.Zero(t, fi2.Size())
}

func TestFSTruncateAfterWriteIsRefused(t *testing.T) {
	fsys := newTestFS(t)

	f, err := fsys.Create("/written.txt")
	require.NoError(t, err)
	defer f.Close()
	_, err = f.Write([]byte("content"))
	require.NoError(t, err)

	assert.Error(t, f.Truncate(0),
		"discarding bytes already written would be a partial update")
}

// TestFSReaddirPaginatesWithoutBuffering is the property that matters for
// large directories: each page is served from the index, so a caller reading
// the first page of a 100k-entry directory does not pay for the other 99k.
func TestFSReaddirPaginatesWithoutBuffering(t *testing.T) {
	fsys := newTestFS(t)

	require.NoError(t, fsys.Mkdir("/big", 0755))
	const total = 250
	for i := range total {
		name := fmt.Sprintf("/big/f%04d", i)
		require.NoError(t, afero.WriteFile(fsys, name, []byte("x"), 0644))
	}

	f, err := fsys.Open("/big")
	require.NoError(t, err)
	defer f.Close()

	var names []string
	pages := 0
	for {
		batch, rErr := f.Readdir(40)
		if rErr == io.EOF {
			break
		}
		require.NoError(t, rErr)
		require.NotEmpty(t, batch, "a non-EOF page must not be empty")
		pages++
		for _, fi := range batch {
			names = append(names, fi.Name())
		}
	}

	require.Len(t, names, total, "every entry is returned exactly once")
	assert.Greater(t, pages, 1, "a directory this size takes several pages")
	assert.True(t, sort.StringsAreSorted(names), "pages continue in name order")
	assert.Equal(t, "f0000", names[0])
	assert.Equal(t, "f0249", names[total-1])
}

// TestFSReaddirDrainAfterPartialPage checks that count <= 0 resumes from the
// cursor rather than restarting, which is what os.File does.
func TestFSReaddirDrainAfterPartialPage(t *testing.T) {
	fsys := newTestFS(t)

	require.NoError(t, fsys.Mkdir("/d", 0755))
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		require.NoError(t, afero.WriteFile(fsys, "/d/"+n, []byte(n), 0644))
	}

	f, err := fsys.Open("/d")
	require.NoError(t, err)
	defer f.Close()

	first, err := f.Readdir(2)
	require.NoError(t, err)
	require.Len(t, first, 2)

	rest, err := f.Readdir(-1)
	require.NoError(t, err)
	assert.Len(t, rest, 3, "the drain returns only what is left")
	assert.Equal(t, "c", rest[0].Name())

	_, err = f.Readdir(1)
	assert.ErrorIs(t, err, io.EOF, "the handle is exhausted")
}

// TestFSReaddirEmptyDirectory pins the EOF behavior for a directory with no
// entries, which the paginated path has to get right on the first call.
func TestFSReaddirEmptyDirectory(t *testing.T) {
	fsys := newTestFS(t)
	require.NoError(t, fsys.Mkdir("/empty", 0755))

	f, err := fsys.Open("/empty")
	require.NoError(t, err)
	defer f.Close()

	all, err := f.Readdir(-1)
	require.NoError(t, err)
	assert.Empty(t, all)

	f2, err := fsys.Open("/empty")
	require.NoError(t, err)
	defer f2.Close()
	_, err = f2.Readdir(10)
	assert.ErrorIs(t, err, io.EOF)
}

// TestFSCreateParentsUsesNamespaceSeparator guards the other half of the same
// class of bug.  A pstore path is a namespace path and is always
// slash-separated, whatever the host filesystem uses, so deriving a parent
// with filepath would ask for a directory named "\a\b\c" on Windows and
// quietly fail every upload into a fresh prefix.
func TestFSCreateParentsUsesNamespaceSeparator(t *testing.T) {
	fsys := newTestFS(t)

	require.NoError(t, afero.WriteFile(fsys, "/a/b/c/deep.txt", []byte("deep"), 0644))

	// Each level exists as a real directory, not one literally named "a/b/c".
	for _, dir := range []string{"/a", "/a/b", "/a/b/c"} {
		fi, err := fsys.Stat(dir)
		require.NoError(t, err, "%s should have been created", dir)
		assert.True(t, fi.IsDir())
	}

	entries, err := afero.ReadDir(fsys, "/")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "a", entries[0].Name(),
		"the root holds one directory, not a single oddly-named entry")

	got, err := afero.ReadFile(fsys, "/a/b/c/deep.txt")
	require.NoError(t, err)
	assert.Equal(t, "deep", string(got))
}

// TestFSReaddirDrainAfterExhaustion pins the os.File contract for a
// non-positive count.
//
// The dirDone short-circuit has to sit below the count<=0 branch. Above it, a
// handle that paginated calls had already drained would answer a "give me the
// rest" call with io.EOF, and os.File never does that: n <= 0 returns whatever
// remains -- possibly nothing -- and a nil error. Callers that treat io.EOF as
// a failure (afero.Walk among them) would see a spurious error at the end of
// every directory they happened to read that way.
func TestFSReaddirDrainAfterExhaustion(t *testing.T) {
	fsys := newTestFS(t)

	require.NoError(t, fsys.Mkdir("/d", 0755))
	for _, n := range []string{"a", "b"} {
		require.NoError(t, afero.WriteFile(fsys, "/d/"+n, []byte(n), 0644))
	}

	f, err := fsys.Open("/d")
	require.NoError(t, err)
	defer f.Close()

	page, err := f.Readdir(2)
	require.NoError(t, err)
	require.Len(t, page, 2, "the paginated call drains the directory")

	rest, err := f.Readdir(-1)
	assert.NoError(t, err, "a non-positive count returns the remainder, never io.EOF")
	assert.Empty(t, rest)

	// A second drain is just as harmless, and a positive count still reports
	// exhaustion the way os.File does.
	rest, err = f.Readdir(0)
	assert.NoError(t, err)
	assert.Empty(t, rest)
	_, err = f.Readdir(1)
	assert.ErrorIs(t, err, io.EOF)
}

// TestFSAbortedWriteLeavesPreviousVersionIntact is the data-loss guarantee.
//
// golang.org/x/net/webdav's handlePut closes the file before it examines the
// error from io.Copy, and a pstore Close installs whatever bytes arrived. A
// client that disconnected halfway through an overwrite therefore replaced a
// complete object with a fragment. AbortWrite is how the layer that sees the
// failure tells the handle not to commit.
func TestFSAbortedWriteLeavesPreviousVersionIntact(t *testing.T) {
	fsys := newTestFS(t)

	const original = "THE COMPLETE ORIGINAL OBJECT"
	require.NoError(t, afero.WriteFile(fsys, "/obj", []byte(original), 0644))
	before, err := fsys.Stat("/obj")
	require.NoError(t, err)

	f, err := fsys.OpenFile("/obj", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	require.NoError(t, err)
	_, err = f.Write([]byte("PARTIAL"))
	require.NoError(t, err)

	aborter, ok := f.(interface{ AbortWrite(error) })
	require.True(t, ok, "a pstore write handle must be abortable")
	aborter.AbortWrite(errors.New("the client went away"))

	err = f.Close()
	require.Error(t, err, "Close must report the failure rather than commit a fragment")
	assert.Contains(t, err.Error(), "the client went away")

	got, err := afero.ReadFile(fsys, "/obj")
	require.NoError(t, err)
	assert.Equal(t, original, string(got), "the previous version's bytes must survive")

	after, err := fsys.Stat("/obj")
	require.NoError(t, err)
	assert.Equal(t, before.Sys().(*Dirent).Generation, after.Sys().(*Dirent).Generation,
		"and its generation, so a client's ETag is still valid")
}

// TestFSAbortedCreateLeavesNothingBehind covers the same path for a create
// rather than an overwrite: the object must not appear at all.
func TestFSAbortedCreateLeavesNothingBehind(t *testing.T) {
	fsys := newTestFS(t)

	f, err := fsys.Create("/fresh")
	require.NoError(t, err)
	_, err = f.Write([]byte("PARTIAL"))
	require.NoError(t, err)
	f.(interface{ AbortWrite(error) }).AbortWrite(errors.New("truncated upload"))
	require.Error(t, f.Close())

	_, err = fsys.Stat("/fresh")
	assert.True(t, os.IsNotExist(err), "an aborted create must not become visible")
}

// TestFSFailedWriteIsSticky covers the case AbortWrite cannot see: the write
// itself was refused, and Close runs anyway because webdav calls it before it
// looks at the copy error.
func TestFSFailedWriteIsSticky(t *testing.T) {
	fsys := newTestFS(t)

	const original = "v1 complete"
	require.NoError(t, afero.WriteFile(fsys, "/obj", []byte(original), 0644))

	f, err := fsys.OpenFile("/obj", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	require.NoError(t, err)
	_, err = f.Write([]byte("some bytes"))
	require.NoError(t, err)

	// WriteAt is always refused, which stands in for any mid-stream write
	// failure (an out-of-space store, a block-layer error).
	_, err = f.WriteAt([]byte("at an offset"), 4)
	require.Error(t, err)

	require.Error(t, f.Close(), "a handle whose write failed must not commit")

	got, err := afero.ReadFile(fsys, "/obj")
	require.NoError(t, err)
	assert.Equal(t, original, string(got))
}

// TestFSOpenFileConditional covers the store-side of a conditional write,
// which the origin reaches through origin_serve's ConditionalWriteFs.
func TestFSOpenFileConditional(t *testing.T) {
	fsys := newTestFS(t)

	t.Run("require absent", func(t *testing.T) {
		f, err := fsys.OpenFileConditional("/create-only", os.O_WRONLY|os.O_CREATE, 0644, -1, true, "")
		require.NoError(t, err)
		_, err = f.Write([]byte("first"))
		require.NoError(t, err)
		require.NoError(t, f.Close(), "the first create-only write wins")

		f2, err := fsys.OpenFileConditional("/create-only", os.O_WRONLY|os.O_CREATE, 0644, -1, true, "")
		require.NoError(t, err, "the condition is evaluated at commit, not at open")
		_, err = f2.Write([]byte("second"))
		require.NoError(t, err)
		assert.ErrorIs(t, f2.Close(), ErrExist)

		got, err := afero.ReadFile(fsys, "/create-only")
		require.NoError(t, err)
		assert.Equal(t, "first", string(got))
	})

	t.Run("require generation", func(t *testing.T) {
		require.NoError(t, afero.WriteFile(fsys, "/cas", []byte("v1"), 0644))
		info, err := fsys.Stat("/cas")
		require.NoError(t, err)
		tag, err := info.(webdav.ETager).ETag(context.Background())
		require.NoError(t, err)

		// Open against the tag we just read, then let someone else win.
		f, err := fsys.OpenFileConditional("/cas", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644, -1, false, tag)
		require.NoError(t, err)
		_, err = f.Write([]byte("v3"))
		require.NoError(t, err)
		require.NoError(t, afero.WriteFile(fsys, "/cas", []byte("v2"), 0644))

		assert.ErrorIs(t, f.Close(), ErrPreconditionFailed)

		got, err := afero.ReadFile(fsys, "/cas")
		require.NoError(t, err)
		assert.Equal(t, "v2", string(got), "the losing write installs nothing")
	})

	t.Run("matching generation commits", func(t *testing.T) {
		require.NoError(t, afero.WriteFile(fsys, "/cas2", []byte("v1"), 0644))
		info, err := fsys.Stat("/cas2")
		require.NoError(t, err)
		tag, err := info.(webdav.ETager).ETag(context.Background())
		require.NoError(t, err)

		f, err := fsys.OpenFileConditional("/cas2", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644, -1, false, tag)
		require.NoError(t, err)
		_, err = f.Write([]byte("v2"))
		require.NoError(t, err)
		require.NoError(t, f.Close())

		got, err := afero.ReadFile(fsys, "/cas2")
		require.NoError(t, err)
		assert.Equal(t, "v2", string(got))
	})
}

// TestGenerationFromETag pins the tag-to-generation unwrapping, including the
// weak prefix a proxy may add.
func TestGenerationFromETag(t *testing.T) {
	assert.Equal(t, "abc123", generationFromETag(`"abc123"`))
	assert.Equal(t, "abc123", generationFromETag(`W/"abc123"`))
	assert.Equal(t, "abc123", generationFromETag(`  "abc123" `))
	assert.Equal(t, "abc123", generationFromETag(`abc123`))
	assert.Empty(t, generationFromETag(""))
	assert.Equal(t, "gen", generationFromETag(etagFor("gen")))
}
