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
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gocloud.dev/blob"
	"gocloud.dev/blob/memblob"
)

// ---------------------------------------------------------------------------
// buildS3BlobURL unit tests
// ---------------------------------------------------------------------------

func TestBuildS3BlobURL(t *testing.T) {
	t.Run("FullOptions", func(t *testing.T) {
		url, err := buildS3BlobURL(BlobBackendOptions{
			Bucket:     "my-bucket",
			Region:     "us-west-2",
			ServiceURL: "https://s3.example.com",
			URLStyle:   "path",
		})
		require.NoError(t, err)
		assert.Contains(t, url, "s3://my-bucket")
		assert.Contains(t, url, "region=us-west-2")
		assert.Contains(t, url, "endpoint=")
		assert.Contains(t, url, "use_path_style=true")
	})

	t.Run("VirtualHostStyle", func(t *testing.T) {
		url, err := buildS3BlobURL(BlobBackendOptions{
			Bucket:   "my-bucket",
			Region:   "eu-central-1",
			URLStyle: "virtual",
		})
		require.NoError(t, err)
		assert.Contains(t, url, "s3://my-bucket")
		assert.NotContains(t, url, "use_path_style")
	})

	t.Run("DefaultStyleIsPath", func(t *testing.T) {
		url, err := buildS3BlobURL(BlobBackendOptions{
			Bucket: "my-bucket",
		})
		require.NoError(t, err)
		assert.Contains(t, url, "use_path_style=true")
	})

	t.Run("MissingBucket", func(t *testing.T) {
		_, err := buildS3BlobURL(BlobBackendOptions{
			Region: "us-east-1",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bucket name is required")
	})

	t.Run("MinimalOptions", func(t *testing.T) {
		url, err := buildS3BlobURL(BlobBackendOptions{
			Bucket: "test",
		})
		require.NoError(t, err)
		assert.Equal(t, "s3://test?use_path_style=true", url)
	})
}

// ---------------------------------------------------------------------------
// blobKey unit tests
// ---------------------------------------------------------------------------

func TestBlobKey(t *testing.T) {
	assert.Equal(t, "foo/bar", blobKey("/foo/bar"))
	assert.Equal(t, "foo", blobKey("/foo"))
	assert.Equal(t, "foo", blobKey("foo"))
	assert.Equal(t, "", blobKey("/"))
	assert.Equal(t, "", blobKey(""))
}

// ---------------------------------------------------------------------------
// loadS3Credentials unit tests
// ---------------------------------------------------------------------------

func TestLoadS3Credentials(t *testing.T) {
	t.Run("EmptyPaths", func(t *testing.T) {
		ak, sk, err := loadS3Credentials("", "")
		require.NoError(t, err)
		assert.Empty(t, ak)
		assert.Empty(t, sk)
	})

	t.Run("ValidFiles", func(t *testing.T) {
		dir := t.TempDir()
		akFile := dir + "/access_key"
		skFile := dir + "/secret_key"
		require.NoError(t, os.WriteFile(akFile, []byte("  AKID123  \n"), 0600))
		require.NoError(t, os.WriteFile(skFile, []byte("  SECRET456  \n"), 0600))

		ak, sk, err := loadS3Credentials(akFile, skFile)
		require.NoError(t, err)
		assert.Equal(t, "AKID123", ak)
		assert.Equal(t, "SECRET456", sk)
	})

	t.Run("MissingAccessKeyFile", func(t *testing.T) {
		dir := t.TempDir()
		skFile := dir + "/secret_key"
		require.NoError(t, os.WriteFile(skFile, []byte("SECRET"), 0600))

		_, _, err := loadS3Credentials(dir+"/nonexistent", skFile)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access key file")
	})

	t.Run("MissingSecretKeyFile", func(t *testing.T) {
		dir := t.TempDir()
		akFile := dir + "/access_key"
		require.NoError(t, os.WriteFile(akFile, []byte("AKID"), 0600))

		_, _, err := loadS3Credentials(akFile, dir+"/nonexistent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secret key file")
	})
}

// ---------------------------------------------------------------------------
// parseHTTPDate unit tests
// ---------------------------------------------------------------------------

func TestParseHTTPDate(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		ts := parseHTTPDate("Mon, 02 Jan 2006 15:04:05 GMT")
		assert.Equal(t, 2006, ts.Year())
		assert.Equal(t, 2, ts.Day())
	})

	t.Run("Invalid", func(t *testing.T) {
		ts := parseHTTPDate("not a date")
		assert.True(t, ts.IsZero())
	})

	t.Run("Empty", func(t *testing.T) {
		ts := parseHTTPDate("")
		assert.True(t, ts.IsZero())
	})
}

// ---------------------------------------------------------------------------
// blobFileSystem using memblob — comprehensive integration tests
// ---------------------------------------------------------------------------

func newMemBlobFS(t *testing.T) (*blobFileSystem, *blob.Bucket) {
	t.Helper()
	bucket := memblob.OpenBucket(nil)
	t.Cleanup(func() { bucket.Close() })
	return &blobFileSystem{bucket: bucket}, bucket
}

func TestBlobFileSystem_WriteAndRead(t *testing.T) {
	fs, _ := newMemBlobFS(t)
	ctx := context.Background()
	content := []byte("hello, blob world!")

	// Write a file
	wf, err := fs.OpenFile(ctx, "/data/greeting.txt", os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	n, err := wf.Write(content)
	require.NoError(t, err)
	assert.Equal(t, len(content), n)
	require.NoError(t, wf.Close())

	// Read it back
	rf, err := fs.OpenFile(ctx, "/data/greeting.txt", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer rf.Close()

	got, err := io.ReadAll(rf)
	require.NoError(t, err)
	assert.Equal(t, content, got)
}

func TestBlobFileSystem_WriteEmpty(t *testing.T) {
	fs, bucket := newMemBlobFS(t)
	ctx := context.Background()

	wf, err := fs.OpenFile(ctx, "/empty.txt", os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	// Close without writing — should create an empty object
	require.NoError(t, wf.Close())

	exists, err := bucket.Exists(ctx, "empty.txt")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestBlobFileSystem_ReadNonExistent(t *testing.T) {
	fs, _ := newMemBlobFS(t)
	ctx := context.Background()

	_, err := fs.OpenFile(ctx, "/does/not/exist.txt", os.O_RDONLY, 0)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestBlobFileSystem_Stat(t *testing.T) {
	fs, bucket := newMemBlobFS(t)
	ctx := context.Background()

	// Write an object
	require.NoError(t, bucket.WriteAll(ctx, "doc/readme.md", []byte("# README"), nil))

	t.Run("ObjectExists", func(t *testing.T) {
		info, err := fs.Stat(ctx, "/doc/readme.md")
		require.NoError(t, err)
		assert.Equal(t, "readme.md", info.Name())
		assert.Equal(t, int64(8), info.Size())
		assert.False(t, info.IsDir())
	})

	t.Run("DirectoryPrefix", func(t *testing.T) {
		info, err := fs.Stat(ctx, "/doc")
		require.NoError(t, err)
		assert.Equal(t, "doc", info.Name())
		assert.True(t, info.IsDir())
	})

	t.Run("NonExistent", func(t *testing.T) {
		_, err := fs.Stat(ctx, "/nope")
		assert.ErrorIs(t, err, os.ErrNotExist)
	})
}

func TestBlobFileSystem_Mkdir(t *testing.T) {
	fs, bucket := newMemBlobFS(t)
	ctx := context.Background()

	require.NoError(t, fs.Mkdir(ctx, "/mydir", 0755))

	// Directory marker object should exist
	exists, err := bucket.Exists(ctx, "mydir/")
	require.NoError(t, err)
	assert.True(t, exists)

	// Stat should report as directory
	info, err := fs.Stat(ctx, "/mydir")
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestBlobFileSystem_RemoveAll(t *testing.T) {
	fs, bucket := newMemBlobFS(t)
	ctx := context.Background()

	require.NoError(t, bucket.WriteAll(ctx, "removeme.txt", []byte("gone"), nil))
	require.NoError(t, fs.RemoveAll(ctx, "/removeme.txt"))

	exists, err := bucket.Exists(ctx, "removeme.txt")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestBlobFileSystem_RemoveAllDirectory(t *testing.T) {
	fs, bucket := newMemBlobFS(t)
	ctx := context.Background()

	// Create a dir marker and a file "inside" it
	require.NoError(t, bucket.WriteAll(ctx, "dir/", nil, nil))
	require.NoError(t, bucket.WriteAll(ctx, "dir/file.txt", []byte("data"), nil))

	// RemoveAll only removes the object itself + directory marker, not children
	require.NoError(t, fs.RemoveAll(ctx, "/dir"))

	// Directory marker should be gone
	exists, err := bucket.Exists(ctx, "dir/")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestBlobFileSystem_Rename(t *testing.T) {
	fs, bucket := newMemBlobFS(t)
	ctx := context.Background()

	require.NoError(t, bucket.WriteAll(ctx, "old.txt", []byte("content"), nil))
	require.NoError(t, fs.Rename(ctx, "/old.txt", "/new.txt"))

	// Old should not exist
	exists, err := bucket.Exists(ctx, "old.txt")
	require.NoError(t, err)
	assert.False(t, exists)

	// New should exist with same content
	data, err := bucket.ReadAll(ctx, "new.txt")
	require.NoError(t, err)
	assert.Equal(t, []byte("content"), data)
}

func TestBlobFileSystem_DirectoryListing(t *testing.T) {
	fs, bucket := newMemBlobFS(t)
	ctx := context.Background()

	// Create files under a prefix
	require.NoError(t, bucket.WriteAll(ctx, "listing/a.txt", []byte("a"), nil))
	require.NoError(t, bucket.WriteAll(ctx, "listing/b.txt", []byte("bb"), nil))
	require.NoError(t, bucket.WriteAll(ctx, "listing/sub/c.txt", []byte("ccc"), nil))

	// Open the directory
	f, err := fs.OpenFile(ctx, "/listing", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer f.Close()

	entries, err := f.Readdir(-1)
	require.NoError(t, err)
	assert.Len(t, entries, 3) // a.txt, b.txt, sub/

	names := make(map[string]bool)
	for _, e := range entries {
		names[e.Name()] = true
	}
	assert.True(t, names["a.txt"])
	assert.True(t, names["b.txt"])
	assert.True(t, names["sub"])
}

func TestBlobFileSystem_SeekOnRead(t *testing.T) {
	fs, bucket := newMemBlobFS(t)
	ctx := context.Background()

	data := []byte("0123456789ABCDEF")
	require.NoError(t, bucket.WriteAll(ctx, "seekable.bin", data, nil))

	f, err := fs.OpenFile(ctx, "/seekable.bin", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer f.Close()

	// Seek to offset 10
	pos, err := f.Seek(10, io.SeekStart)
	require.NoError(t, err)
	assert.Equal(t, int64(10), pos)

	buf := make([]byte, 6)
	n, err := f.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 6, n)
	assert.Equal(t, "ABCDEF", string(buf))
}

// ---------------------------------------------------------------------------
// blobReadFile and blobWriteFile unit tests
// ---------------------------------------------------------------------------

func TestBlobWriteFile_DoubleClose(t *testing.T) {
	bucket := memblob.OpenBucket(nil)
	defer bucket.Close()

	wf := newBlobWriteFile(context.Background(), bucket, "double.txt", "/double.txt")
	_, err := wf.Write([]byte("data"))
	require.NoError(t, err)
	require.NoError(t, wf.Close())
	// Second close should be a no-op
	require.NoError(t, wf.Close())
}

func TestBlobWriteFile_WriteAfterClose(t *testing.T) {
	bucket := memblob.OpenBucket(nil)
	defer bucket.Close()

	wf := newBlobWriteFile(context.Background(), bucket, "closed.txt", "/closed.txt")
	require.NoError(t, wf.Close())

	_, err := wf.Write([]byte("too late"))
	assert.Error(t, err)
}

func TestBlobWriteFile_Stat(t *testing.T) {
	bucket := memblob.OpenBucket(nil)
	defer bucket.Close()

	wf := newBlobWriteFile(context.Background(), bucket, "stat.txt", "/stat.txt")
	info, err := wf.Stat()
	require.NoError(t, err)
	assert.Equal(t, "stat.txt", info.Name())
}

func TestBlobReadFile_Stat(t *testing.T) {
	bucket := memblob.OpenBucket(nil)
	defer bucket.Close()
	ctx := context.Background()

	require.NoError(t, bucket.WriteAll(ctx, "info.txt", []byte("hello"), nil))
	reader, err := bucket.NewReader(ctx, "info.txt", nil)
	require.NoError(t, err)

	rf := &blobReadFile{
		name:   "/info.txt",
		reader: reader,
		size:   reader.Size(),
		mod:    reader.ModTime(),
	}
	defer rf.Close()

	info, err := rf.Stat()
	require.NoError(t, err)
	assert.Equal(t, "info.txt", info.Name())
	assert.Equal(t, int64(5), info.Size())
}

func TestBlobReadFile_WriteNotSupported(t *testing.T) {
	bucket := memblob.OpenBucket(nil)
	defer bucket.Close()
	ctx := context.Background()

	require.NoError(t, bucket.WriteAll(ctx, "ro.txt", []byte("x"), nil))
	reader, err := bucket.NewReader(ctx, "ro.txt", nil)
	require.NoError(t, err)

	rf := &blobReadFile{name: "/ro.txt", reader: reader}
	defer rf.Close()

	_, werr := rf.Write([]byte("nope"))
	assert.Error(t, werr)
}

// ---------------------------------------------------------------------------
// blobDirFile unit tests
// ---------------------------------------------------------------------------

func TestBlobDirFile_Readdir(t *testing.T) {
	entries := []os.FileInfo{
		&blobFileInfo{name: "a.txt", size: 10},
		&blobFileInfo{name: "b.txt", size: 20},
		&blobFileInfo{name: "c.txt", size: 30},
	}

	t.Run("ReadAll", func(t *testing.T) {
		df := &blobDirFile{name: "/test", entries: append([]os.FileInfo{}, entries...)}
		result, err := df.Readdir(-1)
		require.NoError(t, err)
		assert.Len(t, result, 3)
	})

	t.Run("ReadPartial", func(t *testing.T) {
		df := &blobDirFile{name: "/test", entries: append([]os.FileInfo{}, entries...)}
		result, err := df.Readdir(2)
		require.NoError(t, err)
		assert.Len(t, result, 2)
		assert.Equal(t, "a.txt", result[0].Name())

		// Read remaining
		result2, err := df.Readdir(-1)
		require.NoError(t, err)
		assert.Len(t, result2, 1)
		assert.Equal(t, "c.txt", result2[0].Name())
	})

	t.Run("Stat", func(t *testing.T) {
		df := &blobDirFile{name: "/somedir"}
		info, err := df.Stat()
		require.NoError(t, err)
		assert.True(t, info.IsDir())
		assert.Equal(t, "somedir", info.Name())
	})

	t.Run("UnsupportedOps", func(t *testing.T) {
		df := &blobDirFile{name: "/dir"}
		_, err := df.Read(nil)
		assert.Error(t, err)
		_, err = df.Seek(0, 0)
		assert.Error(t, err)
		_, err = df.Write(nil)
		assert.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// blobFileInfo unit tests
// ---------------------------------------------------------------------------

func TestBlobFileInfo(t *testing.T) {
	fi := &blobFileInfo{name: "test.txt", size: 42, isDir: false}
	assert.Equal(t, "test.txt", fi.Name())
	assert.Equal(t, int64(42), fi.Size())
	assert.Equal(t, os.FileMode(0444), fi.Mode())
	assert.False(t, fi.IsDir())
	assert.Nil(t, fi.Sys())

	// Zero ModTime gets replaced with something non-zero
	assert.False(t, fi.ModTime().IsZero())

	fiDir := &blobFileInfo{name: "subdir", isDir: true}
	assert.True(t, fiDir.IsDir())
}

// ---------------------------------------------------------------------------
// blobBackend top-level tests (using memblob via URL)
// ---------------------------------------------------------------------------

func TestBlobBackend_MemURL(t *testing.T) {
	// The "mem://" URL scheme is registered by memblob's init().
	// We import it via the test build only.
	backend, err := newBlobBackend(BlobBackendOptions{
		BlobURL: "mem://",
	})
	require.NoError(t, err)
	defer backend.Close()

	// Accessibility
	require.NoError(t, backend.CheckAvailability())

	// FileSystem should be non-nil
	assert.NotNil(t, backend.FileSystem())

	// Checksummer should be nil for blob backends
	assert.Nil(t, backend.Checksummer())
}

func TestBlobBackend_WithStoragePrefix(t *testing.T) {
	backend, err := newBlobBackend(BlobBackendOptions{
		BlobURL:       "mem://",
		StoragePrefix: "/myprefix",
	})
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	// Write via the filesystem (will be prefixed)
	wf, err := backend.FileSystem().OpenFile(ctx, "/file.txt", os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	_, err = wf.Write([]byte("prefixed content"))
	require.NoError(t, err)
	require.NoError(t, wf.Close())

	// Read back
	rf, err := backend.FileSystem().OpenFile(ctx, "/file.txt", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer rf.Close()
	data, err := io.ReadAll(rf)
	require.NoError(t, err)
	assert.Equal(t, "prefixed content", string(data))
}

// ---------------------------------------------------------------------------
// isNotFound unit tests
// ---------------------------------------------------------------------------

func TestIsNotFound(t *testing.T) {
	assert.False(t, isNotFound(nil))
	// gcerrors-based check is tested transitively via OpenFile/Stat on missing keys
}

// ---------------------------------------------------------------------------
// Full round-trip integration test: write, stat, read, seek, rename, delete
// ---------------------------------------------------------------------------

func TestBlobFileSystem_FullRoundTrip(t *testing.T) {
	fs, _ := newMemBlobFS(t)
	ctx := context.Background()

	// 1. Write
	wf, err := fs.OpenFile(ctx, "/trip/data.bin", os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	_, err = wf.Write([]byte("ABCDEFGHIJ"))
	require.NoError(t, err)
	require.NoError(t, wf.Close())

	// 2. Stat
	info, err := fs.Stat(ctx, "/trip/data.bin")
	require.NoError(t, err)
	assert.Equal(t, int64(10), info.Size())
	assert.False(t, info.IsDir())

	// 3. Read
	rf, err := fs.OpenFile(ctx, "/trip/data.bin", os.O_RDONLY, 0)
	require.NoError(t, err)

	buf := make([]byte, 5)
	n, err := rf.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, "ABCDE", string(buf))

	// 4. Seek back to start and re-read
	pos, err := rf.Seek(0, io.SeekStart)
	require.NoError(t, err)
	assert.Equal(t, int64(0), pos)
	buf2, err := io.ReadAll(rf)
	require.NoError(t, err)
	assert.Equal(t, "ABCDEFGHIJ", string(buf2))
	rf.Close()

	// 5. Rename
	require.NoError(t, fs.Rename(ctx, "/trip/data.bin", "/trip/renamed.bin"))
	_, err = fs.Stat(ctx, "/trip/data.bin")
	assert.ErrorIs(t, err, os.ErrNotExist)
	info, err = fs.Stat(ctx, "/trip/renamed.bin")
	require.NoError(t, err)
	assert.Equal(t, int64(10), info.Size())

	// 6. RemoveAll
	require.NoError(t, fs.RemoveAll(ctx, "/trip/renamed.bin"))
	_, err = fs.Stat(ctx, "/trip/renamed.bin")
	assert.ErrorIs(t, err, os.ErrNotExist)
}
