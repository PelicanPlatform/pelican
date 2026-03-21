//go:build !windows

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
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/test_utils"
)

// ---------------------------------------------------------------------------
// TestBlobBackend_MinioS3 — full integration test using a real minio server.
// Tests the complete S3 flow: build URL, open bucket, write, read, stat,
// rename, delete, directory listing.
// Skipped if minio is not installed.
// ---------------------------------------------------------------------------

func TestBlobBackend_MinioS3(t *testing.T) {
	var wf io.WriteCloser
	var rf io.ReadCloser
	var info os.FileInfo
	var entries []os.FileInfo
	var n int
	var got []byte
	var ctx context.Context
	test_utils.SkipIfNoMinio(t)

	var endpoint, accessKey, secretKey string

	endpoint, accessKey, secretKey = test_utils.StartMinio(t, "bucket1")

	var err error

	// Create the second bucket using the S3 API
	minioEndpoint := strings.TrimPrefix(endpoint, "http://")
	minioEndpoint = strings.TrimPrefix(minioEndpoint, "https://")
	minioClient, err := minio.New(minioEndpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: false,
	})
	require.NoError(t, err)
	ctx = context.Background()
	for _, bucket := range []string{"bucket1", "bucket2"} {
		exists, err := minioClient.BucketExists(ctx, bucket)
		require.NoError(t, err)
		if !exists {
			err = minioClient.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
			require.NoError(t, err)
		}
	}

	backend, err := newBlobBackend(BlobBackendOptions{
		ServiceURL: endpoint,
		Region:     "us-east-1",
		Bucket:     "bucket1",
		AccessKey:  accessKey,
		SecretKey:  secretKey,
		URLStyle:   "path",
	})
	require.NoError(t, err)
	defer backend.(*blobBackend).Close()

	ctx = context.Background()

	t.Run("CheckAvailability", func(t *testing.T) {
		require.NoError(t, backend.CheckAvailability())
	})

	t.Run("WriteAndRead", func(t *testing.T) {
		content := []byte("Hello from MinIO integration test!")

		wf, err = backend.FileSystem().OpenFile(ctx, "/greeting.txt", os.O_CREATE|os.O_WRONLY, 0644)
		require.NoError(t, err)
		n, err = wf.Write(content)
		require.NoError(t, err)
		assert.Equal(t, len(content), n)
		require.NoError(t, wf.Close())

		rf, err = backend.FileSystem().OpenFile(ctx, "/greeting.txt", os.O_RDONLY, 0)
		require.NoError(t, err)
		got, err = io.ReadAll(rf)
		require.NoError(t, err)
		assert.Equal(t, content, got)
		rf.Close()
	})

	t.Run("Stat", func(t *testing.T) {
		// Write an object directly
		wf, err = backend.FileSystem().OpenFile(ctx, "/statfile.bin", os.O_CREATE|os.O_WRONLY, 0644)
		require.NoError(t, err)
		_, err = wf.Write([]byte("0123456789"))
		require.NoError(t, err)
		require.NoError(t, wf.Close())

		info, err = backend.FileSystem().Stat(ctx, "/statfile.bin")
		require.NoError(t, err)
		assert.Equal(t, int64(10), info.Size())
		assert.Equal(t, "statfile.bin", info.Name())
		assert.False(t, info.IsDir())
	})

	t.Run("StatNonExistent", func(t *testing.T) {
		_, err := backend.FileSystem().Stat(ctx, "/nonexistent.txt")
		assert.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("ReadNonExistent", func(t *testing.T) {
		_, err := backend.FileSystem().OpenFile(ctx, "/does-not-exist.txt", os.O_RDONLY, 0)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("Rename", func(t *testing.T) {
		wf, err = backend.FileSystem().OpenFile(ctx, "/rename-src.txt", os.O_CREATE|os.O_WRONLY, 0644)
		require.NoError(t, err)
		_, err = wf.Write([]byte("rename me"))
		require.NoError(t, err)
		require.NoError(t, wf.Close())

		require.NoError(t, backend.FileSystem().Rename(ctx, "/rename-src.txt", "/rename-dst.txt"))

		_, err = backend.FileSystem().Stat(ctx, "/rename-src.txt")
		assert.ErrorIs(t, err, os.ErrNotExist)

		info, err = backend.FileSystem().Stat(ctx, "/rename-dst.txt")
		require.NoError(t, err)
		assert.Equal(t, int64(9), info.Size())
	})

	t.Run("RemoveAll", func(t *testing.T) {
		wf, err = backend.FileSystem().OpenFile(ctx, "/delete-me.txt", os.O_CREATE|os.O_WRONLY, 0644)
		require.NoError(t, err)
		_, err = wf.Write([]byte("gone"))
		require.NoError(t, err)
		require.NoError(t, wf.Close())

		require.NoError(t, backend.FileSystem().RemoveAll(ctx, "/delete-me.txt"))

		_, err = backend.FileSystem().Stat(ctx, "/delete-me.txt")
		assert.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("DirectoryListing", func(t *testing.T) {
		// Write multiple objects under a "directory"
		for _, name := range []string{"/listing/a.txt", "/listing/b.txt", "/listing/c.txt"} {
			wf, err = backend.FileSystem().OpenFile(ctx, name, os.O_CREATE|os.O_WRONLY, 0644)
			require.NoError(t, err)
			_, err = wf.Write([]byte(name))
			require.NoError(t, err)
			require.NoError(t, wf.Close())
		}

		dir, err := backend.FileSystem().OpenFile(ctx, "/listing", os.O_RDONLY, 0)
		require.NoError(t, err)
		defer dir.Close()

		entries, err = dir.Readdir(-1)
		require.NoError(t, err)
		assert.Len(t, entries, 3)

		names := make(map[string]bool)
		for _, e := range entries {
			names[e.Name()] = true
		}
		assert.True(t, names["a.txt"])
		assert.True(t, names["b.txt"])
		assert.True(t, names["c.txt"])
	})

	t.Run("SeekOnRead", func(t *testing.T) {
		content := []byte("0123456789ABCDEF")
		wf, err := backend.FileSystem().OpenFile(ctx, "/seekable.bin", os.O_CREATE|os.O_WRONLY, 0644)
		require.NoError(t, err)
		_, err = wf.Write(content)
		require.NoError(t, err)
		require.NoError(t, wf.Close())

		rf, err := backend.FileSystem().OpenFile(ctx, "/seekable.bin", os.O_RDONLY, 0)
		require.NoError(t, err)
		defer rf.Close()

		pos, err := rf.Seek(10, io.SeekStart)
		require.NoError(t, err)
		assert.Equal(t, int64(10), pos)

		buf := make([]byte, 6)
		n, err := rf.Read(buf)
		// Read may return io.EOF along with the final data — that's valid
		if err != nil {
			assert.ErrorIs(t, err, io.EOF)
		}
		assert.Equal(t, 6, n)
		assert.Equal(t, "ABCDEF", string(buf))
	})

	t.Run("WriteEmptyObject", func(t *testing.T) {
		wf, err := backend.FileSystem().OpenFile(ctx, "/empty.txt", os.O_CREATE|os.O_WRONLY, 0644)
		require.NoError(t, err)
		require.NoError(t, wf.Close())

		info, err := backend.FileSystem().Stat(ctx, "/empty.txt")
		require.NoError(t, err)
		assert.Equal(t, int64(0), info.Size())
	})

	t.Run("StoragePrefix", func(t *testing.T) {
		prefixedBackend, err := newBlobBackend(BlobBackendOptions{
			ServiceURL:    endpoint,
			Region:        "us-east-1",
			Bucket:        "bucket1",
			AccessKey:     accessKey,
			SecretKey:     secretKey,
			URLStyle:      "path",
			StoragePrefix: "/prefixed",
		})
		require.NoError(t, err)
		defer prefixedBackend.(*blobBackend).Close()

		wf, err := prefixedBackend.FileSystem().OpenFile(ctx, "/scoped.txt", os.O_CREATE|os.O_WRONLY, 0644)
		require.NoError(t, err)
		_, err = wf.Write([]byte("scoped content"))
		require.NoError(t, err)
		require.NoError(t, wf.Close())

		// Read back via the prefixed backend
		rf, err := prefixedBackend.FileSystem().OpenFile(ctx, "/scoped.txt", os.O_RDONLY, 0)
		require.NoError(t, err)
		got, err := io.ReadAll(rf)
		require.NoError(t, err)
		assert.Equal(t, "scoped content", string(got))
		rf.Close()

		// The un-prefixed backend should see it at /prefixed/scoped.txt
		rf2, err := backend.FileSystem().OpenFile(ctx, "/prefixed/scoped.txt", os.O_RDONLY, 0)
		require.NoError(t, err)
		got2, err := io.ReadAll(rf2)
		require.NoError(t, err)
		assert.Equal(t, "scoped content", string(got2))
		rf2.Close()
	})
}

// ---------------------------------------------------------------------------
// TestBlobBackend_MinioS3_MultiBucket — integration test for dynamic bucket backend
// ---------------------------------------------------------------------------

func TestBlobBackend_MinioS3_MultiBucket(t *testing.T) {
	test_utils.SkipIfNoMinio(t)

	// Start minio with one bucket (bucket1) and create bucket2 via the S3 API
	endpoint, accessKey, secretKey := test_utils.StartMinio(t, "bucket1")

	// minio-go wants "host:port" without the scheme
	minioEndpoint := strings.TrimPrefix(endpoint, "http://")
	minioEndpoint = strings.TrimPrefix(minioEndpoint, "https://")
	minioClient, err := minio.New(minioEndpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: false,
	})
	require.NoError(t, err)
	err = minioClient.MakeBucket(context.Background(), "bucket2", minio.MakeBucketOptions{})
	require.NoError(t, err)
	require.NoError(t, err)

	// Use dynamic multi-bucket backend (no Bucket specified)
	backend, err := newBlobBackend(BlobBackendOptions{
		ServiceURL: endpoint,
		Region:     "us-east-1",
		AccessKey:  accessKey,
		SecretKey:  secretKey,
		URLStyle:   "path",
	})
	require.NoError(t, err)
	defer backend.(*multiBucketBlobBackend).Close()

	ctx := context.Background()

	content1 := []byte("hello from bucket1")
	content2 := []byte("hello from bucket2")

	// Write to bucket1
	wf1, err := backend.FileSystem().OpenFile(ctx, "/bucket1/foo.txt", os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	_, err = wf1.Write(content1)
	require.NoError(t, err)
	require.NoError(t, wf1.Close())

	// Write to bucket2
	wf2, err := backend.FileSystem().OpenFile(ctx, "/bucket2/bar.txt", os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	_, err = wf2.Write(content2)
	require.NoError(t, err)
	require.NoError(t, wf2.Close())

	// Read back from bucket1
	rf1, err := backend.FileSystem().OpenFile(ctx, "/bucket1/foo.txt", os.O_RDONLY, 0)
	require.NoError(t, err)
	got1, err := io.ReadAll(rf1)
	require.NoError(t, err)
	assert.Equal(t, content1, got1)
	rf1.Close()

	// Read back from bucket2
	rf2, err := backend.FileSystem().OpenFile(ctx, "/bucket2/bar.txt", os.O_RDONLY, 0)
	require.NoError(t, err)
	got2, err := io.ReadAll(rf2)
	require.NoError(t, err)
	assert.Equal(t, content2, got2)
	rf2.Close()

	// Stat should work for both
	info1, err := backend.FileSystem().Stat(ctx, "/bucket1/foo.txt")
	require.NoError(t, err)
	assert.Equal(t, int64(len(content1)), info1.Size())
	info2, err := backend.FileSystem().Stat(ctx, "/bucket2/bar.txt")
	require.NoError(t, err)
	assert.Equal(t, int64(len(content2)), info2.Size())

	// Directory listing for bucket1
	dir1, err := backend.FileSystem().OpenFile(ctx, "/bucket1", os.O_RDONLY, 0)
	require.NoError(t, err)
	entries1, err := dir1.Readdir(-1)
	require.NoError(t, err)
	assert.True(t, len(entries1) > 0)
	dir1.Close()

	// Directory listing for bucket2
	dir2, err := backend.FileSystem().OpenFile(ctx, "/bucket2", os.O_RDONLY, 0)
	require.NoError(t, err)
	entries2, err := dir2.Readdir(-1)
	require.NoError(t, err)
	assert.True(t, len(entries2) > 0)
	dir2.Close()
}
