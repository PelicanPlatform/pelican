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

// These tests exercise the native S3 (gocloud.dev/blob) backend against the
// same public AWS S3 bucket used by xrootd-s3-http's s3_tests.cc, ensuring
// parity between the old C++ plugin and the new Go implementation.
//
// The bucket "genome-browser" at s3.us-east-1.amazonaws.com contains the
// UCSC Cell Browser dataset.  It is publicly accessible and read-only;
// no credentials are needed.
//
// Target directory: cells/tabula-sapiens
// Known file:       cells/tabula-sapiens/cellbrowser.json.bak  (672 bytes)
//
// The xrootd-s3-http tests define five fixture configurations:
//
//   FileSystemS3VirtualBucket   – virtual URL style, bucket = genome-browser
//   FileSystemS3VirtualNoBucket – virtual URL style, no bucket (bucket in path)
//   FileSystemS3PathBucket      – path URL style,    bucket = genome-browser
//   FileSystemS3PathNoBucket    – path URL style,    no bucket (bucket in path)
//   FileSystemS3PathBucketSlash – path URL style,    trailing slash on service URL
//
// We replicate equivalent configurations below, each for Stat and List.
//
// NOTE: These tests make live network requests to AWS S3.  They are skipped
// when the PELICAN_TEST_AWS_S3 environment variable is not set to "1".

import (
	"context"
	"io"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func skipIfNoAWS(t *testing.T) {
	t.Helper()
	if os.Getenv("PELICAN_TEST_AWS_S3") != "1" {
		t.Skip("PELICAN_TEST_AWS_S3 not set; skipping live AWS S3 test")
	}
}

// The xrootd-s3-http tests use s3.path_name = /test, which means the namespace
// root is /test and the actual S3 objects live under the key prefix that follows.
// In the Go backend, StoragePrefix serves the same role.

// --------------------------------------------------------------------------
// Configuration 1: Virtual-hosted URL style, bucket = genome-browser
// Equivalent to FileSystemS3VirtualBucket in s3_tests.cc
// --------------------------------------------------------------------------

func openVirtualBucket(t *testing.T) *blobBackend {
	t.Helper()
	backend, err := newBlobBackend(BlobBackendOptions{
		ServiceURL: "https://s3.us-east-1.amazonaws.com",
		Region:     "us-east-1",
		Bucket:     "genome-browser",
		URLStyle:   "virtual",
	})
	require.NoError(t, err, "failed to open genome-browser bucket (virtual style)")
	bb := backend.(*blobBackend)
	t.Cleanup(func() { bb.Close() })
	return bb
}

// --------------------------------------------------------------------------
// Configuration 2: Path-style URL, bucket = genome-browser
// Equivalent to FileSystemS3PathBucket in s3_tests.cc
// --------------------------------------------------------------------------

func openPathBucket(t *testing.T) *blobBackend {
	t.Helper()
	backend, err := newBlobBackend(BlobBackendOptions{
		ServiceURL: "https://s3.us-east-1.amazonaws.com",
		Region:     "us-east-1",
		Bucket:     "genome-browser",
		URLStyle:   "path",
	})
	require.NoError(t, err, "failed to open genome-browser bucket (path style)")
	bb := backend.(*blobBackend)
	t.Cleanup(func() { bb.Close() })
	return bb
}

// --------------------------------------------------------------------------
// Configuration 3: Path-style URL, trailing slash on service URL
// Equivalent to FileSystemS3PathBucketSlash in s3_tests.cc
// --------------------------------------------------------------------------

func openPathBucketSlash(t *testing.T) *blobBackend {
	t.Helper()
	backend, err := newBlobBackend(BlobBackendOptions{
		ServiceURL: "https://s3.us-east-1.amazonaws.com/",
		Region:     "us-east-1",
		Bucket:     "genome-browser",
		URLStyle:   "path",
	})
	require.NoError(t, err, "failed to open genome-browser bucket (path+slash)")
	bb := backend.(*blobBackend)
	t.Cleanup(func() { bb.Close() })
	return bb
}

// --------------------------------------------------------------------------
// Configuration 4: Virtual-hosted, no explicit bucket — bucket is in the
// StoragePrefix.
// Equivalent to FileSystemS3VirtualNoBucket in s3_tests.cc.
// NOTE: gocloud.dev requires the bucket name in the URL scheme, so we
// test this by putting the first path component as the StoragePrefix.
//
// In xrootd-s3-http, when no bucket is given, the first path component
// *after* the path_name is the bucket.  The stat path used is:
//   /test/genome-browser/cells/tabula-sapiens/cellbrowser.json.bak
// which resolves to bucket=genome-browser, key=cells/tabula-sapiens/cellbrowser.json.bak
//
// We can't replicate the exact no-bucket behavior with gocloud (which
// requires a bucket at URL time), so we test the same data via the
// StoragePrefix configuration — a realistic usage pattern.
// --------------------------------------------------------------------------

func openVirtualBucketWithPrefix(t *testing.T) *blobBackend {
	t.Helper()
	backend, err := newBlobBackend(BlobBackendOptions{
		ServiceURL:    "https://s3.us-east-1.amazonaws.com",
		Region:        "us-east-1",
		Bucket:        "genome-browser",
		URLStyle:      "virtual",
		StoragePrefix: "/cells/tabula-sapiens",
	})
	require.NoError(t, err, "failed to open genome-browser bucket (virtual+prefix)")
	bb := backend.(*blobBackend)
	t.Cleanup(func() { bb.Close() })
	return bb
}

// ==========================================================================
// Stat tests — match xrootd-s3-http TEST_F(..., Stat) tests
// ==========================================================================

func TestAWSS3_VirtualBucket_Stat(t *testing.T) {
	skipIfNoAWS(t)
	backend := openVirtualBucket(t)

	ctx := context.Background()
	info, err := backend.FileSystem().Stat(ctx, "/cells/tabula-sapiens/cellbrowser.json.bak")
	require.NoError(t, err, "Stat failed on genome-browser bucket (virtual)")
	assert.Equal(t, int64(672), info.Size(), "unexpected file size")
	assert.False(t, info.IsDir())
	assert.Equal(t, "cellbrowser.json.bak", info.Name())
}

func TestAWSS3_PathBucket_Stat(t *testing.T) {
	skipIfNoAWS(t)
	backend := openPathBucket(t)

	ctx := context.Background()
	info, err := backend.FileSystem().Stat(ctx, "/cells/tabula-sapiens/cellbrowser.json.bak")
	require.NoError(t, err, "Stat failed on genome-browser bucket (path)")
	assert.Equal(t, int64(672), info.Size())
}

func TestAWSS3_PathBucketSlash_Stat(t *testing.T) {
	skipIfNoAWS(t)
	backend := openPathBucketSlash(t)

	ctx := context.Background()
	info, err := backend.FileSystem().Stat(ctx, "/cells/tabula-sapiens/cellbrowser.json.bak")
	require.NoError(t, err, "Stat failed on genome-browser bucket (path+slash)")
	assert.Equal(t, int64(672), info.Size())
}

func TestAWSS3_VirtualBucket_StatNotFound(t *testing.T) {
	skipIfNoAWS(t)
	backend := openVirtualBucket(t)

	ctx := context.Background()
	_, err := backend.FileSystem().Stat(ctx, "/cells/tabula-sapiens/does_not_exist.zzz")
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// ==========================================================================
// Stat directory tests — match xrootd-s3-http StatRoot/NestedDir tests
// ==========================================================================

func TestAWSS3_VirtualBucket_StatDirectory(t *testing.T) {
	skipIfNoAWS(t)
	backend := openVirtualBucket(t)

	ctx := context.Background()
	fs := backend.FileSystem()

	// "cells" should appear as a directory
	info, err := fs.Stat(ctx, "/cells")
	require.NoError(t, err, "Stat directory /cells failed")
	assert.True(t, info.IsDir())

	// "cells/tabula-sapiens" should appear as a directory
	info, err = fs.Stat(ctx, "/cells/tabula-sapiens")
	require.NoError(t, err, "Stat directory /cells/tabula-sapiens failed")
	assert.True(t, info.IsDir())
}

// ==========================================================================
// Stat with StoragePrefix — the prefix scopes us inside the bucket, so
// "cellbrowser.json.bak" should be accessible at the root of the
// prefix namespace.
// ==========================================================================

func TestAWSS3_VirtualBucket_WithPrefix_Stat(t *testing.T) {
	skipIfNoAWS(t)
	backend := openVirtualBucketWithPrefix(t)

	ctx := context.Background()
	info, err := backend.FileSystem().Stat(ctx, "/cellbrowser.json.bak")
	require.NoError(t, err, "Stat with StoragePrefix failed")
	assert.Equal(t, int64(672), info.Size())
}

// ==========================================================================
// List tests — match xrootd-s3-http TestDirectoryContents helper
//
// The xrootd-s3-http test verifies the exact order and contents of
//   cells/tabula-sapiens:
//     cellbrowser.json.bak  (file, 672 bytes)
//     dataset.json          (file, 1847 bytes)
//     desc.json             (file, 1091 bytes)
//     all/                  (directory)
//     by-organ/             (directory)
//     func-compart/         (directory)
//
// S3 list output is lexicographic.  We sort our results the same way
// and verify file vs directory type plus sizes for files.
// ==========================================================================

type dirEntry struct {
	name  string
	size  int64
	isDir bool
}

func listDirViaFS(t *testing.T, backend *blobBackend, dirPath string) []dirEntry {
	t.Helper()
	ctx := context.Background()
	f, err := backend.FileSystem().OpenFile(ctx, dirPath, os.O_RDONLY, 0)
	require.NoError(t, err, "OpenFile(%s) failed", dirPath)
	defer f.Close()

	entries, err := f.Readdir(-1)
	require.NoError(t, err, "Readdir(%s) failed", dirPath)

	var result []dirEntry
	for _, e := range entries {
		result = append(result, dirEntry{
			name:  e.Name(),
			size:  e.Size(),
			isDir: e.IsDir(),
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].name < result[j].name })
	return result
}

func TestAWSS3_VirtualBucket_List(t *testing.T) {
	skipIfNoAWS(t)
	backend := openVirtualBucket(t)

	entries := listDirViaFS(t, backend, "/cells/tabula-sapiens")

	// Build maps for easier assertion
	entryByName := map[string]dirEntry{}
	for _, e := range entries {
		entryByName[e.name] = e
	}

	// Files expected by xrootd-s3-http tests
	expectedFiles := map[string]int64{
		"cellbrowser.json.bak": 672,
		"dataset.json":         1847,
		"desc.json":            1091,
	}
	for name, size := range expectedFiles {
		e, ok := entryByName[name]
		require.True(t, ok, "expected file %q not found in listing", name)
		assert.False(t, e.isDir, "%q should be a file", name)
		assert.Equal(t, size, e.size, "wrong size for %q", name)
	}

	// Directories expected by xrootd-s3-http tests
	expectedDirs := []string{"all", "by-organ", "func-compart"}
	for _, name := range expectedDirs {
		e, ok := entryByName[name]
		require.True(t, ok, "expected directory %q not found in listing", name)
		assert.True(t, e.isDir, "%q should be a directory", name)
	}
}

func TestAWSS3_PathBucket_List(t *testing.T) {
	skipIfNoAWS(t)
	backend := openPathBucket(t)

	entries := listDirViaFS(t, backend, "/cells/tabula-sapiens")

	entryByName := map[string]dirEntry{}
	for _, e := range entries {
		entryByName[e.name] = e
	}

	e, ok := entryByName["cellbrowser.json.bak"]
	require.True(t, ok, "cellbrowser.json.bak not found in path-style listing")
	assert.Equal(t, int64(672), e.size)
	assert.False(t, e.isDir)
}

func TestAWSS3_PathBucketSlash_List(t *testing.T) {
	skipIfNoAWS(t)
	backend := openPathBucketSlash(t)

	entries := listDirViaFS(t, backend, "/cells/tabula-sapiens")

	entryByName := map[string]dirEntry{}
	for _, e := range entries {
		entryByName[e.name] = e
	}

	e, ok := entryByName["cellbrowser.json.bak"]
	require.True(t, ok, "cellbrowser.json.bak not found in path+slash listing")
	assert.Equal(t, int64(672), e.size)
}

func TestAWSS3_VirtualBucket_WithPrefix_List(t *testing.T) {
	skipIfNoAWS(t)
	backend := openVirtualBucketWithPrefix(t)

	// With prefix = /cells/tabula-sapiens, the root "/" should list
	// the same contents as /cells/tabula-sapiens without prefix.
	entries := listDirViaFS(t, backend, "/")

	entryByName := map[string]dirEntry{}
	for _, e := range entries {
		entryByName[e.name] = e
	}

	e, ok := entryByName["cellbrowser.json.bak"]
	require.True(t, ok, "cellbrowser.json.bak not found via prefix listing")
	assert.Equal(t, int64(672), e.size)
}

// ==========================================================================
// Read test — verify we can actually download and read file content
// ==========================================================================

func TestAWSS3_VirtualBucket_Read(t *testing.T) {
	skipIfNoAWS(t)
	backend := openVirtualBucket(t)

	ctx := context.Background()
	f, err := backend.FileSystem().OpenFile(ctx, "/cells/tabula-sapiens/cellbrowser.json.bak", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer f.Close()

	data, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, 672, len(data), "read returned unexpected number of bytes")
}

func TestAWSS3_PathBucket_Read(t *testing.T) {
	skipIfNoAWS(t)
	backend := openPathBucket(t)

	ctx := context.Background()
	f, err := backend.FileSystem().OpenFile(ctx, "/cells/tabula-sapiens/cellbrowser.json.bak", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer f.Close()

	data, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, 672, len(data))
}

// ==========================================================================
// Availability test — bucket should be accessible
// ==========================================================================

func TestAWSS3_VirtualBucket_Availability(t *testing.T) {
	skipIfNoAWS(t)
	backend := openVirtualBucket(t)
	require.NoError(t, backend.CheckAvailability())
}

func TestAWSS3_PathBucket_Availability(t *testing.T) {
	skipIfNoAWS(t)
	backend := openPathBucket(t)
	require.NoError(t, backend.CheckAvailability())
}
