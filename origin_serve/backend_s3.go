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
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/azureblob" // register azblob:// URL opener
	_ "gocloud.dev/blob/gcsblob"   // register gs:// URL opener
	_ "gocloud.dev/blob/memblob"   // register mem:// URL opener (useful for testing)
	_ "gocloud.dev/blob/s3blob"    // register s3:// URL opener
	"gocloud.dev/gcerrors"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/server_utils"
)

// ---------------------------------------------------------------------------
// blobBackend implements server_utils.OriginBackend using gocloud.dev/blob.
// Supports S3, GCS (gs://), and Azure (azblob://) via driver imports.
// ---------------------------------------------------------------------------

type blobBackend struct {
	bucket *blob.Bucket
	fs     *blobFileSystem
}

// BlobBackendOptions groups the parameters needed to construct a blob backend.
// There are two ways to open a bucket:
//  1. Set BlobURL to a gocloud.dev URL (e.g. "s3://bucket", "gs://bucket", "azblob://container").
//  2. Set the S3-specific fields (ServiceURL, Region, Bucket, etc.) for backwards-compatible S3 config.
// If BlobURL is set it takes precedence.
type BlobBackendOptions struct {
	// Generic gocloud.dev/blob URL — takes precedence over the S3-specific fields.
	BlobURL string

	// S3-specific fields (used only when BlobURL is empty).
	ServiceURL string // e.g. "https://s3.us-east-1.amazonaws.com"
	Region     string
	Bucket     string
	AccessKey  string
	SecretKey  string
	URLStyle   string // "path" or "virtual" (default: "path")

	// Common fields.
	StoragePrefix string // optional key prefix within the bucket/container
}

// buildS3BlobURL constructs an s3:// gocloud URL from the backward-compatible
// S3-specific fields in BlobBackendOptions.
func buildS3BlobURL(opts BlobBackendOptions) (string, error) {
	if opts.Bucket == "" {
		return "", fmt.Errorf("S3 bucket name is required when BlobURL is not set")
	}

	u := &url.URL{
		Scheme: "s3",
		Host:   opts.Bucket,
	}
	q := u.Query()

	if opts.Region != "" {
		q.Set("region", opts.Region)
	}

	if opts.ServiceURL != "" {
		q.Set("endpoint", opts.ServiceURL)
	}

	urlStyle := strings.ToLower(opts.URLStyle)
	if urlStyle != "virtual" {
		q.Set("use_path_style", "true")
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

// newBlobBackend opens a gocloud.dev/blob bucket according to opts and returns
// a blobBackend.
func newBlobBackend(opts BlobBackendOptions) (*blobBackend, error) {
	var (
		bucket *blob.Bucket
		err    error
	)

	blobURL := opts.BlobURL
	if blobURL == "" {
		// Build an s3:// URL from the backward-compatible S3-specific fields.
		blobURL, err = buildS3BlobURL(opts)
		if err != nil {
			return nil, err
		}
	}

	// If per-export S3 credentials were provided, set them in the environment
	// so the gocloud AWS credential chain picks them up.
	if opts.AccessKey != "" && opts.SecretKey != "" {
		os.Setenv("AWS_ACCESS_KEY_ID", opts.AccessKey)
		os.Setenv("AWS_SECRET_ACCESS_KEY", opts.SecretKey)
	} else if strings.HasPrefix(blobURL, "s3://") {
		// No credentials supplied — request anonymous access unless the env
		// already has credentials configured.
		if os.Getenv("AWS_ACCESS_KEY_ID") == "" {
			// Append anonymous=true so the SDK doesn't try IAM, etc.
			if strings.Contains(blobURL, "?") {
				blobURL += "&anonymous=true"
			} else {
				blobURL += "?anonymous=true"
			}
		}
	}

	log.Infof("Opening blob bucket via URL: %s", blobURL)
	bucket, err = blob.OpenBucket(context.Background(), blobURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open blob bucket from URL %q: %w", blobURL, err)
	}

	// If a storagePrefix is configured, scope all operations to it.
	prefix := strings.TrimPrefix(opts.StoragePrefix, "/")
	if prefix != "" {
		prefix = strings.TrimSuffix(prefix, "/") + "/"
		bucket = blob.PrefixedBucket(bucket, prefix)
	}

	fs := &blobFileSystem{bucket: bucket}
	return &blobBackend{bucket: bucket, fs: fs}, nil
}

func (b *blobBackend) CheckAvailability() error {
	ok, err := b.bucket.IsAccessible(context.Background())
	if err != nil {
		return fmt.Errorf("blob bucket accessibility check failed: %w", err)
	}
	if !ok {
		return fmt.Errorf("blob bucket is not accessible")
	}
	return nil
}

func (b *blobBackend) FileSystem() webdav.FileSystem { return b.fs }
func (b *blobBackend) Checksummer() server_utils.OriginChecksummer {
	return nil // Cloud blob backends don't support xattr-based checksums
}

// Close cleans up the underlying bucket handle.
func (b *blobBackend) Close() error {
	return b.bucket.Close()
}

// ---------------------------------------------------------------------------
// blobFileSystem — implements webdav.FileSystem backed by gocloud.dev/blob.
// ---------------------------------------------------------------------------

type blobFileSystem struct {
	bucket *blob.Bucket
}

// blobKey normalises a webdav path ("/foo/bar") to a blob key ("foo/bar").
func blobKey(name string) string {
	return strings.TrimPrefix(name, "/")
}

// Mkdir implements webdav.FileSystem.
// Blob stores don't have real directories; we create a zero-byte marker.
func (fs *blobFileSystem) Mkdir(ctx context.Context, name string, _ os.FileMode) error {
	key := blobKey(name)
	if !strings.HasSuffix(key, "/") {
		key += "/"
	}
	return fs.bucket.WriteAll(ctx, key, nil, nil)
}

// OpenFile implements webdav.FileSystem.
func (fs *blobFileSystem) OpenFile(ctx context.Context, name string, flag int, _ os.FileMode) (webdav.File, error) {
	key := blobKey(name)

	// Write mode — return a writer that uploads on Close.
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC) != 0 {
		return newBlobWriteFile(ctx, fs.bucket, key, name), nil
	}

	// Check if this is a "directory" by listing with prefix.
	dirPrefix := key
	if dirPrefix != "" && !strings.HasSuffix(dirPrefix, "/") {
		dirPrefix += "/"
	}
	entries, err := fs.listDir(ctx, dirPrefix)
	if err == nil && len(entries) > 0 {
		return &blobDirFile{name: name, entries: entries}, nil
	}

	// Read mode — open via blob.NewReader (supports seek).
	reader, err := fs.bucket.NewReader(ctx, key, nil)
	if err != nil {
		if isNotFound(err) {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("blob read %q: %w", key, err)
	}

	return &blobReadFile{
		name:   name,
		reader: reader,
		size:   reader.Size(),
		mod:    reader.ModTime(),
	}, nil
}

// RemoveAll implements webdav.FileSystem.
func (fs *blobFileSystem) RemoveAll(ctx context.Context, name string) error {
	key := blobKey(name)

	// Try deleting as a plain object first.
	err := fs.bucket.Delete(ctx, key)
	if err != nil && !isNotFound(err) {
		return err
	}

	// Also try the directory marker.
	_ = fs.bucket.Delete(ctx, key+"/")
	return nil
}

// Rename implements webdav.FileSystem.
func (fs *blobFileSystem) Rename(ctx context.Context, oldName, newName string) error {
	oldKey := blobKey(oldName)
	newKey := blobKey(newName)

	if err := fs.bucket.Copy(ctx, newKey, oldKey, nil); err != nil {
		return fmt.Errorf("blob copy %q -> %q: %w", oldKey, newKey, err)
	}
	return fs.bucket.Delete(ctx, oldKey)
}

// Stat implements webdav.FileSystem.
func (fs *blobFileSystem) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	key := blobKey(name)

	attrs, err := fs.bucket.Attributes(ctx, key)
	if err == nil {
		return &blobFileInfo{
			name: path.Base(name),
			size: attrs.Size,
			mod:  attrs.ModTime,
		}, nil
	}

	// Not found as an object — check if it's a directory prefix.
	dirPrefix := key
	if dirPrefix != "" && !strings.HasSuffix(dirPrefix, "/") {
		dirPrefix += "/"
	}
	iter := fs.bucket.List(&blob.ListOptions{Prefix: dirPrefix, Delimiter: "/"})
	obj, iterErr := iter.Next(ctx)
	if iterErr == nil && obj != nil {
		return &blobFileInfo{name: path.Base(name), isDir: true}, nil
	}

	if isNotFound(err) {
		return nil, os.ErrNotExist
	}
	return nil, err
}

// listDir lists immediate children under prefix (with "/" delimiter).
func (fs *blobFileSystem) listDir(ctx context.Context, prefix string) ([]os.FileInfo, error) {
	iter := fs.bucket.List(&blob.ListOptions{Prefix: prefix, Delimiter: "/"})
	var entries []os.FileInfo
	for {
		obj, err := iter.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		baseName := strings.TrimPrefix(obj.Key, prefix)
		baseName = strings.TrimSuffix(baseName, "/")
		if baseName == "" {
			continue
		}
		entries = append(entries, &blobFileInfo{
			name:  baseName,
			size:  obj.Size,
			mod:   obj.ModTime,
			isDir: obj.IsDir,
		})
	}
	return entries, nil
}

// isNotFound returns true if the error represents a "not found" condition.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	return gcerrors.Code(err) == gcerrors.NotFound
}

// ---------------------------------------------------------------------------
// blobFileInfo — implements os.FileInfo
// ---------------------------------------------------------------------------

type blobFileInfo struct {
	name  string
	size  int64
	mod   time.Time
	isDir bool
}

func (fi *blobFileInfo) Name() string      { return fi.name }
func (fi *blobFileInfo) Size() int64       { return fi.size }
func (fi *blobFileInfo) Mode() os.FileMode { return 0444 }
func (fi *blobFileInfo) ModTime() time.Time {
	if fi.mod.IsZero() {
		return time.Now()
	}
	return fi.mod
}
func (fi *blobFileInfo) IsDir() bool      { return fi.isDir }
func (fi *blobFileInfo) Sys() interface{} { return nil }

// ---------------------------------------------------------------------------
// blobReadFile — read-only file backed by a blob.Reader.
// blob.Reader already supports Read and Seek.
// Uses atomic offset tracking for concurrent safety.
// ---------------------------------------------------------------------------

type blobReadFile struct {
	name   string
	reader *blob.Reader
	size   int64
	mod    time.Time
	offset atomic.Int64
}

func (f *blobReadFile) Read(p []byte) (int, error) {
	n, err := f.reader.Read(p)
	f.offset.Add(int64(n))
	return n, err
}

func (f *blobReadFile) Seek(offset int64, whence int) (int64, error) {
	n, err := f.reader.Seek(offset, whence)
	if err == nil {
		f.offset.Store(n)
	}
	return n, err
}

func (f *blobReadFile) Close() error { return f.reader.Close() }

func (f *blobReadFile) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("write not supported on read file")
}

func (f *blobReadFile) Readdir(_ int) ([]os.FileInfo, error) {
	return nil, fmt.Errorf("readdir not supported on file")
}

func (f *blobReadFile) Stat() (os.FileInfo, error) {
	return &blobFileInfo{
		name: path.Base(f.name),
		size: f.size,
		mod:  f.mod,
	}, nil
}

// ---------------------------------------------------------------------------
// blobWriteFile — write file backed by blob.Writer.
// Streams writes directly through to the underlying blob store.
// Uses a mutex to protect concurrent writes.
// ---------------------------------------------------------------------------

type blobWriteFile struct {
	ctx    context.Context
	bucket *blob.Bucket
	key    string
	name   string

	mu     sync.Mutex
	writer *blob.Writer
	opened bool
	closed bool
}

func newBlobWriteFile(ctx context.Context, bucket *blob.Bucket, key, name string) *blobWriteFile {
	return &blobWriteFile{ctx: ctx, bucket: bucket, key: key, name: name}
}

// ensureWriter lazily opens the blob.Writer on first Write.
func (f *blobWriteFile) ensureWriter() error {
	if f.opened {
		return nil
	}
	w, err := f.bucket.NewWriter(f.ctx, f.key, nil)
	if err != nil {
		return fmt.Errorf("blob new writer %q: %w", f.key, err)
	}
	f.writer = w
	f.opened = true
	return nil
}

func (f *blobWriteFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, fmt.Errorf("write to closed file")
	}
	if err := f.ensureWriter(); err != nil {
		return 0, err
	}
	return f.writer.Write(p)
}

func (f *blobWriteFile) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	if !f.opened {
		// Nothing was written; create an empty object.
		return f.bucket.WriteAll(f.ctx, f.key, nil, nil)
	}
	return f.writer.Close()
}

func (f *blobWriteFile) Read(_ []byte) (int, error) {
	return 0, fmt.Errorf("read not supported on write file")
}

func (f *blobWriteFile) Seek(_ int64, _ int) (int64, error) {
	return 0, fmt.Errorf("seek not supported on write file")
}

func (f *blobWriteFile) Readdir(_ int) ([]os.FileInfo, error) {
	return nil, fmt.Errorf("readdir not supported on write file")
}

func (f *blobWriteFile) Stat() (os.FileInfo, error) {
	return &blobFileInfo{
		name: path.Base(f.name),
	}, nil
}

// ---------------------------------------------------------------------------
// blobDirFile — directory representation for blob listings.
// ---------------------------------------------------------------------------

type blobDirFile struct {
	name    string
	entries []os.FileInfo
}

func (f *blobDirFile) Read(_ []byte) (int, error) {
	return 0, fmt.Errorf("read not supported on directory")
}

func (f *blobDirFile) Seek(_ int64, _ int) (int64, error) {
	return 0, fmt.Errorf("seek not supported on directory")
}

func (f *blobDirFile) Close() error { return nil }

func (f *blobDirFile) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("write not supported on directory")
}

func (f *blobDirFile) Readdir(count int) ([]os.FileInfo, error) {
	if count <= 0 || count > len(f.entries) {
		result := f.entries
		f.entries = nil
		return result, nil
	}
	result := f.entries[:count]
	f.entries = f.entries[count:]
	return result, nil
}

func (f *blobDirFile) Stat() (os.FileInfo, error) {
	return &blobFileInfo{
		name:  path.Base(f.name),
		isDir: true,
	}, nil
}

// ---------------------------------------------------------------------------
// S3 credential loading (unchanged — reads key files from disk)
// ---------------------------------------------------------------------------

func loadS3Credentials(accessKeyFile, secretKeyFile string) (accessKey, secretKey string, err error) {
	if accessKeyFile == "" || secretKeyFile == "" {
		return "", "", nil
	}
	akBytes, rErr := os.ReadFile(accessKeyFile)
	if rErr != nil {
		return "", "", fmt.Errorf("failed to read S3 access key file %s: %w", accessKeyFile, rErr)
	}
	skBytes, rErr := os.ReadFile(secretKeyFile)
	if rErr != nil {
		return "", "", fmt.Errorf("failed to read S3 secret key file %s: %w", secretKeyFile, rErr)
	}
	return strings.TrimSpace(string(akBytes)), strings.TrimSpace(string(skBytes)), nil
}

// parseHTTPDate parses an HTTP-Date header value.
func parseHTTPDate(s string) time.Time {
	t, err := time.Parse(time.RFC1123, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
