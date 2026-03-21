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
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

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
//
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
// S3-specific fields in BlobBackendOptions.  When bucket is non-empty it
// overrides opts.Bucket (used by the multi-bucket backend).
func buildS3BlobURL(opts BlobBackendOptions, bucket ...string) (string, error) {
	bucketName := opts.Bucket
	if len(bucket) > 0 && bucket[0] != "" {
		bucketName = bucket[0]
	}
	if bucketName == "" {
		return "", fmt.Errorf("S3 bucket name is required when BlobURL is not set")
	}

	u := &url.URL{
		Scheme: "s3",
		Host:   bucketName,
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
// an OriginBackend.
//
// When opts.Bucket is empty and opts.BlobURL is also empty the backend
// operates in "multi-bucket" mode: the first path component of every
// request is treated as the S3 bucket name and the remainder as the
// object key.  Bucket connections are opened lazily and cached.
func newBlobBackend(opts BlobBackendOptions) (server_utils.OriginBackend, error) {
	// Multi-bucket mode: no fixed bucket configured.
	if opts.Bucket == "" && opts.BlobURL == "" {
		return newMultiBucketBlobBackend(opts), nil
	}

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
	return &blobChecksummer{bucket: b.bucket}
}

// Close cleans up the underlying bucket handle.
func (b *blobBackend) Close() error {
	return b.bucket.Close()
}

// ---------------------------------------------------------------------------
// blobChecksummer — implements OriginChecksummer using blob Attributes.
// Returns MD5 digests (RFC 3230) when the provider supplies them.
// ---------------------------------------------------------------------------

type blobChecksummer struct {
	bucket *blob.Bucket
}

func (c *blobChecksummer) GetDigests(relativePath, wantDigest string) ([]string, error) {
	key := blobKey(relativePath)
	attrs, err := c.bucket.Attributes(context.Background(), key)
	if err != nil {
		// Best-effort: if we can't get attributes, return nothing.
		return nil, nil
	}

	var digests []string
	for _, alg := range strings.Split(wantDigest, ",") {
		alg = strings.TrimSpace(strings.ToLower(alg))
		switch alg {
		case "md5":
			if len(attrs.MD5) > 0 {
				digests = append(digests, "md5="+base64.StdEncoding.EncodeToString(attrs.MD5))
			}
		}
	}
	return digests, nil
}

// ---------------------------------------------------------------------------
// Content-length hint — allows callers (e.g. HTTP handlers) to pass the
// expected upload size to the blob writer via context.  This mirrors
// xrootd-s3-http's "oss.asize" mechanism.
// ---------------------------------------------------------------------------

type blobCtxKey int

const blobContentLengthKey blobCtxKey = iota

// ContextWithContentLength returns a child context carrying the expected
// upload size.  The blob filesystem's OpenFile will use this to hint the
// underlying writer, enabling single-PUT uploads for small objects.
func ContextWithContentLength(ctx context.Context, size int64) context.Context {
	return context.WithValue(ctx, blobContentLengthKey, size)
}

func contentLengthFromCtx(ctx context.Context) int64 {
	if v, ok := ctx.Value(blobContentLengthKey).(int64); ok {
		return v
	}
	return -1
}

// ---------------------------------------------------------------------------
// blobFileSystem — implements webdav.FileSystem backed by gocloud.dev/blob.
// ---------------------------------------------------------------------------

type blobFileSystem struct {
	bucket *blob.Bucket
}

// blobKey normalises a webdav path ("/foo/bar") to a blob key ("foo/bar").
// Also cleans path traversal sequences as defense-in-depth.
func blobKey(name string) string {
	return strings.TrimPrefix(path.Clean("/"+name), "/")
}

// Mkdir implements webdav.FileSystem.
// Blob stores don't have real directories; we create a zero-byte marker.
func (fs *blobFileSystem) Mkdir(ctx context.Context, name string, _ os.FileMode) error {
	key := blobKey(name)
	if key == "" {
		return nil // Root always exists.
	}
	if !strings.HasSuffix(key, "/") {
		key += "/"
	}
	return fs.bucket.WriteAll(ctx, key, nil, nil)
}

// OpenFile implements webdav.FileSystem.
func (fs *blobFileSystem) OpenFile(ctx context.Context, name string, flag int, _ os.FileMode) (webdav.File, error) {
	key := blobKey(name)

	// Write mode — open a streaming writer immediately so permission
	// or connectivity errors surface now, not on the first Write call.
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC) != 0 {
		wf, err := newBlobWriteFile(ctx, fs.bucket, key, name)
		if err != nil {
			return nil, err
		}
		return wf, nil
	}

	// Check if this is a "directory" by peeking at a prefix listing.
	dirPrefix := key
	if dirPrefix != "" && !strings.HasSuffix(dirPrefix, "/") {
		dirPrefix += "/"
	}
	peekIter := fs.bucket.List(&blob.ListOptions{Prefix: dirPrefix, Delimiter: "/"})
	if _, peekErr := peekIter.Next(ctx); peekErr == nil {
		// It is a directory — return a lazy dir handle (a fresh iterator
		// will be created when Readdir is called).
		return &blobDirFile{name: name, bucket: fs.bucket, prefix: dirPrefix}, nil
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
			etag: attrs.ETag,
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
	etag  string
}

// BlobFileSysInfo is returned by blobFileInfo.Sys() when metadata is available.
type BlobFileSysInfo struct {
	ETag string
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
func (fi *blobFileInfo) IsDir() bool { return fi.isDir }
func (fi *blobFileInfo) Sys() interface{} {
	if fi.etag != "" {
		return &BlobFileSysInfo{ETag: fi.etag}
	}
	return nil
}

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
// The writer is opened eagerly so that permission and connectivity
// errors are reported at OpenFile time, not deferred to the first Write.
// Data is streamed directly through to the underlying blob store;
// nothing is buffered beyond the driver's internal upload-part buffer.
// Uses a mutex to protect concurrent writes.
// ---------------------------------------------------------------------------

type blobWriteFile struct {
	name   string
	mu     sync.Mutex
	writer *blob.Writer
	closed bool
}

// newBlobWriteFile opens a blob.Writer immediately.  If the context
// carries a content-length hint (see ContextWithContentLength), it is
// used to size the driver's upload buffer — small objects that fit in
// a single part avoid multipart overhead entirely.
func newBlobWriteFile(ctx context.Context, bucket *blob.Bucket, key, name string) (*blobWriteFile, error) {
	var opts blob.WriterOptions
	if hint := contentLengthFromCtx(ctx); hint > 0 {
		// Set the buffer to the exact object size when it is small
		// enough for a single-part upload. The S3 driver will issue
		// a simple PutObject instead of a multipart sequence.
		const maxSinglePart = 5 * 1024 * 1024 * 1024 // 5 GiB S3 single-part limit
		if hint <= maxSinglePart {
			opts.BufferSize = int(hint)
		}
	}
	w, err := bucket.NewWriter(ctx, key, &opts)
	if err != nil {
		return nil, fmt.Errorf("blob open for write %q: %w", key, err)
	}
	return &blobWriteFile{name: name, writer: w}, nil
}

func (f *blobWriteFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, fmt.Errorf("write to closed file")
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
	// Close flushes buffered data and finalises the upload.
	// If nothing was written the driver creates a zero-byte object.
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
// blobDirFile — lazy directory representation for blob listings.
// Entries are fetched on demand from the blob iterator, avoiding
// pre-buffering an unbounded number of objects.
// ---------------------------------------------------------------------------

type blobDirFile struct {
	name   string
	bucket *blob.Bucket
	prefix string

	mu   sync.Mutex
	iter *blob.ListIterator
	done bool
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

// Readdir returns directory entries lazily from the underlying blob
// listing iterator.  When count <= 0 it returns all remaining entries;
// otherwise it returns up to count entries per call.
// Internally the iterator pages through the provider's native page size
// (typically 1 000 objects for S3) so memory stays bounded even for
// very large directories.
func (f *blobDirFile) Readdir(count int) ([]os.FileInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.iter == nil {
		f.iter = f.bucket.List(&blob.ListOptions{Prefix: f.prefix, Delimiter: "/"})
	}

	if f.done {
		return nil, io.EOF
	}

	var entries []os.FileInfo
	for {
		if count > 0 && len(entries) >= count {
			break
		}

		obj, err := f.iter.Next(context.Background())
		if err == io.EOF {
			f.done = true
			break
		}
		if err != nil {
			return entries, err
		}

		baseName := strings.TrimPrefix(obj.Key, f.prefix)
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

	if len(entries) == 0 && f.done {
		return nil, io.EOF
	}
	return entries, nil
}

func (f *blobDirFile) Stat() (os.FileInfo, error) {
	return &blobFileInfo{
		name:  path.Base(f.name),
		isDir: true,
	}, nil
}

// ---------------------------------------------------------------------------
// S3 credential loading (reads key files from disk)
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

// ---------------------------------------------------------------------------
// multiBucketBlobBackend — dynamic bucket backend for S3
//
// When S3Bucket is not configured, the first path component of each
// request is used as the bucket name.  For example, a request for
// "/foo/bar" resolves to bucket "foo", object key "bar".
//
// Bucket connections are opened lazily and cached for reuse.
// ---------------------------------------------------------------------------

type multiBucketBlobBackend struct {
	opts BlobBackendOptions

	mu      sync.RWMutex
	buckets map[string]*blob.Bucket
	group   singleflight.Group
}

func newMultiBucketBlobBackend(opts BlobBackendOptions) *multiBucketBlobBackend {
	// Set credentials in the environment so the gocloud AWS credential
	// chain picks them up for all buckets opened by this backend.
	if opts.AccessKey != "" && opts.SecretKey != "" {
		os.Setenv("AWS_ACCESS_KEY_ID", opts.AccessKey)
		os.Setenv("AWS_SECRET_ACCESS_KEY", opts.SecretKey)
	}
	return &multiBucketBlobBackend{
		opts:    opts,
		buckets: make(map[string]*blob.Bucket),
	}
}

// openBucket returns a cached bucket handle, opening one if necessary.
// Concurrent callers requesting the same bucket are coalesced via
// singleflight so that only one connection is established while other
// buckets can be opened in parallel.
func (mb *multiBucketBlobBackend) openBucket(bucketName string) (*blob.Bucket, error) {
	mb.mu.RLock()
	b, ok := mb.buckets[bucketName]
	mb.mu.RUnlock()
	if ok {
		return b, nil
	}

	// singleflight.Do deduplicates concurrent opens of the same bucket
	// while allowing different buckets to be opened in parallel.
	v, err, _ := mb.group.Do(bucketName, func() (interface{}, error) {
		// Re-check the cache inside the singleflight func — another
		// goroutine may have populated it before we were scheduled.
		mb.mu.RLock()
		if b, ok := mb.buckets[bucketName]; ok {
			mb.mu.RUnlock()
			return b, nil
		}
		mb.mu.RUnlock()

		blobURL, err := buildS3BlobURL(mb.opts, bucketName)
		if err != nil {
			return nil, err
		}

		// Anonymous access when no credentials are configured.
		if mb.opts.AccessKey == "" && mb.opts.SecretKey == "" {
			if os.Getenv("AWS_ACCESS_KEY_ID") == "" {
				if strings.Contains(blobURL, "?") {
					blobURL += "&anonymous=true"
				} else {
					blobURL += "?anonymous=true"
				}
			}
		}

		log.Infof("Opening blob bucket via URL: %s", blobURL)
		bucket, err := blob.OpenBucket(context.Background(), blobURL)
		if err != nil {
			return nil, fmt.Errorf("failed to open blob bucket from URL %q: %w", blobURL, err)
		}

		mb.mu.Lock()
		mb.buckets[bucketName] = bucket
		mb.mu.Unlock()

		return bucket, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*blob.Bucket), nil
}

// splitBucketPath splits a path like "/foo/bar/baz" into bucket name "foo"
// and remainder "/bar/baz".  Returns an error if the path has no bucket
// component.
func splitBucketPath(name string) (bucket, remainder string, err error) {
	clean := strings.TrimPrefix(path.Clean("/"+name), "/")
	if clean == "" {
		return "", "", fmt.Errorf("path %q does not contain a bucket component", name)
	}
	parts := strings.SplitN(clean, "/", 2)
	bucket = parts[0]
	if len(parts) > 1 {
		remainder = "/" + parts[1]
	} else {
		remainder = "/"
	}
	return bucket, remainder, nil
}

func (mb *multiBucketBlobBackend) CheckAvailability() error { return nil }

func (mb *multiBucketBlobBackend) FileSystem() webdav.FileSystem {
	return &multiBucketBlobFileSystem{backend: mb}
}

func (mb *multiBucketBlobBackend) Checksummer() server_utils.OriginChecksummer {
	return &multiBucketBlobChecksummer{backend: mb}
}

func (mb *multiBucketBlobBackend) Close() error {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	for name, b := range mb.buckets {
		if err := b.Close(); err != nil {
			log.Warnf("Error closing bucket %s: %v", name, err)
		}
	}
	mb.buckets = nil
	return nil
}

// ---------------------------------------------------------------------------
// multiBucketBlobFileSystem — webdav.FileSystem that dispatches to the
// correct bucket based on the first path component.
// ---------------------------------------------------------------------------

type multiBucketBlobFileSystem struct {
	backend *multiBucketBlobBackend
}

func (fs *multiBucketBlobFileSystem) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	bucketName, remainder, err := splitBucketPath(name)
	if err != nil {
		return err
	}
	bucket, err := fs.backend.openBucket(bucketName)
	if err != nil {
		return err
	}
	bfs := &blobFileSystem{bucket: bucket}
	return bfs.Mkdir(ctx, remainder, perm)
}

func (fs *multiBucketBlobFileSystem) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	bucketName, remainder, err := splitBucketPath(name)
	if err != nil {
		return nil, err
	}
	bucket, err := fs.backend.openBucket(bucketName)
	if err != nil {
		return nil, err
	}
	bfs := &blobFileSystem{bucket: bucket}
	return bfs.OpenFile(ctx, remainder, flag, perm)
}

func (fs *multiBucketBlobFileSystem) RemoveAll(ctx context.Context, name string) error {
	bucketName, remainder, err := splitBucketPath(name)
	if err != nil {
		return err
	}
	bucket, err := fs.backend.openBucket(bucketName)
	if err != nil {
		return err
	}
	bfs := &blobFileSystem{bucket: bucket}
	return bfs.RemoveAll(ctx, remainder)
}

func (fs *multiBucketBlobFileSystem) Rename(ctx context.Context, oldName, newName string) error {
	oldBucket, oldRemainder, err := splitBucketPath(oldName)
	if err != nil {
		return err
	}
	newBucket, newRemainder, err := splitBucketPath(newName)
	if err != nil {
		return err
	}
	if oldBucket != newBucket {
		return fmt.Errorf("cannot rename across buckets (%s -> %s)", oldBucket, newBucket)
	}
	bucket, err := fs.backend.openBucket(oldBucket)
	if err != nil {
		return err
	}
	bfs := &blobFileSystem{bucket: bucket}
	return bfs.Rename(ctx, oldRemainder, newRemainder)
}

func (fs *multiBucketBlobFileSystem) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	bucketName, remainder, err := splitBucketPath(name)
	if err != nil {
		return nil, err
	}
	bucket, err := fs.backend.openBucket(bucketName)
	if err != nil {
		return nil, err
	}
	bfs := &blobFileSystem{bucket: bucket}
	return bfs.Stat(ctx, remainder)
}

// ---------------------------------------------------------------------------
// multiBucketBlobChecksummer
// ---------------------------------------------------------------------------

type multiBucketBlobChecksummer struct {
	backend *multiBucketBlobBackend
}

func (c *multiBucketBlobChecksummer) GetDigests(relativePath, wantDigest string) ([]string, error) {
	bucketName, remainder, err := splitBucketPath(relativePath)
	if err != nil {
		return nil, nil
	}
	bucket, err := c.backend.openBucket(bucketName)
	if err != nil {
		return nil, nil
	}
	cs := &blobChecksummer{bucket: bucket}
	return cs.GetDigests(remainder, wantDigest)
}
