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

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	log "github.com/sirupsen/logrus"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/azureblob" // register azblob:// URL opener
	_ "gocloud.dev/blob/gcsblob"   // register gs:// URL opener
	_ "gocloud.dev/blob/memblob"   // register mem:// URL opener (useful for testing)
	"gocloud.dev/blob/s3blob"
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
	ctx := context.Background()

	var (
		bucket *blob.Bucket
		err    error
	)

	switch {
	case opts.BlobURL == "" && opts.AccessKey != "" && opts.SecretKey != "":
		// Native S3 export with per-export static credentials. Construct an
		// explicit *s3.Client so each backend carries its own credentials.
		// Previously the keys were exported into the global process
		// environment, which meant two S3 exports configured against
		// different accounts would clobber one another -- whichever was
		// initialized last won.
		bucket, err = openS3BucketWithCredentials(ctx, opts)
		if err != nil {
			return nil, err
		}
	default:
		// Generic gocloud.dev path: an explicit BlobURL (s3/gs/azblob/mem), or
		// an S3 bucket with no per-export credentials (anonymous, or ambient
		// credentials from the environment / instance role).
		blobURL := opts.BlobURL
		if blobURL == "" {
			// Build an s3:// URL from the backward-compatible S3-specific fields.
			blobURL, err = buildS3BlobURL(opts)
			if err != nil {
				return nil, err
			}
		}
		if strings.HasPrefix(blobURL, "s3://") && os.Getenv("AWS_ACCESS_KEY_ID") == "" {
			// No credentials available — request anonymous access so the SDK
			// doesn't probe IAM, instance metadata, etc.
			if strings.Contains(blobURL, "?") {
				blobURL += "&anonymous=true"
			} else {
				blobURL += "?anonymous=true"
			}
		}
		log.Infof("Opening blob bucket via URL: %s", redactBlobURL(blobURL))
		bucket, err = blob.OpenBucket(ctx, blobURL)
		if err != nil {
			return nil, fmt.Errorf("failed to open blob bucket from URL %q: %w", redactBlobURL(blobURL), err)
		}
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

// openS3BucketWithCredentials opens an S3 bucket using an explicit *s3.Client
// configured with static, per-export credentials. Unlike opening via an s3://
// URL (which relies on the ambient AWS credential chain backed by process-wide
// environment variables), this keeps each export's credentials local to its
// own client, so multiple S3 exports with distinct accounts can coexist within
// a single origin process.
func openS3BucketWithCredentials(ctx context.Context, opts BlobBackendOptions) (*blob.Bucket, error) {
	if opts.Bucket == "" {
		return nil, fmt.Errorf("S3 bucket name is required when BlobURL is not set")
	}

	cfgOpts := []func(*config.LoadOptions) error{
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(opts.AccessKey, opts.SecretKey, ""),
		),
	}
	if opts.Region != "" {
		cfgOpts = append(cfgOpts, config.WithRegion(opts.Region))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for bucket %q: %w", opts.Bucket, err)
	}

	var s3Opts []func(*s3.Options)
	// Default to path-style addressing (endpoint/bucket/key) unless virtual-host
	// style is explicitly requested; path-style is required by most
	// S3-compatible services (MinIO, Ceph) and custom endpoints.
	if strings.ToLower(opts.URLStyle) != "virtual" {
		s3Opts = append(s3Opts, func(o *s3.Options) { o.UsePathStyle = true })
	}
	if opts.ServiceURL != "" {
		endpoint := opts.ServiceURL
		s3Opts = append(s3Opts, func(o *s3.Options) { o.BaseEndpoint = &endpoint })
	}
	client := s3.NewFromConfig(awsCfg, s3Opts...)

	log.Infof("Opening S3 bucket %q with per-export credentials (endpoint: %q, region: %q)",
		opts.Bucket, opts.ServiceURL, opts.Region)

	// Mirror gocloud's URL opener: the S3 upload manager doesn't pick up the
	// checksum-calculation setting from the config, so propagate it explicitly
	// to preserve compatibility with third-party S3 providers.
	return s3blob.OpenBucket(ctx, client, opts.Bucket, &s3blob.Options{
		RequestChecksumCalculation: awsCfg.RequestChecksumCalculation,
	})
}

// redactBlobURL strips any embedded credentials (the userinfo component and
// well-known secret query parameters) from a blob URL so it is safe to log.
// Operators may embed secrets directly in Origin.ObjectProviderURL, e.g.
// "s3://bucket?awssecretkey=...", and those must never reach the logs.
func redactBlobURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		// If it doesn't parse we can't reason about it; don't risk leaking.
		return "[unparsable blob URL redacted]"
	}
	if u.User != nil {
		u.User = url.UserPassword("redacted", "redacted")
	}
	if q := u.Query(); len(q) > 0 {
		changed := false
		for key := range q {
			switch strings.ToLower(key) {
			case "awssecretkey", "secretkey", "secret_access_key", "access_key", "awsaccesskeyid", "password", "token":
				q.Set(key, "redacted")
				changed = true
			}
		}
		if changed {
			u.RawQuery = q.Encode()
		}
	}
	return u.Redacted()
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
		// will be created when Readdir is called). Carry the request context
		// so the deferred listing honours cancellation/deadlines.
		return &blobDirFile{name: name, bucket: fs.bucket, prefix: dirPrefix, ctx: ctx}, nil
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
//
// Per the webdav.FileSystem contract this must remove `name` and, if it is a
// directory, everything underneath it. The previous implementation only
// deleted the named object plus its directory marker, leaving children
// orphaned. We list the prefix and delete every key, then remove the marker.
//
// Listing is paginated so memory stays bounded for large directories. Each
// delete is best-effort -- a partial failure returns the first error but
// continues so we don't strand half a tree.
func (fs *blobFileSystem) RemoveAll(ctx context.Context, name string) error {
	key := blobKey(name)

	// First try a plain-object delete (handles non-directory paths).
	err := fs.bucket.Delete(ctx, key)
	if err != nil && !isNotFound(err) {
		return err
	}

	// Recursively delete anything under the directory prefix. Note we
	// intentionally don't pass a Delimiter here -- we want every descendant.
	dirPrefix := key
	if dirPrefix != "" && !strings.HasSuffix(dirPrefix, "/") {
		dirPrefix += "/"
	}
	iter := fs.bucket.List(&blob.ListOptions{Prefix: dirPrefix})
	var firstErr error
	for {
		obj, listErr := iter.Next(ctx)
		if listErr == io.EOF {
			break
		}
		if listErr != nil {
			if firstErr == nil {
				firstErr = listErr
			}
			break
		}
		if delErr := fs.bucket.Delete(ctx, obj.Key); delErr != nil && !isNotFound(delErr) {
			if firstErr == nil {
				firstErr = delErr
			}
		}
	}

	// Finally, the directory marker (some providers return it as a child of
	// the prefix above and some don't, so this is belt-and-suspenders).
	_ = fs.bucket.Delete(ctx, key+"/")
	return firstErr
}

// Rename implements webdav.FileSystem.
//
// Blob stores have no native rename, so we copy-then-delete. For a leaf object
// that is a single copy/delete. When oldName refers to a "directory" (a key
// prefix with children) we must also move every descendant -- otherwise the
// children would be orphaned under the old prefix. Listing is paginated so
// memory stays bounded for large trees, and each object is best-effort: a
// partial failure returns the first error but continues so we don't strand a
// half-moved tree.
func (fs *blobFileSystem) Rename(ctx context.Context, oldName, newName string) error {
	oldKey := blobKey(oldName)
	newKey := blobKey(newName)

	// Move the object at the exact key, if one exists. A missing object is not
	// an error here: oldName may be a pure directory prefix with no marker.
	if err := fs.bucket.Copy(ctx, newKey, oldKey, nil); err != nil {
		if !isNotFound(err) {
			return fmt.Errorf("blob copy %q -> %q: %w", oldKey, newKey, err)
		}
	} else if err := fs.bucket.Delete(ctx, oldKey); err != nil && !isNotFound(err) {
		return fmt.Errorf("blob delete %q: %w", oldKey, err)
	}

	// Move every descendant under the directory prefix.
	oldPrefix := oldKey
	if oldPrefix != "" && !strings.HasSuffix(oldPrefix, "/") {
		oldPrefix += "/"
	}
	newPrefix := newKey
	if newPrefix != "" && !strings.HasSuffix(newPrefix, "/") {
		newPrefix += "/"
	}

	iter := fs.bucket.List(&blob.ListOptions{Prefix: oldPrefix})
	var firstErr error
	for {
		obj, listErr := iter.Next(ctx)
		if listErr == io.EOF {
			break
		}
		if listErr != nil {
			if firstErr == nil {
				firstErr = listErr
			}
			break
		}
		destKey := newPrefix + strings.TrimPrefix(obj.Key, oldPrefix)
		if err := fs.bucket.Copy(ctx, destKey, obj.Key, nil); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("blob copy %q -> %q: %w", obj.Key, destKey, err)
			}
			continue
		}
		if err := fs.bucket.Delete(ctx, obj.Key); err != nil && !isNotFound(err) {
			if firstErr == nil {
				firstErr = fmt.Errorf("blob delete %q: %w", obj.Key, err)
			}
		}
	}
	return firstErr
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
	ctx    context.Context

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

		ctx := f.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		obj, err := f.iter.Next(ctx)
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
