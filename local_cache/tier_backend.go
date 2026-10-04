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
	"io"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/memblob" // register mem:// URL opener (testing); blobstore registers the rest
	"gocloud.dev/gcerrors"

	"github.com/pelicanplatform/pelican/blobstore"
)

// TierBackend is the remote storage a cache tiers completed objects to.
//
// It is deliberately a flat keyed blob store rather than a filesystem: the
// cache addresses objects by instance hash, needs ranged reads to serve them,
// and needs a key-ordered listing to reconcile the backend against its
// metadata.  That is a much smaller contract than server_utils.OriginBackend
// (a webdav.FileSystem), and a different one -- an origin backend serves a
// POSIX-ish namespace and has no notion of handing a client a URL.
//
// Keys are supplied by the caller and are backend-agnostic; see
// tierTarget.objectKey for the layout and why it is ordered.
type TierBackend interface {
	// Put stores size bytes read from body under key, and reports the
	// object as the backend then holds it.  It reports an error if fewer
	// than size bytes arrive, or if the stored object is not size bytes
	// long, and makes a best effort to abort a partial write rather than
	// commit a short object.
	Put(ctx context.Context, key, contentType string, size int64, body io.Reader) (TierObjectInfo, error)

	// OpenRange returns a reader for the object starting at offset.  When
	// expect is non-nil, the read is pinned to that copy of the object --
	// by version where the backend keeps versions, otherwise by entity tag
	// -- and fails with ErrTierObjectChanged if the backend no longer holds
	// it.  A backend that can do neither ignores expect.
	OpenRange(ctx context.Context, key string, offset int64, expect *TierObjectInfo) (io.ReadCloser, error)

	// Stat reports an object as the backend currently holds it.  A missing
	// object is (TierObjectInfo{}, false, nil), not an error.
	Stat(ctx context.Context, key string) (info TierObjectInfo, exists bool, err error)

	// Delete removes an object.  Deleting a missing object is not an error.
	Delete(ctx context.Context, key string) error

	// List walks every object under the backend's prefix in ascending key
	// order, which is what lets the consistency sweep merge-join the
	// listing against hash-ordered metadata instead of buffering it.
	List(ctx context.Context, fn func(key string, size int64, modified time.Time) error) error

	// DisplayURL is a human-readable identity for logs and for the
	// DiskMapping.Directory column.  It must not contain credentials.
	DisplayURL() string

	// Close releases any client resources.
	Close() error
}

// TierObjectInfo describes an object as a tiering target stored it.  The
// cache records it when an object is tiered, and uses it to tell whether the
// target still holds the same bytes.
//
// That matters because a tiered object is stored in plaintext and, unlike a
// local block, is not authenticated when read back: without a record, a
// same-length substitution in the bucket was undetectable.  Any write to an
// object changes its entity tag, and where the bucket keeps versions, the
// version identifier names the exact bytes uploaded -- so reads can be
// pinned to them even after the key is overwritten.
type TierObjectInfo struct {
	Size int64 `msgpack:"s"`
	// ETag is the backend's entity tag, opaque to the cache.  It is
	// compared only for equality: for S3 it is an MD5 of the content for a
	// simple upload but not for a multipart one, so it is not a checksum.
	ETag string `msgpack:"e,omitempty"`
	// Version is the backend's version identifier, set only where the
	// target keeps versions (an S3 bucket with versioning enabled).
	Version string `msgpack:"v,omitempty"`
	// ModTime is when the backend says the object was written.
	ModTime time.Time `msgpack:"m,omitempty"`
}

// ErrTierObjectChanged reports that a tiering target no longer holds the copy
// of an object the cache uploaded -- it was overwritten or replaced.
var ErrTierObjectChanged = errors.New("the tiering target no longer holds the copy of this object that was uploaded")

// TierRedirector is implemented by backends that can hand a client a URL it
// can fetch directly, carrying its own authorization.  This is the capability
// that lets the cache redirect instead of proxying; a backend that cannot do
// it (or is not configured to) simply does not implement this, and the cache
// serves the bytes itself.
type TierRedirector interface {
	// RedirectURL returns a self-authenticating URL for a GET of key, valid
	// for expiry.  The URL must not require the caller to present any
	// Pelican credential.  When expect names a version, the URL should
	// fetch that version, so a client sent there receives the bytes the
	// cache uploaded even if the key has since been overwritten.
	RedirectURL(ctx context.Context, key string, expiry time.Duration, expect *TierObjectInfo) (string, error)
}

// TierStaleUploadReaper is implemented by backends with a notion of an
// incomplete upload that survives a crash and consumes space invisibly --
// S3's multipart uploads being the motivating case.  Backends where a failed
// write leaves nothing behind do not implement it.
type TierStaleUploadReaper interface {
	// ReapStaleUploads aborts incomplete uploads older than maxAge and
	// returns how many were aborted.
	ReapStaleUploads(ctx context.Context, maxAge time.Duration) (int, error)
}

// blobTierBackend implements TierBackend over gocloud.dev/blob, which covers
// S3 (including S3-compatible services such as MinIO and Ceph), Google Cloud
// Storage, Azure Blob Storage, and the in-memory driver used by tests.
//
// It also implements TierRedirector via blob.SignedURL.  Whether a given
// driver can actually sign is not a static property of the driver -- GCS
// needs a signing key and fileblob needs a URLSigner -- so support is probed
// once at startup rather than assumed from the URL scheme.
type blobTierBackend struct {
	bucket  *blob.Bucket
	display string

	// s3Client is non-nil only when the underlying driver is S3, recovered
	// through gocloud's As() escape hatch.  It, and the bucket/prefix beside
	// it, exist solely for multipart reaping, which has no portable
	// equivalent and so cannot go through the blob API.
	s3Client *s3.Client
	s3Bucket string
	s3Prefix string
}

var (
	_ TierBackend           = (*blobTierBackend)(nil)
	_ TierRedirector        = (*blobTierBackend)(nil)
	_ TierStaleUploadReaper = (*blobTierBackend)(nil)
)

// newBlobTierBackend opens the bucket described by cfg.  No object I/O
// happens here; identity resolution is tierTarget's job.
func newBlobTierBackend(ctx context.Context, cfg TierTargetConfig) (*blobTierBackend, error) {
	var (
		bucket *blob.Bucket
		client *s3.Client
		err    error
	)
	bucketName := cfg.Bucket
	if cfg.ProviderURL != "" {
		// blobstore.OpenURL keeps the URL out of the error, which gocloud's
		// openers would otherwise quote verbatim.
		bucket, err = blobstore.OpenURL(ctx, cfg.ProviderURL)
		if err != nil {
			return nil, errors.Wrap(err, "failed to open cache tier target")
		}
		// Recover the S3 client when the URL happened to name an S3 bucket.
		if !bucket.As(&client) {
			client = nil
		}
		if u, perr := url.Parse(cfg.ProviderURL); perr == nil {
			bucketName = u.Host
		}
	} else {
		accessKey, secretKey, kerr := blobstore.ReadKeyfilePair(cfg.AccessKeyfile, cfg.SecretKeyfile)
		if kerr != nil {
			return nil, errors.Wrapf(kerr, "failed to load credentials for cache tier target %s", cfg.DisplayURL())
		}
		// With no keyfiles this falls through to the ambient credential
		// chain rather than anonymous access: a tier target is a bucket the
		// cache writes plaintext objects to, so it is private by design.
		bucket, client, err = blobstore.OpenS3(ctx, blobstore.S3Options{
			ServiceURL: cfg.ServiceUrl,
			Region:     cfg.Region,
			Bucket:     cfg.Bucket,
			URLStyle:   cfg.UrlStyle,
			AccessKey:  accessKey,
			SecretKey:  secretKey,
		})
		if err != nil {
			return nil, errors.Wrapf(err, "failed to open cache tier target %s", cfg.DisplayURL())
		}
	}

	prefix := trimTierPrefix(cfg.Prefix)
	if prefix != "" {
		// PrefixedBucket closes the bucket it wraps, so only the wrapper is
		// closed later.  Keys above this point are prefix-relative, which is
		// why nothing else in the cache has to think about the prefix.
		bucket = blob.PrefixedBucket(bucket, prefix+"/")
		prefix += "/"
	}

	return &blobTierBackend{
		bucket:   bucket,
		display:  cfg.DisplayURL(),
		s3Client: client,
		s3Bucket: bucketName,
		s3Prefix: prefix,
	}, nil
}

func (b *blobTierBackend) DisplayURL() string { return b.display }

func (b *blobTierBackend) Close() error { return b.bucket.Close() }

// Put streams body to the bucket.  Multipart chunking, where the driver
// supports it, is handled inside the writer.
func (b *blobTierBackend) Put(ctx context.Context, key, contentType string, size int64, body io.Reader) (TierObjectInfo, error) {
	// Aborting a partially written object means cancelling the writer's
	// context: blob.Writer has no explicit abort, and Close() on its own
	// would commit whatever was written.
	writeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	opts := &blob.WriterOptions{}
	if contentType != "" {
		opts.ContentType = contentType
	} else {
		// Without this the writer sniffs the first 512 bytes to guess a
		// content type, which costs a buffer copy and can only be wrong for
		// opaque cache objects.
		opts.DisableContentTypeDetection = true
	}

	w, err := b.bucket.NewWriter(writeCtx, key, opts)
	if err != nil {
		return TierObjectInfo{}, errors.Wrapf(err, "failed to open %s for write on cache tier target %s", key, b.display)
	}
	n, copyErr := io.Copy(w, body)
	if copyErr == nil && n != size {
		copyErr = errors.Errorf("expected %d bytes, read %d", size, n)
	}
	if copyErr != nil {
		cancel()
		_ = w.Close()
		return TierObjectInfo{}, errors.Wrapf(copyErr, "failed to upload %s to cache tier target %s", key, b.display)
	}
	if err := w.Close(); err != nil {
		return TierObjectInfo{}, errors.Wrapf(err, "failed to upload %s to cache tier target %s", key, b.display)
	}
	// Read back what the backend actually stored.  This records the entity
	// tag and version for later verification, and it is also the only
	// end-to-end confirmation that the whole object landed: a writer that
	// closed cleanly on a short object would otherwise go unnoticed.
	info, exists, err := b.Stat(ctx, key)
	if err != nil {
		return TierObjectInfo{}, errors.Wrapf(err, "failed to confirm the upload of %s to cache tier target %s", key, b.display)
	}
	if !exists || info.Size != size {
		return TierObjectInfo{}, errors.Errorf("upload of %s to cache tier target %s stored %d bytes; expected %d",
			key, b.display, info.Size, size)
	}
	return info, nil
}

func (b *blobTierBackend) OpenRange(ctx context.Context, key string, offset int64, expect *TierObjectInfo) (io.ReadCloser, error) {
	var opts *blob.ReaderOptions
	if expect != nil && (expect.Version != "" || expect.ETag != "") {
		opts = &blob.ReaderOptions{BeforeRead: func(as func(any) bool) error {
			var in *s3.GetObjectInput
			if !as(&in) {
				return nil // not S3: no way to pin the read
			}
			// A version names the exact bytes uploaded and survives the key
			// being overwritten; an entity tag can only detect that it was.
			if expect.Version != "" {
				in.VersionId = &expect.Version
			} else {
				in.IfMatch = &expect.ETag
			}
			return nil
		}}
	}
	r, err := b.bucket.NewRangeReader(ctx, key, offset, -1, opts)
	if err != nil {
		if gcerrors.Code(err) == gcerrors.FailedPrecondition {
			return nil, errors.Wrapf(ErrTierObjectChanged, "%s on cache tier target %s", key, b.display)
		}
		return nil, errors.Wrapf(err, "failed to open %s on cache tier target %s", key, b.display)
	}
	return r, nil
}

func (b *blobTierBackend) Stat(ctx context.Context, key string) (TierObjectInfo, bool, error) {
	attrs, err := b.bucket.Attributes(ctx, key)
	if err != nil {
		if blobstore.IsNotFound(err) {
			return TierObjectInfo{}, false, nil
		}
		return TierObjectInfo{}, false, errors.Wrapf(err, "failed to stat %s on cache tier target %s", key, b.display)
	}
	info := TierObjectInfo{Size: attrs.Size, ETag: attrs.ETag, ModTime: attrs.ModTime}
	var head s3.HeadObjectOutput
	if attrs.As(&head) && head.VersionId != nil && *head.VersionId != "null" {
		// S3 reports "null" for an object written while versioning was
		// off, which names no version a read could be pinned to.
		info.Version = *head.VersionId
	}
	return info, true, nil
}

func (b *blobTierBackend) Delete(ctx context.Context, key string) error {
	err := b.bucket.Delete(ctx, key)
	if err != nil && !blobstore.IsNotFound(err) {
		return errors.Wrapf(err, "failed to delete %s from cache tier target %s", key, b.display)
	}
	return nil
}

// List walks the bucket in key order.  blob.List documents a lexicographic
// ordering over UTF-8 keys for every driver, which is the property the
// consistency sweep's merge join depends on.
func (b *blobTierBackend) List(ctx context.Context, fn func(key string, size int64, modified time.Time) error) error {
	iter := b.bucket.List(&blob.ListOptions{})
	for {
		obj, err := iter.Next(ctx)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errors.Wrapf(err, "failed to list cache tier target %s", b.display)
		}
		if obj.IsDir {
			continue
		}
		if err := fn(obj.Key, obj.Size, obj.ModTime); err != nil {
			return err
		}
	}
}

// RedirectURL returns a pre-signed URL.  Drivers that cannot sign report
// gcerrors.Unimplemented, which tierTarget turns into "this backend cannot
// redirect" at startup.
func (b *blobTierBackend) RedirectURL(ctx context.Context, key string, expiry time.Duration, expect *TierObjectInfo) (string, error) {
	opts := &blob.SignedURLOptions{Expiry: expiry}
	if expect != nil && expect.Version != "" {
		// The version is part of the signed URL, so a client sent there
		// gets the bytes the cache uploaded even if the key was overwritten.
		// (An entity tag cannot be pinned this way: If-Match would be a
		// header the client has to send, and clients do not.)
		opts.BeforeSign = func(as func(any) bool) error {
			var in *s3.GetObjectInput
			if as(&in) {
				in.VersionId = &expect.Version
			}
			return nil
		}
	}
	url, err := b.bucket.SignedURL(ctx, key, opts)
	if err != nil {
		return "", errors.Wrapf(err, "failed to sign a URL for %s on cache tier target %s", key, b.display)
	}
	return url, nil
}

// probeRedirect asks the bucket to sign a URL for a key that need not exist,
// returning the URL when it can.  Whether a driver can sign is a property of
// the driver *and* its configuration -- GCS needs a signing key, fileblob a
// URLSigner -- so it cannot be inferred from the URL scheme.  The URL itself
// is also useful: its scheme and host are what a client would be sent to,
// which is what the Authorization-forwarding rule has to be evaluated against.
func (b *blobTierBackend) probeRedirect(ctx context.Context) (string, bool) {
	signed, err := b.bucket.SignedURL(ctx, tierRedirectProbeKey, &blob.SignedURLOptions{Expiry: time.Minute})
	if err == nil {
		return signed, true
	}
	if gcerrors.Code(err) != gcerrors.Unimplemented {
		// Any other error (a malformed key, say) says nothing about support.
		log.Debugf("Redirect-capability probe for cache tier target %s was inconclusive: %v", b.display, err)
	}
	return "", false
}

// tierRedirectProbeKey is signed but never fetched; SignedURL is documented
// to work for keys that do not exist.
const tierRedirectProbeKey = ".pelican-redirect-probe"

// ReapStaleUploads aborts S3 multipart uploads that outlived any plausible
// in-flight transfer.  Incomplete parts are invisible to listings but still
// consume bucket space, so a crash would otherwise leak them indefinitely.
//
// There is no portable equivalent, so this reaches through gocloud's As()
// escape hatch and does nothing on non-S3 drivers.
func (b *blobTierBackend) ReapStaleUploads(ctx context.Context, maxAge time.Duration) (int, error) {
	if b.s3Client == nil || b.s3Bucket == "" {
		return 0, nil
	}

	bucketName := b.s3Bucket
	input := &s3.ListMultipartUploadsInput{Bucket: &bucketName}
	if b.s3Prefix != "" {
		prefix := b.s3Prefix
		input.Prefix = &prefix
	}
	cutoff := time.Now().Add(-maxAge)
	aborted := 0
	for {
		out, err := b.s3Client.ListMultipartUploads(ctx, input)
		if err != nil {
			return aborted, errors.Wrapf(err, "failed to list multipart uploads on cache tier target %s", b.display)
		}
		for _, up := range out.Uploads {
			if up.Key == nil || up.UploadId == nil {
				continue
			}
			if up.Initiated != nil && up.Initiated.After(cutoff) {
				continue
			}
			if _, err := b.s3Client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
				Bucket:   &bucketName,
				Key:      up.Key,
				UploadId: up.UploadId,
			}); err != nil {
				log.Warnf("Failed to abort stale multipart upload %s on cache tier target %s: %v",
					*up.Key, b.display, err)
				continue
			}
			aborted++
		}
		if out.IsTruncated == nil || !*out.IsTruncated {
			return aborted, nil
		}
		input.KeyMarker = out.NextKeyMarker
		input.UploadIdMarker = out.NextUploadIdMarker
	}
}
