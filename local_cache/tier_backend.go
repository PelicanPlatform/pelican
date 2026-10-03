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
	"net/http"
	"net/url"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/azureblob" // register azblob:// URL opener
	_ "gocloud.dev/blob/gcsblob"   // register gs:// URL opener
	_ "gocloud.dev/blob/memblob"   // register mem:// URL opener (testing)
	"gocloud.dev/blob/s3blob"
	"gocloud.dev/gcerrors"
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
	// Put stores size bytes read from body under key.  It reports an error
	// if fewer than size bytes arrive, and makes a best effort to abort a
	// partial write rather than commit a short object.
	Put(ctx context.Context, key, contentType string, size int64, body io.Reader) error

	// OpenRange returns a reader for the object starting at offset.
	OpenRange(ctx context.Context, key string, offset int64) (io.ReadCloser, error)

	// Stat reports an object's size.  A missing object is (0, false, nil),
	// not an error.
	Stat(ctx context.Context, key string) (size int64, exists bool, err error)

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

// TierRedirector is implemented by backends that can hand a client a URL it
// can fetch directly, carrying its own authorization.  This is the capability
// that lets the cache redirect instead of proxying; a backend that cannot do
// it (or is not configured to) simply does not implement this, and the cache
// serves the bytes itself.
type TierRedirector interface {
	// RedirectURL returns a self-authenticating URL for a GET of key, valid
	// for expiry.  The URL must not require the caller to present any
	// Pelican credential.
	RedirectURL(ctx context.Context, key string, expiry time.Duration) (string, error)
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
		bucket, err = blob.OpenBucket(ctx, cfg.ProviderURL)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to open cache tier target %s", cfg.DisplayURL())
		}
		// Recover the S3 client when the URL happened to name an S3 bucket.
		if !bucket.As(&client) {
			client = nil
		}
		if u, perr := url.Parse(cfg.ProviderURL); perr == nil {
			bucketName = u.Host
		}
	} else {
		bucket, client, err = openS3TierBucket(ctx, cfg)
		if err != nil {
			return nil, err
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

// openS3TierBucket builds an S3 bucket from the explicit S3 fields, mirroring
// the origin's blob backend so both halves of Pelican reach an S3-compatible
// service the same way.
func openS3TierBucket(ctx context.Context, cfg TierTargetConfig) (*blob.Bucket, *s3.Client, error) {
	cfgOpts := []func(*awsconfig.LoadOptions) error{}
	if cfg.Region != "" {
		cfgOpts = append(cfgOpts, awsconfig.WithRegion(cfg.Region))
	}
	if cfg.AccessKeyfile != "" {
		accessKey, secretKey, err := readTierKeyfiles(cfg.AccessKeyfile, cfg.SecretKeyfile)
		if err != nil {
			return nil, nil, err
		}
		cfgOpts = append(cfgOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
		))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to load AWS config for cache tier target %s", cfg.DisplayURL())
	}

	var s3Opts []func(*s3.Options)
	// Path-style addressing is required by most S3-compatible services and
	// custom endpoints; virtual-host style is opt-in.
	if !cfg.UsesVirtualHostStyle() {
		s3Opts = append(s3Opts, func(o *s3.Options) { o.UsePathStyle = true })
	}
	if cfg.ServiceUrl != "" {
		endpoint := cfg.ServiceUrl
		s3Opts = append(s3Opts, func(o *s3.Options) { o.BaseEndpoint = &endpoint })
	}
	client := s3.NewFromConfig(awsCfg, s3Opts...)

	// The upload manager does not inherit the checksum-calculation setting
	// from the config, so propagate it for third-party S3 providers.
	bucket, err := s3blob.OpenBucket(ctx, client, cfg.Bucket, &s3blob.Options{
		RequestChecksumCalculation: awsCfg.RequestChecksumCalculation,
	})
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to open cache tier target %s", cfg.DisplayURL())
	}
	return bucket, client, nil
}

func (b *blobTierBackend) DisplayURL() string { return b.display }

func (b *blobTierBackend) Close() error { return b.bucket.Close() }

// Put streams body to the bucket.  Multipart chunking, where the driver
// supports it, is handled inside the writer.
func (b *blobTierBackend) Put(ctx context.Context, key, contentType string, size int64, body io.Reader) error {
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
		return errors.Wrapf(err, "failed to open %s for write on cache tier target %s", key, b.display)
	}
	n, copyErr := io.Copy(w, body)
	if copyErr == nil && n != size {
		copyErr = errors.Errorf("expected %d bytes, read %d", size, n)
	}
	if copyErr != nil {
		cancel()
		_ = w.Close()
		return errors.Wrapf(copyErr, "failed to upload %s to cache tier target %s", key, b.display)
	}
	if err := w.Close(); err != nil {
		return errors.Wrapf(err, "failed to upload %s to cache tier target %s", key, b.display)
	}
	return nil
}

func (b *blobTierBackend) OpenRange(ctx context.Context, key string, offset int64) (io.ReadCloser, error) {
	r, err := b.bucket.NewRangeReader(ctx, key, offset, -1, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open %s on cache tier target %s", key, b.display)
	}
	return r, nil
}

func (b *blobTierBackend) Stat(ctx context.Context, key string) (int64, bool, error) {
	attrs, err := b.bucket.Attributes(ctx, key)
	if err != nil {
		if isTierNotFound(err) {
			return 0, false, nil
		}
		return 0, false, errors.Wrapf(err, "failed to stat %s on cache tier target %s", key, b.display)
	}
	return attrs.Size, true, nil
}

func (b *blobTierBackend) Delete(ctx context.Context, key string) error {
	err := b.bucket.Delete(ctx, key)
	if err != nil && !isTierNotFound(err) {
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
func (b *blobTierBackend) RedirectURL(ctx context.Context, key string, expiry time.Duration) (string, error) {
	url, err := b.bucket.SignedURL(ctx, key, &blob.SignedURLOptions{Expiry: expiry})
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

// isTierNotFound reports whether an error from the blob layer means the object
// is absent.  gocloud's own classification covers the documented S3 error
// codes; isS3NotFound adds the forms it does not.
func isTierNotFound(err error) bool {
	return gcerrors.Code(err) == gcerrors.NotFound || isS3NotFound(err)
}

// isS3NotFound reports whether an S3 error indicates a missing object.
//
// The typed errors cover the documented cases, but a HeadObject against a
// missing key, and several S3-compatible implementations in general, answer
// with a bare 404 that the SDK surfaces as a generic API error.  Those are
// recognised by inspecting the HTTP status the response carries rather than by
// matching error text, so a provider that phrases its errors differently
// cannot turn "absent" into a hard failure -- which would make deletes
// non-idempotent and leave the consistency sweep unable to ever reconcile the
// entry it was checking.
//
// gocloud.dev's s3blob classifies by API error code alone, so it misses
// exactly these: a bare 404 with no parseable code comes back as
// gcerrors.Unknown.  Its errors keep the underlying cause reachable through
// Unwrap, which is what lets this check run on them.
func isS3NotFound(err error) bool {
	if err == nil {
		return false
	}
	var noKey *s3types.NoSuchKey
	var notFound *s3types.NotFound
	if errors.As(err, &noKey) || errors.As(err, &notFound) {
		return true
	}
	var respErr *awshttp.ResponseError
	if errors.As(err, &respErr) {
		return respErr.HTTPStatusCode() == http.StatusNotFound
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "NoSuchKey", "NotFound", "404":
			return true
		}
	}
	return false
}
