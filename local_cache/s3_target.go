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
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// s3IdentityKey is the object key (under the configured prefix) that holds
// the target's identity UUID, mirroring the .pelican-cache-id file dropped
// in POSIX storage directories.  The UUID lets a bucket be re-associated
// with its storage ID when the endpoint URL or credentials change.
const s3IdentityKey = ".pelican-cache-id"

// s3Target wraps the AWS SDK clients for one S3 bucket used as a cache
// storage target.  Objects are stored unencrypted under
// <prefix>/<aa>/<bb>/<rest-of-instance-hash> — the same fan-out layout as
// POSIX directories, which keeps bucket listings in instance-hash order for
// the consistency sweep's merge join.
type s3Target struct {
	id      StorageID
	cfg     S3TargetConfig
	client  *s3.Client
	presign *s3.PresignClient
	upload  *manager.Uploader
}

// newS3Target constructs the SDK clients for a target.  No network I/O is
// performed here; identity resolution happens in (*s3Target).resolveIdentity.
func newS3Target(ctx context.Context, cfg S3TargetConfig) (*s3Target, error) {
	cfgOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(cfg.Region),
	}
	if cfg.AccessKeyfile != "" {
		accessKey, secretKey, err := readS3Keyfiles(cfg.AccessKeyfile, cfg.SecretKeyfile)
		if err != nil {
			return nil, err
		}
		cfgOpts = append(cfgOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
		))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load AWS config for cache S3 target %s", cfg.Bucket)
	}

	var s3Opts []func(*s3.Options)
	if strings.ToLower(cfg.UrlStyle) != "virtual" {
		s3Opts = append(s3Opts, func(o *s3.Options) { o.UsePathStyle = true })
	}
	endpoint := cfg.ServiceUrl
	s3Opts = append(s3Opts, func(o *s3.Options) { o.BaseEndpoint = &endpoint })

	client := s3.NewFromConfig(awsCfg, s3Opts...)
	return &s3Target{
		cfg:     cfg,
		client:  client,
		presign: s3.NewPresignClient(client),
		upload:  manager.NewUploader(client),
	}, nil
}

// readS3Keyfiles loads static credentials from the configured key files,
// mirroring the origin's S3 credential handling (whole file, trimmed).
func readS3Keyfiles(accessKeyFile, secretKeyFile string) (accessKey, secretKey string, err error) {
	akBytes, err := os.ReadFile(accessKeyFile)
	if err != nil {
		return "", "", errors.Wrap(err, "failed to read S3 access keyfile")
	}
	skBytes, err := os.ReadFile(secretKeyFile)
	if err != nil {
		return "", "", errors.Wrap(err, "failed to read S3 secret keyfile")
	}
	return strings.TrimSpace(string(akBytes)), strings.TrimSpace(string(skBytes)), nil
}

// objectKey returns the bucket key for an instance hash.
func (t *s3Target) objectKey(instanceHash InstanceHash) string {
	return t.keyForStoragePath(GetInstanceStoragePath(instanceHash))
}

// keyForStoragePath prepends the configured prefix to a storage-relative path.
func (t *s3Target) keyForStoragePath(rel string) string {
	if t.cfg.Prefix == "" {
		return rel
	}
	return path.Join(t.cfg.Prefix, rel)
}

// hashFromKey converts a bucket key back to an instance hash, undoing the
// prefix and the aa/bb/rest fan-out.  Returns "" when the key does not look
// like a cache object (e.g. the identity object).
func (t *s3Target) hashFromKey(key string) InstanceHash {
	rel := key
	if t.cfg.Prefix != "" {
		var ok bool
		rel, ok = strings.CutPrefix(key, t.cfg.Prefix+"/")
		if !ok {
			return ""
		}
	}
	parts := strings.SplitN(rel, "/", 3)
	if len(parts) != 3 || len(parts[0]) != 2 || len(parts[1]) != 2 {
		return ""
	}
	hash := parts[0] + parts[1] + parts[2]
	if len(hash) != 64 {
		return ""
	}
	for _, c := range hash {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ""
		}
	}
	return InstanceHash(hash)
}

// resolveIdentity reads the identity UUID object from the bucket, creating
// it when missing.  Returns the UUID string.
func (t *s3Target) resolveIdentity(ctx context.Context) (string, error) {
	key := t.keyForStoragePath(s3IdentityKey)
	out, err := t.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &t.cfg.Bucket,
		Key:    &key,
	})
	if err == nil {
		defer out.Body.Close()
		data, readErr := io.ReadAll(io.LimitReader(out.Body, 128))
		if readErr == nil {
			id := strings.TrimSpace(string(data))
			if _, parseErr := uuid.Parse(id); parseErr == nil {
				return id, nil
			}
		}
		log.Warnf("Cache S3 target %s has an invalid identity object; rewriting", t.cfg.DisplayURL())
	} else if !isS3NotFound(err) {
		return "", errors.Wrapf(err, "failed to read identity object from cache S3 target %s", t.cfg.DisplayURL())
	}

	newID := uuid.New().String()
	body := strings.NewReader(newID)
	if _, err := t.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &t.cfg.Bucket,
		Key:    &key,
		Body:   body,
	}); err != nil {
		return "", errors.Wrapf(err, "failed to write identity object to cache S3 target %s", t.cfg.DisplayURL())
	}
	return newID, nil
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

// uploadObject streams plaintext object bytes to the bucket.  Multipart is
// handled by the SDK's upload manager; on error, incomplete parts are
// aborted automatically (LeavePartsOnError defaults to false).
func (t *s3Target) uploadObject(ctx context.Context, instanceHash InstanceHash, contentType string, size int64, body io.Reader) error {
	key := t.objectKey(instanceHash)
	input := &s3.PutObjectInput{
		Bucket:        &t.cfg.Bucket,
		Key:           &key,
		Body:          body,
		ContentLength: &size,
	}
	if contentType != "" {
		input.ContentType = &contentType
	}
	_, err := t.upload.Upload(ctx, input)
	return errors.Wrapf(err, "failed to upload %s to cache S3 target %s", instanceHash, t.cfg.DisplayURL())
}

// deleteObject removes an object from the bucket.  Missing objects are not
// an error (deletion is idempotent).
func (t *s3Target) deleteObject(ctx context.Context, instanceHash InstanceHash) error {
	key := t.objectKey(instanceHash)
	_, err := t.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &t.cfg.Bucket,
		Key:    &key,
	})
	if err != nil && !isS3NotFound(err) {
		return errors.Wrapf(err, "failed to delete %s from cache S3 target %s", instanceHash, t.cfg.DisplayURL())
	}
	return nil
}

// objectExists probes the bucket for an object via HeadObject.
func (t *s3Target) objectExists(ctx context.Context, instanceHash InstanceHash) (bool, error) {
	_, exists, err := t.objectSize(ctx, instanceHash)
	return exists, err
}

// objectSize probes the bucket for an object's size via HeadObject.
func (t *s3Target) objectSize(ctx context.Context, instanceHash InstanceHash) (size int64, exists bool, err error) {
	key := t.objectKey(instanceHash)
	out, err := t.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &t.cfg.Bucket,
		Key:    &key,
	})
	if err == nil {
		if out.ContentLength != nil {
			size = *out.ContentLength
		}
		return size, true, nil
	}
	if isS3NotFound(err) {
		return 0, false, nil
	}
	return 0, false, errors.Wrapf(err, "failed to stat %s on cache S3 target %s", instanceHash, t.cfg.DisplayURL())
}

// presignGet returns a pre-signed GET URL for the object.
func (t *s3Target) presignGet(ctx context.Context, instanceHash InstanceHash, expiry time.Duration) (string, error) {
	key := t.objectKey(instanceHash)
	req, err := t.presign.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: &t.cfg.Bucket,
		Key:    &key,
	}, s3.WithPresignExpires(expiry))
	if err != nil {
		return "", errors.Wrapf(err, "failed to presign GET for %s on cache S3 target %s", instanceHash, t.cfg.DisplayURL())
	}
	return req.URL, nil
}

// openStream starts a GET at the given byte offset and returns the body.
// Used by the proxying read path; a Seek discards the stream and opens a
// new one at the target offset.
func (t *s3Target) openStream(ctx context.Context, instanceHash InstanceHash, offset int64) (io.ReadCloser, error) {
	key := t.objectKey(instanceHash)
	input := &s3.GetObjectInput{
		Bucket: &t.cfg.Bucket,
		Key:    &key,
	}
	if offset > 0 {
		rng := fmt.Sprintf("bytes=%d-", offset)
		input.Range = &rng
	}
	out, err := t.client.GetObject(ctx, input)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open %s on cache S3 target %s", instanceHash, t.cfg.DisplayURL())
	}
	return out.Body, nil
}

// listObjects walks the bucket under the configured prefix in lexicographic
// key order, invoking fn for each cache object (identity and non-cache keys
// are skipped).  Because the key layout mirrors GetInstanceStoragePath, the
// callback observes instance hashes in sorted order.
func (t *s3Target) listObjects(ctx context.Context, fn func(hash InstanceHash, size int64, modified time.Time) error) error {
	input := &s3.ListObjectsV2Input{
		Bucket: &t.cfg.Bucket,
	}
	if t.cfg.Prefix != "" {
		prefix := t.cfg.Prefix + "/"
		input.Prefix = &prefix
	}
	paginator := s3.NewListObjectsV2Paginator(t.client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return errors.Wrapf(err, "failed to list cache S3 target %s", t.cfg.DisplayURL())
		}
		for _, obj := range page.Contents {
			if obj.Key == nil {
				continue
			}
			hash := t.hashFromKey(*obj.Key)
			if hash == "" {
				continue
			}
			var size int64
			if obj.Size != nil {
				size = *obj.Size
			}
			var modified time.Time
			if obj.LastModified != nil {
				modified = *obj.LastModified
			}
			if err := fn(hash, size, modified); err != nil {
				return err
			}
		}
	}
	return nil
}

// abortStaleMultipartUploads aborts multipart uploads under the prefix that
// started more than maxAge ago.  Incomplete multipart parts are invisible to
// listings but still consume bucket space; this reclaims them after crashes.
func (t *s3Target) abortStaleMultipartUploads(ctx context.Context, maxAge time.Duration) (aborted int, err error) {
	input := &s3.ListMultipartUploadsInput{
		Bucket: &t.cfg.Bucket,
	}
	if t.cfg.Prefix != "" {
		prefix := t.cfg.Prefix + "/"
		input.Prefix = &prefix
	}
	cutoff := time.Now().Add(-maxAge)
	for {
		out, listErr := t.client.ListMultipartUploads(ctx, input)
		if listErr != nil {
			return aborted, errors.Wrapf(listErr, "failed to list multipart uploads on cache S3 target %s", t.cfg.DisplayURL())
		}
		for _, up := range out.Uploads {
			if up.Key == nil || up.UploadId == nil {
				continue
			}
			if up.Initiated != nil && up.Initiated.After(cutoff) {
				continue
			}
			_, abortErr := t.client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
				Bucket:   &t.cfg.Bucket,
				Key:      up.Key,
				UploadId: up.UploadId,
			})
			if abortErr != nil {
				log.Warnf("Failed to abort stale multipart upload %s on cache S3 target %s: %v",
					*up.Key, t.cfg.DisplayURL(), abortErr)
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

// s3ObjectStream adapts a lazily-opened S3 GET stream into an
// io.ReadSeekCloser suitable for http.ServeContent.  ServeContent's access
// pattern is a couple of Seeks (to learn the size / position) followed by a
// sequential read of one range, so the implementation opens at most one GET
// per served range: Seek is a pure position update and the GET starts on the
// first Read after a position change.
type s3ObjectStream struct {
	ctx      context.Context
	target   *s3Target
	hash     InstanceHash
	size     int64
	position int64

	body       io.ReadCloser
	bodyOffset int64 // position the current body corresponds to

	// onClose releases resources held for the lifetime of the stream -- for a
	// stream serving a client, the reader pin that keeps eviction from
	// deleting the bucket object mid-transfer.  Called once, by Close.
	onClose func()
}

func newS3ObjectStream(ctx context.Context, target *s3Target, hash InstanceHash, size int64) *s3ObjectStream {
	return &s3ObjectStream{ctx: ctx, target: target, hash: hash, size: size}
}

func (s *s3ObjectStream) Read(p []byte) (int, error) {
	if s.position >= s.size {
		return 0, io.EOF
	}
	if s.body == nil || s.bodyOffset != s.position {
		if s.body != nil {
			s.body.Close()
			s.body = nil
		}
		body, err := s.target.openStream(s.ctx, s.hash, s.position)
		if err != nil {
			// Read errors can surface to clients via the response body or
			// the X-Transfer-Status trailer; log the detail (which names
			// the endpoint/bucket) and return a generic error so proxy
			// mode does not disclose the backing store.
			log.Warnf("Failed to open S3 stream for %s: %v", s.hash, err)
			return 0, errors.Errorf("failed to read object %s from backing storage", s.hash)
		}
		s.body = body
		s.bodyOffset = s.position
	}
	n, err := s.body.Read(p)
	s.position += int64(n)
	s.bodyOffset = s.position
	if err != nil && err != io.EOF {
		// The body is no longer usable.  Drop it and leave bodyOffset where it
		// is so the next Read reopens at the current position rather than
		// reading on through a broken stream: a mid-transfer network blip
		// should cost one re-issued GET, not the whole proxied transfer.
		log.Warnf("S3 stream for %s failed at offset %d; will reopen: %v", s.hash, s.position, err)
		s.body.Close()
		s.body = nil
		if n > 0 {
			return n, nil
		}
		body, reopenErr := s.target.openStream(s.ctx, s.hash, s.position)
		if reopenErr != nil {
			log.Warnf("Failed to reopen S3 stream for %s: %v", s.hash, reopenErr)
			return 0, errors.Errorf("failed to read object %s from backing storage", s.hash)
		}
		s.body = body
		s.bodyOffset = s.position
		return 0, nil
	}
	if err == io.EOF && s.position < s.size {
		// Short object relative to metadata — surface as an error rather
		// than silently truncating the response.
		return n, errors.Errorf("S3 object %s ended at %d bytes; expected %d", s.hash, s.position, s.size)
	}
	return n, err
}

func (s *s3ObjectStream) Seek(offset int64, whence int) (int64, error) {
	var newPos int64
	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = s.position + offset
	case io.SeekEnd:
		newPos = s.size + offset
	default:
		return 0, errors.New("invalid whence")
	}
	if newPos < 0 {
		return 0, errors.New("negative seek position")
	}
	s.position = newPos
	return newPos, nil
}

func (s *s3ObjectStream) Close() error {
	if s.onClose != nil {
		s.onClose()
		s.onClose = nil
	}
	if s.body != nil {
		err := s.body.Close()
		s.body = nil
		return err
	}
	return nil
}
