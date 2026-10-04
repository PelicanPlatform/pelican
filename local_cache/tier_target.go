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
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// tierIdentityKey is the object key holding the target's identity UUID,
// mirroring the .pelican-cache-id file dropped in POSIX storage directories.
// The UUID lets a target be re-associated with its storage ID when its URL or
// credentials change.
const tierIdentityKey = ".pelican-cache-id"

// tierTarget is one remote storage target: a TierBackend plus the cache-side
// concerns that are the same no matter what the backend is -- the key layout,
// the identity object, and whether the backend can serve redirects.
//
// Keeping these here rather than in TierBackend is deliberate.  The key
// layout is a property of the cache, not of the storage, and every backend
// must use the same one or the consistency sweep's merge join breaks.
type tierTarget struct {
	id      StorageID
	cfg     TierTargetConfig
	backend TierBackend

	// canRedirect records the result of probing the backend for redirect
	// support at startup; see TierRedirector.
	canRedirect bool

	// redirectScheme and redirectHost are where this target's redirect URLs
	// point, learned from the startup probe.  They are what a client would be
	// sent to, so they -- not the configured endpoint -- are what the
	// Authorization-forwarding rule is checked against.  That matters for
	// virtual-host addressing (the bucket name becomes a host label) and for
	// targets named by ProviderURL, which have no endpoint field at all.
	//
	// Knowing them up front lets the per-request check run before a URL is
	// minted.  For S3 minting is a local HMAC, but for a backend that has to
	// fetch a credential to build the URL it is a network round trip, and a
	// request that is going to be proxied anyway should not pay for one.
	redirectScheme string
	redirectHost   string
}

// newTierTarget opens the backend for cfg and probes its capabilities.  No
// object I/O happens beyond the capability probe; identity resolution is a
// separate, explicit step.
func newTierTarget(ctx context.Context, cfg TierTargetConfig) (*tierTarget, error) {
	backend, err := newBlobTierBackend(ctx, cfg)
	if err != nil {
		return nil, err
	}
	t := &tierTarget{cfg: cfg, backend: backend}
	if probe, ok := probeTierRedirect(ctx, backend); ok {
		if u, perr := url.Parse(probe); perr == nil {
			t.canRedirect = true
			t.redirectScheme = strings.ToLower(u.Scheme)
			t.redirectHost = u.Host
		}
	}
	if !t.canRedirect {
		log.Infof("Cache tier target %s cannot issue redirect URLs; its objects will be proxied through the cache",
			cfg.DisplayURL())
	}
	return t, nil
}

// probeTierRedirect asks a backend for a sample redirect URL, reporting
// whether it can produce one at all.
func probeTierRedirect(ctx context.Context, backend TierBackend) (string, bool) {
	if prober, ok := backend.(interface {
		probeRedirect(context.Context) (string, bool)
	}); ok {
		return prober.probeRedirect(ctx)
	}
	return "", false
}

// redirectSendsCredentials reports whether a client that reached this cache
// as reqHost, if redirected to this target, would carry its Authorization
// header along -- in which case the cache must proxy rather than redirect.
//
// A destination that is not http(s) cannot forward anything: the client
// opens it directly rather than making a request to a host, so there is no
// header on the wire.  That is what lets a target hand out file:// URLs to
// clients that share its storage.
func (t *tierTarget) redirectSendsCredentials(reqHost string) bool {
	switch t.redirectScheme {
	case "http", "https":
		return redirectRetainsAuthorization(t.redirectHost, reqHost)
	case "":
		// Nothing was learned; assume the worst so the caller proxies.
		return true
	default:
		return false
	}
}

// DisplayURL is the credential-free identity string for logs and the
// DiskMapping.Directory column.
func (t *tierTarget) DisplayURL() string { return t.cfg.DisplayURL() }

// Close releases the backend's client resources.
func (t *tierTarget) Close() error { return t.backend.Close() }

// objectKey returns the backend key for an instance hash.
//
// The layout is the same aa/bb/rest fan-out POSIX directories use, which
// matters for more than familiarity: because the first characters of the key
// are the first characters of the hash, a key-ordered listing is also a
// hash-ordered listing, and the consistency sweep can merge-join it against
// hash-ordered metadata instead of buffering the whole bucket.
//
// Keys are relative to the configured prefix; the backend applies it.
func (t *tierTarget) objectKey(instanceHash InstanceHash) string {
	return GetInstanceStoragePath(instanceHash)
}

// hashFromKey converts a backend key back to an instance hash, undoing the
// aa/bb/rest fan-out.  Returns "" when the key is not a cache object (the
// identity object, say).
func (t *tierTarget) hashFromKey(key string) InstanceHash {
	parts := strings.SplitN(key, "/", 3)
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

// resolveIdentity reads the identity UUID from the target, creating it when
// missing.  This is backend-agnostic: it is just a small well-known object.
func (t *tierTarget) resolveIdentity(ctx context.Context) (string, error) {
	body, err := t.backend.OpenRange(ctx, tierIdentityKey, 0)
	if err == nil {
		defer body.Close()
		data, readErr := io.ReadAll(io.LimitReader(body, 128))
		if readErr == nil {
			id := strings.TrimSpace(string(data))
			if _, parseErr := uuid.Parse(id); parseErr == nil {
				return id, nil
			}
		}
		log.Warnf("Cache tier target %s has an invalid identity object; rewriting", t.DisplayURL())
	} else if _, exists, statErr := t.backend.Stat(ctx, tierIdentityKey); statErr == nil && exists {
		// The object is there but unreadable -- that is a real failure, not
		// a first-use case, so do not silently take ownership of the target.
		return "", errors.Wrapf(err, "failed to read the identity object from cache tier target %s", t.DisplayURL())
	}

	newID := uuid.New().String()
	if err := t.backend.Put(ctx, tierIdentityKey, "text/plain", int64(len(newID)), strings.NewReader(newID)); err != nil {
		return "", errors.Wrapf(err, "failed to write the identity object to cache tier target %s", t.DisplayURL())
	}
	return newID, nil
}

// uploadObject streams plaintext object bytes to the target.
func (t *tierTarget) uploadObject(ctx context.Context, instanceHash InstanceHash, contentType string, size int64, body io.Reader) error {
	return t.backend.Put(ctx, t.objectKey(instanceHash), contentType, size, body)
}

// deleteObject removes an object.  Missing objects are not an error.
func (t *tierTarget) deleteObject(ctx context.Context, instanceHash InstanceHash) error {
	return t.backend.Delete(ctx, t.objectKey(instanceHash))
}

// objectExists probes the target for an object.
func (t *tierTarget) objectExists(ctx context.Context, instanceHash InstanceHash) (bool, error) {
	_, exists, err := t.objectSize(ctx, instanceHash)
	return exists, err
}

// objectSize probes the target for an object's size.
func (t *tierTarget) objectSize(ctx context.Context, instanceHash InstanceHash) (int64, bool, error) {
	return t.backend.Stat(ctx, t.objectKey(instanceHash))
}

// openStream starts a read at the given byte offset.
func (t *tierTarget) openStream(ctx context.Context, instanceHash InstanceHash, offset int64) (io.ReadCloser, error) {
	return t.backend.OpenRange(ctx, t.objectKey(instanceHash), offset)
}

// redirectURL returns a URL the client can fetch directly, or an error when
// the backend cannot issue one.  Callers should check canRedirect first.
func (t *tierTarget) redirectURL(ctx context.Context, instanceHash InstanceHash, expiry time.Duration) (string, error) {
	redirector, ok := t.backend.(TierRedirector)
	if !ok {
		return "", errors.Errorf("cache tier target %s cannot issue redirect URLs", t.DisplayURL())
	}
	return redirector.RedirectURL(ctx, t.objectKey(instanceHash), expiry)
}

// listObjects walks the target in instance-hash order, skipping keys that are
// not cache objects.
func (t *tierTarget) listObjects(ctx context.Context, fn func(hash InstanceHash, size int64, modified time.Time) error) error {
	return t.backend.List(ctx, func(key string, size int64, modified time.Time) error {
		hash := t.hashFromKey(key)
		if hash == "" {
			return nil
		}
		return fn(hash, size, modified)
	})
}

// reapStaleUploads asks the backend to clean up incomplete uploads older than
// maxAge.  Backends with no such concept report zero.
func (t *tierTarget) reapStaleUploads(ctx context.Context, maxAge time.Duration) (int, error) {
	reaper, ok := t.backend.(TierStaleUploadReaper)
	if !ok {
		return 0, nil
	}
	return reaper.ReapStaleUploads(ctx, maxAge)
}

// tierObjectStream adapts a lazily-opened backend read into an
// io.ReadSeekCloser suitable for http.ServeContent.  ServeContent's access
// pattern is a couple of Seeks (to learn the size / position) followed by a
// sequential read of one range, so this opens at most one request per served
// range: Seek is a pure position update and the read starts on the first Read
// after a position change.
type tierObjectStream struct {
	ctx      context.Context
	target   *tierTarget
	hash     InstanceHash
	size     int64
	position int64

	body       io.ReadCloser
	bodyOffset int64 // position the current body corresponds to

	// onClose releases resources held for the lifetime of the stream -- for a
	// stream serving a client, the reader pin that keeps eviction from
	// deleting the remote object mid-transfer.  Called once, by Close.
	onClose func()
}

func newTierObjectStream(ctx context.Context, target *tierTarget, hash InstanceHash, size int64) *tierObjectStream {
	return &tierObjectStream{ctx: ctx, target: target, hash: hash, size: size}
}

func (s *tierObjectStream) Read(p []byte) (int, error) {
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
			// the backend) and return a generic error so proxy mode does
			// not disclose the backing store.
			log.Warnf("Failed to open a tier stream for %s: %v", s.hash, err)
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
		// should cost one re-issued request, not the whole proxied transfer.
		log.Warnf("Tier stream for %s failed at offset %d; will reopen: %v", s.hash, s.position, err)
		s.body.Close()
		s.body = nil
		if n > 0 {
			return n, nil
		}
		body, reopenErr := s.target.openStream(s.ctx, s.hash, s.position)
		if reopenErr != nil {
			log.Warnf("Failed to reopen the tier stream for %s: %v", s.hash, reopenErr)
			return 0, errors.Errorf("failed to read object %s from backing storage", s.hash)
		}
		s.body = body
		s.bodyOffset = s.position
		return 0, nil
	}
	if err == io.EOF && s.position < s.size {
		// Short object relative to metadata -- surface as an error rather
		// than silently truncating the response.
		return n, errors.Errorf("tiered object %s ended at %d bytes; expected %d", s.hash, s.position, s.size)
	}
	return n, err
}

func (s *tierObjectStream) Seek(offset int64, whence int) (int64, error) {
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

func (s *tierObjectStream) Close() error {
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
