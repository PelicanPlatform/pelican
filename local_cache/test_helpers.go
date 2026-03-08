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
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

// BackdateObject shifts the Completed timestamp of a cached object backward
// by the given duration. This is useful for testing the Age response header
// without waiting for wall-clock time to elapse.
func (pc *PersistentCache) BackdateObject(objectPath string, age time.Duration) error {
	pelicanURL := pc.normalizePath(objectPath)
	objectHash := pc.db.ObjectHash(pelicanURL)

	etag, err := pc.db.GetLatestETag(objectHash)
	if err != nil {
		return fmt.Errorf("BackdateObject: lookup ETag: %w", err)
	}

	instanceHash := pc.db.InstanceHash(etag, objectHash)
	meta, err := pc.storage.GetMetadata(instanceHash)
	if err != nil {
		return fmt.Errorf("BackdateObject: get metadata: %w", err)
	}
	if meta == nil {
		return fmt.Errorf("BackdateObject: object %q not cached", objectPath)
	}

	meta.Completed = meta.Completed.Add(-age)
	if err := pc.storage.SetMetadata(instanceHash, meta); err != nil {
		return fmt.Errorf("BackdateObject: set metadata: %w", err)
	}
	return nil
}

// InitIssuerKeyForTests initializes issuer keys for testing.
// This must be called before creating a CacheDB or EncryptionManager.
// It generates a new issuer key in a temporary directory and registers a cleanup.
func InitIssuerKeyForTests(t testing.TB) {
	t.Helper()

	// Create a temp directory for the issuer keys
	keysDir := filepath.Join(t.TempDir(), "issuerKeys")

	// Set the IssuerKeysDirectory configuration
	require.NoError(t, param.Set(param.IssuerKeysDirectory.GetName(), keysDir))

	// This will generate a new key if none exists, and load it into memory
	_, err := config.GetIssuerPublicJWKS()
	require.NoError(t, err, "Failed to initialize issuer keys for testing")

	// Register cleanup to reset keys when test completes
	t.Cleanup(func() {
		config.ResetIssuerPrivateKeys()
	})
}

// CheckCacheObjectExists checks if an object exists in the PersistentCache by making
// a HEAD request to the cache's unix socket. Returns true if the object exists.
// NOTE: This will trigger a download if the object is not cached, so it always returns true
// unless the origin is unreachable. For testing eviction, use CheckCacheObjectIsCached instead.
func CheckCacheObjectExists(ctx context.Context, socketPath, objectPath string) (bool, error) {
	// Create a transport that dials the unix socket
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}

	client := &http.Client{Transport: transport}

	// Build the URL - host is ignored for unix sockets but required for URL validity
	reqURL := &url.URL{
		Scheme: "http",
		Host:   "localhost",
		Path:   objectPath,
	}

	req, err := http.NewRequestWithContext(ctx, "HEAD", reqURL.String(), nil)
	if err != nil {
		return false, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// 200 OK means object exists, 404 means it doesn't
	return resp.StatusCode == http.StatusOK, nil
}

// CheckCacheObjectIsCached checks if an object is actually in the cache (not just accessible).
// This sends a special header to prevent downloading if the object is not cached.
// Returns true only if the object is already cached, false if it would need to be downloaded.
func CheckCacheObjectIsCached(ctx context.Context, socketPath, objectPath string) (bool, error) {
	// Create a transport that dials the unix socket
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}

	client := &http.Client{Transport: transport}

	// Build the URL - host is ignored for unix sockets but required for URL validity
	reqURL := &url.URL{
		Scheme: "http",
		Host:   "localhost",
		Path:   objectPath,
	}

	req, err := http.NewRequestWithContext(ctx, "HEAD", reqURL.String(), nil)
	if err != nil {
		return false, err
	}

	// Only return a stored response; do not fetch from origin (RFC 7234 §5.2.1.7)
	req.Header.Set("Cache-Control", "only-if-cached")

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// 200 OK means object is cached, 504 means it's not (RFC 7234 only-if-cached)
	return resp.StatusCode == http.StatusOK, nil
}
