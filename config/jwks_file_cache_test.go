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

package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	log "github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config/configtest"
)

// fakeClock drives jwksFileCacheNow so TTL behavior can be tested by advancing
// time explicitly rather than sleeping.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// useFakeClock installs a fake clock for the JWKS file cache and clears the
// cache, restoring both when the test finishes.
func useFakeClock(t *testing.T) *fakeClock {
	t.Helper()
	// A fixed, arbitrary start time; the cache only ever looks at differences.
	clock := &fakeClock{now: time.Unix(1700000000, 0)}
	prev := jwksFileCacheNow
	jwksFileCacheNow = clock.Now
	ResetJWKSFileCache()
	t.Cleanup(func() {
		jwksFileCacheNow = prev
		ResetJWKSFileCache()
	})
	return clock
}

// newPublicJWK returns a fresh public EC key with the given kid.
func newPublicJWK(t *testing.T, kid string) jwk.Key {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub, err := jwk.FromRaw(priv.PublicKey)
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, kid))
	return pub
}

// captureLogs installs a logrus test hook and returns a function that reports
// whether any captured message contains substr.
func captureLogs(t *testing.T) func(substr string) bool {
	t.Helper()
	hook := logrustest.NewLocal(log.StandardLogger())
	prevLevel := log.GetLevel()
	log.SetLevel(log.DebugLevel)
	t.Cleanup(func() {
		log.SetLevel(prevLevel)
		hook.Reset()
	})
	return func(substr string) bool {
		for _, entry := range hook.AllEntries() {
			if strings.Contains(entry.Message, substr) {
				return true
			}
		}
		return false
	}
}

// TestJWKSFileCacheThrottlesReads verifies that the file is read at most once
// per TTL: an edit written inside the window is not observed, and the same
// edit is observed once the window has passed.
func TestJWKSFileCacheThrottlesReads(t *testing.T) {
	clock := useFakeClock(t)
	dir := t.TempDir()

	path := configtest.WriteJWKSFile(t, dir, "keys.jwks", newPublicJWK(t, "first"))

	got, err := ReadPublicJWKSFile(path)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"first"}, collectKIDs(t, got))

	// Rewrite the file with different contents, still inside the TTL window.
	configtest.WriteJWKSFile(t, dir, "keys.jwks", newPublicJWK(t, "second"))

	got, err = ReadPublicJWKSFile(path)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"first"}, collectKIDs(t, got),
		"a read inside the TTL window must not hit the filesystem")

	// Just short of the TTL: still cached.
	clock.advance(jwksFileCacheTTL - time.Nanosecond)
	got, err = ReadPublicJWKSFile(path)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"first"}, collectKIDs(t, got))

	// Past the TTL: the new contents are picked up.
	clock.advance(time.Nanosecond)
	got, err = ReadPublicJWKSFile(path)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"second"}, collectKIDs(t, got),
		"a read after the TTL window must observe the new contents")
}

// TestJWKSFileCacheThrottlesFailedReads verifies that a persistently broken
// file is not re-read on every call either. Without caching the failure, an
// unauthenticated request would drive a filesystem read every time.
func TestJWKSFileCacheThrottlesFailedReads(t *testing.T) {
	clock := useFakeClock(t)
	path := filepath.Join(t.TempDir(), "missing.jwks")

	_, err := ReadPublicJWKSFile(path)
	require.Error(t, err)

	// Create a valid file inside the TTL window; the cached failure stands.
	dir := filepath.Dir(path)
	configtest.WriteJWKSFile(t, dir, "missing.jwks", newPublicJWK(t, "appeared"))
	_, err = ReadPublicJWKSFile(path)
	require.Error(t, err, "a cached failure must not be retried inside the TTL window")

	clock.advance(jwksFileCacheTTL)
	got, err := ReadPublicJWKSFile(path)
	require.NoError(t, err, "the retry after the TTL window should succeed")
	assert.ElementsMatch(t, []string{"appeared"}, collectKIDs(t, got))
}

// TestJWKSFileCacheFallsBackOnTornRead verifies that a non-empty file which no
// longer parses keeps serving the last version that loaded successfully. A
// JWKS file rewritten in place can be read mid-write, and dropping a
// namespace's keys for that instant would break token verification.
func TestJWKSFileCacheFallsBackOnTornRead(t *testing.T) {
	clock := useFakeClock(t)
	logged := captureLogs(t)
	dir := t.TempDir()

	path := configtest.WriteJWKSFile(t, dir, "keys.jwks", newPublicJWK(t, "good"))
	got, err := ReadPublicJWKSFile(path)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"good"}, collectKIDs(t, got))

	// Simulate a torn read: a non-empty file holding a truncated document.
	require.NoError(t, os.WriteFile(path, []byte(`{"keys":[{"kty":"E`), 0600))

	clock.advance(jwksFileCacheTTL)
	got, err = ReadPublicJWKSFile(path)
	require.NoError(t, err, "a torn read must not surface as an error")
	assert.ElementsMatch(t, []string{"good"}, collectKIDs(t, got),
		"the last good version should still be served")
	assert.True(t, logged("could not be loaded"),
		"falling back to a stale version should be logged")

	// Once the rewrite completes, the new contents take over.
	configtest.WriteJWKSFile(t, dir, "keys.jwks", newPublicJWK(t, "rewritten"))
	clock.advance(jwksFileCacheTTL)
	got, err = ReadPublicJWKSFile(path)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"rewritten"}, collectKIDs(t, got))
}

// TestJWKSFileCacheNoFallbackForMissingOrEmpty verifies that the stale
// fallback is scoped to non-empty files. A deleted or truncated-to-nothing
// file is an unambiguous "these keys are gone" signal, so it must surface as
// an error (the caller degrades to the base key set) rather than resurrecting
// keys the operator removed.
func TestJWKSFileCacheNoFallbackForMissingOrEmpty(t *testing.T) {
	t.Run("emptied file", func(t *testing.T) {
		clock := useFakeClock(t)
		dir := t.TempDir()

		path := configtest.WriteJWKSFile(t, dir, "keys.jwks", newPublicJWK(t, "good"))
		_, err := ReadPublicJWKSFile(path)
		require.NoError(t, err)

		require.NoError(t, os.WriteFile(path, nil, 0600))
		clock.advance(jwksFileCacheTTL)
		_, err = ReadPublicJWKSFile(path)
		require.Error(t, err, "an emptied file must not fall back to the previous contents")
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("deleted file", func(t *testing.T) {
		clock := useFakeClock(t)
		dir := t.TempDir()

		path := configtest.WriteJWKSFile(t, dir, "keys.jwks", newPublicJWK(t, "good"))
		_, err := ReadPublicJWKSFile(path)
		require.NoError(t, err)

		require.NoError(t, os.Remove(path))
		clock.advance(jwksFileCacheTTL)
		_, err = ReadPublicJWKSFile(path)
		require.Error(t, err, "a deleted file must not fall back to the previous contents")

		// A later torn read must not resurrect the pre-deletion keys: the
		// remembered good version is dropped on a hard failure.
		require.NoError(t, os.WriteFile(path, []byte(`{"keys":[{"kty":"E`), 0600))
		clock.advance(jwksFileCacheTTL)
		_, err = ReadPublicJWKSFile(path)
		require.Error(t, err,
			"the good version from before the deletion must not come back")
	})
}

// TestJWKSFileCacheBoundsReadSize verifies that an oversized file is rejected
// without being read into memory.
func TestJWKSFileCacheBoundsReadSize(t *testing.T) {
	useFakeClock(t)
	path := filepath.Join(t.TempDir(), "huge.jwks")

	// A syntactically valid JWKS padded past the limit with whitespace, so the
	// rejection can only be the size bound and not a parse failure.
	body := []byte(`{"keys":[]}`)
	padding := make([]byte, MaxJWKSFileSize+1-len(body))
	for i := range padding {
		padding[i] = ' '
	}
	require.NoError(t, os.WriteFile(path, append(body, padding...), 0600))

	_, err := ReadPublicJWKSFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
}

// TestJWKSFileCacheWarnsOnWorldWritable verifies the permission check. Every
// key in the file is published as a trusted signing key, so write access to it
// is the authority to mint tokens the server accepts; that is worth a warning,
// but not worth refusing to serve the namespace's keys over.
func TestJWKSFileCacheWarnsOnWorldWritable(t *testing.T) {
	t.Run("world-writable warns but still serves", func(t *testing.T) {
		useFakeClock(t)
		logged := captureLogs(t)
		dir := t.TempDir()

		path := configtest.WriteJWKSFile(t, dir, "loose.jwks", newPublicJWK(t, "loose-key"))
		require.NoError(t, os.Chmod(path, 0666))

		got, err := ReadPublicJWKSFile(path)
		require.NoError(t, err, "a permission warning must not block the keys")
		assert.ElementsMatch(t, []string{"loose-key"}, collectKIDs(t, got))
		assert.True(t, logged("world-writable"),
			"a world-writable JWKS file should be warned about")
	})

	t.Run("tightly permissioned file does not warn", func(t *testing.T) {
		useFakeClock(t)
		logged := captureLogs(t)
		dir := t.TempDir()

		path := configtest.WriteJWKSFile(t, dir, "tight.jwks", newPublicJWK(t, "tight-key"))
		require.NoError(t, os.Chmod(path, 0640))

		_, err := ReadPublicJWKSFile(path)
		require.NoError(t, err)
		assert.False(t, logged("world-writable"),
			"a file that is not world-writable should not warn")
	})
}

// TestJWKSFileWarningsDoNotRepeat verifies that a standing misconfiguration is
// logged once rather than on every cache refresh. The JWKS endpoints are
// unauthenticated and polled continuously, so a per-refresh warning would bury
// the log.
func TestJWKSFileWarningsDoNotRepeat(t *testing.T) {
	clock := useFakeClock(t)
	hook := logrustest.NewLocal(log.StandardLogger())
	t.Cleanup(hook.Reset)

	dir := t.TempDir()
	path := configtest.WriteJWKSFile(t, dir, "loose.jwks", newPublicJWK(t, "loose-key"))
	require.NoError(t, os.Chmod(path, 0666))

	countWorldWritable := func() int {
		n := 0
		for _, entry := range hook.AllEntries() {
			if strings.Contains(entry.Message, "world-writable") {
				n++
			}
		}
		return n
	}

	for i := 0; i < 5; i++ {
		_, err := ReadPublicJWKSFile(path)
		require.NoError(t, err)
		clock.advance(jwksFileCacheTTL)
	}
	assert.Equal(t, 1, countWorldWritable(),
		"a standing permission problem should be logged once, not once per refresh")
}
