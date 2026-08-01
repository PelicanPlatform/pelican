//go:build !windows

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

// End-to-end tests for what a V2 cache does when asked for a collection.
//
// A namespace with Listings enabled will answer a plain GET on a collection
// with an HTML index. Nothing about that response says "this is not an
// object", so the risk is that the cache stores the index and thereafter
// serves it as though it were the object the user named -- which is how the
// confusing downloads reported in issue #1706 were produced.

package fed_tests

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// xrootdCollectionOriginConfig is an XRootD-backed export with Listings
// enabled. This is the configuration the confusing downloads were reported
// against, and it matters here because XRootD answers a plain GET on a
// collection with an HTML index rather than refusing -- a Go-native origin
// returns 405 and so never produces a listing for a cache to store.
const xrootdCollectionOriginConfig = `
Origin:
  StorageType: "posix"
  Exports:
    - StoragePrefix: /<SHOULD BE OVERRIDDEN>
      FederationPrefix: /test
      Capabilities: ["PublicReads", "Reads", "DirectReads", "Listings"]
`

// makeCollectionInOrigin creates a collection holding one object and returns
// the collection's federation-relative path.
func makeCollectionInOrigin(t *testing.T, ft *fed_test_utils.FedTest, name string) string {
	t.Helper()
	storageDir := ft.Exports[0].StoragePrefix
	collectionPath := filepath.Join(storageDir, name)
	require.NoError(t, os.MkdirAll(collectionPath, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(collectionPath, "member.txt"),
		[]byte("member object contents"), 0644))
	return "/test/" + name
}

// TestCacheCollectionNotStoredAsObject is the regression guarded against here:
// fetching a collection through a V2 cache must not leave the cache
// holding a directory index under the collection's name, because every later
// request for that path -- including ones for the object a user believes is
// there -- would then be served the index.
func TestCacheCollectionNotStoredAsObject(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Cache_EnableV2.Set(true))
	ft := fed_test_utils.NewFedTest(t, cacheControlOriginConfig(""))
	token := getTempTokenForTest(t)

	collection := makeCollectionInOrigin(t, ft, "a-collection")
	cacheURL := waitForCacheRedirectURL(t, ft, collection, token)

	// Ask the cache for the collection directly, the way a browser or a naive
	// client would.
	resp := fetchFromCache(t, ft, cacheURL, nil)
	t.Logf("cache answered a collection GET with status %d, %d bytes, content-type %q",
		resp.statusCode, len(resp.body), resp.headers.Get("Content-Type"))

	// The cache keys objects by path, so storing something under the
	// collection's name cannot corrupt the entry for an object inside it. This
	// is here to show the namespace is still usable after the collection was
	// requested, not to detect the storage itself -- the Age check below is
	// what does that.
	memberURL := waitForCacheRedirectURL(t, ft, collection+"/member.txt", token)
	member := fetchFromCache(t, ft, memberURL, nil)
	require.Equal(t, 200, member.statusCode,
		"an object inside the collection must still be retrievable")
	assert.Equal(t, "member object contents", string(member.body),
		"the object must be served as itself, not as a directory index")

	// A second fetch of the collection must not start succeeding from cache
	// with index content, which is what "the listing got stored" would look
	// like.
	second := fetchFromCache(t, ft, cacheURL, nil)
	if second.statusCode == 200 {
		assert.NotContains(t, strings.ToLower(string(second.body)), "<html",
			"a cached collection response must not be an HTML directory index")
	}
}

// TestClientRefusesCachedCollection covers the user-facing half through the
// same V2 cache: a non-recursive get of a collection is refused outright, and
// leaves nothing behind at the destination. The reported symptom was an empty
// file or an HTML listing saved under the name the user asked for.
func TestClientRefusesCachedCollection(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Cache_EnableV2.Set(true))
	ft := fed_test_utils.NewFedTest(t, cacheControlOriginConfig(""))
	token := getTempTokenForTest(t)

	collection := makeCollectionInOrigin(t, ft, "refused-collection")
	// Make sure the cache is advertising before the client asks.
	waitForCacheRedirectURL(t, ft, collection, token)

	downloadURL := fmt.Sprintf("pelican://%s:%d%s",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), collection)
	dest := filepath.Join(t.TempDir(), "downloaded")

	_, err := client.DoGet(ft.Ctx, downloadURL, dest, false,
		client.WithRejectCollections(true))
	require.Error(t, err, "a non-recursive get of a collection must be refused")
	assert.Contains(t, err.Error(), "is a collection")

	_, statErr := os.Stat(dest)
	assert.True(t, os.IsNotExist(statErr),
		"nothing may be written to the destination for a refused collection")

	// The object inside it still downloads, so the refusal is specific to
	// collections rather than to this namespace or this cache.
	objectURL := downloadURL + "/member.txt"
	objectDest := filepath.Join(t.TempDir(), "member.txt")
	_, objErr := client.DoGet(ft.Ctx, objectURL, objectDest, false,
		client.WithRejectCollections(true))
	require.NoError(t, objErr, "an object inside the collection must still download")
	contents, readErr := os.ReadFile(objectDest)
	require.NoError(t, readErr)
	assert.Equal(t, "member object contents", string(contents))
}

// TestCacheXrootdCollectionNotStoredAsObject is the same regression against an
// XRootD origin, which unlike a Go-native one will happily serve an HTML index
// for a collection. That index is what must never end up cached as the
// object's contents, and what a client must never write to a user's file.
func TestCacheXrootdCollectionNotStoredAsObject(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Cache_EnableV2.Set(true))
	ft := fed_test_utils.NewFedTest(t, xrootdCollectionOriginConfig)
	token := getTempTokenForTest(t)

	collection := makeCollectionInOrigin(t, ft, "xrootd-collection")
	cacheURL := waitForCacheRedirectURL(t, ft, collection, token)

	resp := fetchFromCache(t, ft, cacheURL, nil)
	t.Logf("xrootd-backed cache answered a collection GET with status %d, %d bytes, content-type %q",
		resp.statusCode, len(resp.body), resp.headers.Get("Content-Type"))

	// If the cache served an index, it must at least not have kept it: the
	// object inside the collection has to come back as itself.
	memberURL := waitForCacheRedirectURL(t, ft, collection+"/member.txt", token)
	member := fetchFromCache(t, ft, memberURL, nil)
	require.Equal(t, 200, member.statusCode)
	assert.Equal(t, "member object contents", string(member.body),
		"the object must be served as itself, not as a directory index")

	// And the client refuses the collection outright rather than writing
	// whatever the cache produced into the user's file.
	downloadURL := fmt.Sprintf("pelican://%s:%d%s",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), collection)
	dest := filepath.Join(t.TempDir(), "xrootd-downloaded")
	_, err := client.DoGet(ft.Ctx, downloadURL, dest, false,
		client.WithRejectCollections(true))
	require.Error(t, err, "a non-recursive get of an XRootD-served collection must be refused")
	assert.Contains(t, err.Error(), "is a collection")

	_, statErr := os.Stat(dest)
	assert.True(t, os.IsNotExist(statErr),
		"no file may be left behind -- an empty file or a saved HTML index is the reported symptom")
}

// TestCacheServesButDoesNotStoreXrootdCollectionListing covers the cache half
// of the fix. An export with Listings enabled answers a collection GET
// with an index, and users want to see it, so the cache still serves it -- but
// it must never be written to disk as that path's object. Once stored, every
// later request for the path is answered with the index instead, from any
// client.
//
// Measured by the same signal TestCacheControl_NoStore uses: a stored response
// ages, a passed-through one does not.
func TestCacheServesButDoesNotStoreXrootdCollectionListing(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Cache_EnableV2.Set(true))
	ft := fed_test_utils.NewFedTest(t, xrootdCollectionOriginConfig)
	token := getTempTokenForTest(t)

	collection := makeCollectionInOrigin(t, ft, "aged-collection")
	cacheURL := waitForCacheRedirectURL(t, ft, collection, token)

	resp := fetchFromCache(t, ft, cacheURL, nil)
	t.Logf("collection GET through the cache: status %d, %d bytes, content-type %q",
		resp.statusCode, len(resp.body), resp.headers.Get("Content-Type"))
	assert.Equal(t, 200, resp.statusCode,
		"the listing is still worth showing a user; only storing it is the problem")
	// The cache does not record what the origin called the response, so it must
	// not let net/http guess either: an index typed as HTML would run as a
	// document on the same web origin as the cache's UI. The header says the
	// same thing to the browser, for every object rather than only this path.
	assert.Equal(t, "application/octet-stream", resp.headers.Get("Content-Type"),
		"a passed-through listing must be typed opaquely, not sniffed as HTML")
	assert.Equal(t, "nosniff", resp.headers.Get("X-Content-Type-Options"),
		"the cache must tell the browser not to re-guess the type it was given")

	// A stored object is served with an Age header (see TestCacheControl_NoStore
	// for the same signal used the other way round). The absence of one on every
	// repeat is what says the listing was passed through rather than kept, and
	// it is true from the first fetch onward, so no waiting is involved.
	require.Empty(t, resp.headers.Get("Age"),
		"a collection index must not be stored and aged as this path's object")
	for i := 0; i < 3; i++ {
		again := fetchFromCache(t, ft, cacheURL, nil)
		t.Logf("collection GET repeat %d: status %d, Age=%q", i, again.statusCode, again.headers.Get("Age"))
		require.Equal(t, 200, again.statusCode, "repeat %d", i)
		require.Empty(t, again.headers.Get("Age"),
			"repeat %d: the cache started serving the listing from storage", i)
	}
}
