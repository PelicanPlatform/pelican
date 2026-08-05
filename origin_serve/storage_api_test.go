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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// newStorageAPI stands up the administrative routes over a live store, with
// authentication stubbed so the tests exercise the handlers rather than the
// auth stack.
func newStorageAPI(t *testing.T) (*gin.Engine, *pstoreBackend) {
	t.Helper()
	require.NoError(t, param.Origin_StorageType.Set(string(server_structs.OriginStoragePStore)))
	t.Cleanup(func() { _ = param.Origin_StorageType.Set("posix") })

	backend := newPStoreTestBackend(t, "/")

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	RegisterStorageAPI(engine.Group("/api/v1.0"), func(c *gin.Context) { c.Next() })
	return engine, backend
}

func seedObject(t *testing.T, b *pstoreBackend, name, body string) {
	t.Helper()
	f, err := b.FileSystem().OpenFile(t.Context(), name, os.O_WRONLY|os.O_CREATE, 0644)
	require.NoError(t, err)
	_, err = f.Write([]byte(body))
	require.NoError(t, err)
	require.NoError(t, f.Close())
}

func getJSON(t *testing.T, engine *gin.Engine, path string, out any) int {
	t.Helper()
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if out != nil && rec.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), out))
	}
	// Surface the body on an unexpected status; a bare status code says
	// nothing about which of several conditions produced it.
	t.Logf("GET %s -> %d: %s", path, rec.Code, strings.TrimSpace(rec.Body.String()))
	return rec.Code
}

// TestStorageAPIListsALiveStore is the point of the whole interface: the
// offline CLI cannot open a store the origin holds locked, so the running
// process has to answer.
func TestStorageAPIListsALiveStore(t *testing.T) {
	engine, backend := newStorageAPI(t)

	require.NoError(t, backend.FileSystem().Mkdir(t.Context(), "/data", 0755))
	seedObject(t, backend, "/data/a.txt", "alpha")
	seedObject(t, backend, "/data/b.txt", "beta")

	var result storageListResponse
	require.Equal(t, http.StatusOK, getJSON(t, engine, "/api/v1.0/origin/storage/pstore/ls/data", &result))

	assert.Equal(t, storageBackendPStore, result.Backend)
	require.Len(t, result.Entries, 2)
	assert.Equal(t, "a.txt", result.Entries[0].Name)
	assert.Equal(t, "/data/a.txt", result.Entries[0].Path)
	assert.Equal(t, int64(5), result.Entries[0].Size)
	assert.NotEmpty(t, result.Entries[0].ETag)
	assert.False(t, result.More)
}

func TestStorageAPIPaginates(t *testing.T) {
	engine, backend := newStorageAPI(t)

	require.NoError(t, backend.FileSystem().Mkdir(t.Context(), "/d", 0755))
	for _, n := range []string{"a", "b", "c"} {
		seedObject(t, backend, "/d/"+n, n)
	}

	var page storageListResponse
	require.Equal(t, http.StatusOK,
		getJSON(t, engine, "/api/v1.0/origin/storage/pstore/ls/d?limit=2", &page))
	require.Len(t, page.Entries, 2)
	assert.True(t, page.More, "a truncated page says so")

	var rest storageListResponse
	require.Equal(t, http.StatusOK,
		getJSON(t, engine, "/api/v1.0/origin/storage/pstore/ls/d?limit=2&after=b", &rest))
	require.Len(t, rest.Entries, 1)
	assert.Equal(t, "c", rest.Entries[0].Name)
	assert.False(t, rest.More)
}

func TestStorageAPIStatAndDigest(t *testing.T) {
	engine, backend := newStorageAPI(t)
	seedObject(t, backend, "/obj.txt", "contents")

	var entry storageEntryResponse
	require.Equal(t, http.StatusOK,
		getJSON(t, engine, "/api/v1.0/origin/storage/pstore/stat/obj.txt", &entry))
	assert.Equal(t, "obj.txt", entry.Name)
	assert.Equal(t, int64(8), entry.Size)
	assert.False(t, entry.IsDir)

	var digest storageDigestResponse
	require.Equal(t, http.StatusOK,
		getJSON(t, engine, "/api/v1.0/origin/storage/pstore/digest/obj.txt", &digest))
	assert.Contains(t, digest.Digest, "md5=", "digests are reported in RFC 3230 form")
}

func TestStorageAPIUsage(t *testing.T) {
	engine, backend := newStorageAPI(t)
	seedObject(t, backend, "/obj.txt", "contents")

	var usage storageUsageResponse
	require.Equal(t, http.StatusOK,
		getJSON(t, engine, "/api/v1.0/origin/storage/pstore/usage", &usage))
	assert.Equal(t, storageBackendPStore, usage.Backend)
	assert.Greater(t, usage.UsedBytes, int64(0))
}

// TestStorageAPIErrorsAreActionable checks that a caller can tell the
// difference between a missing object and a misuse.
func TestStorageAPIErrorsAreActionable(t *testing.T) {
	engine, backend := newStorageAPI(t)
	seedObject(t, backend, "/file.txt", "x")

	assert.Equal(t, http.StatusNotFound,
		getJSON(t, engine, "/api/v1.0/origin/storage/pstore/stat/missing", nil))
	assert.Equal(t, http.StatusBadRequest,
		getJSON(t, engine, "/api/v1.0/origin/storage/pstore/ls/file.txt", nil),
		"listing a file is a client error, not a server one")
	assert.Equal(t, http.StatusBadRequest,
		getJSON(t, engine, "/api/v1.0/origin/storage/pstore/ls/?limit=-1", nil))
}

// TestStorageAPIAbsentOnOtherBackends is why the CLI can say "this origin has
// no such interface" rather than failing obscurely: the routes are never
// registered unless the backend actually has one.
func TestStorageAPIAbsentOnOtherBackends(t *testing.T) {
	require.NoError(t, param.Origin_StorageType.Set("posix"))
	t.Cleanup(func() { _ = param.Origin_StorageType.Set("posix") })
	ResetPStoreState()

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	RegisterStorageAPI(engine.Group("/api/v1.0"), func(c *gin.Context) { c.Next() })

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/api/v1.0/origin/storage/pstore/usage", nil))
	assert.Equal(t, http.StatusNotFound, rec.Code,
		"a non-pstore origin registers no storage routes at all")
}

// TestStorageAPIRequiresAdmin confirms the middleware is actually applied;
// these routes expose the whole namespace.
func TestStorageAPIRequiresAdmin(t *testing.T) {
	require.NoError(t, param.Origin_StorageType.Set(string(server_structs.OriginStoragePStore)))
	t.Cleanup(func() { _ = param.Origin_StorageType.Set("posix") })
	_ = newPStoreTestBackend(t, "/")

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	denied := false
	RegisterStorageAPI(engine.Group("/api/v1.0"), func(c *gin.Context) {
		denied = true
		c.AbortWithStatus(http.StatusForbidden)
	})

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/api/v1.0/origin/storage/pstore/usage", nil))
	assert.True(t, denied, "the auth handler must run before the route")
	assert.Equal(t, http.StatusForbidden, rec.Code)
}
