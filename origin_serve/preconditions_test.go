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
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/webdav"
)

func TestETagListMatches(t *testing.T) {
	assert.True(t, etagListMatches(`"abc"`, `"abc"`))
	assert.True(t, etagListMatches(`"abc", "def"`, `"def"`))
	assert.True(t, etagListMatches(`W/"abc"`, `"abc"`), "comparison is weak")
	assert.True(t, etagListMatches(`"abc"`, `W/"abc"`), "weak on either side")
	assert.False(t, etagListMatches(`"abc"`, `"xyz"`))
	assert.False(t, etagListMatches(`"abc"`, ""), "an absent tag never matches")
	assert.False(t, etagListMatches("", `"abc"`))
}

// putPreconditionCase drives checkPutPreconditions against a real pstore
// backend, which is the one that reports a generation-based ETag.
func runPreconditionCase(t *testing.T, headers map[string]string, path string) (int, bool) {
	t.Helper()
	backend := newPStoreTestBackend(t, "/")

	// Seed an object so there is something to match against.
	fs := backend.FileSystem()
	f, err := fs.OpenFile(t.Context(), "/exists.txt", os.O_WRONLY|os.O_CREATE, 0644)
	require.NoError(t, err)
	_, err = f.Write([]byte("seed"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPut, "http://origin"+path, nil)
	for k, v := range headers {
		c.Request.Header.Set(k, v)
	}

	_, proceed := checkPutPreconditions(c, backend, path)
	return rec.Code, proceed
}

// currentETagOf returns the ETag a client would have been given for path.
func currentETagOf(t *testing.T, backend *pstoreBackend, path string) string {
	t.Helper()
	info, err := backend.FileSystem().Stat(t.Context(), path)
	require.NoError(t, err)
	tag, err := info.(webdav.ETager).ETag(context.Background())
	require.NoError(t, err)
	return tag
}

func TestPutPreconditionsNoHeaders(t *testing.T) {
	_, proceed := runPreconditionCase(t, nil, "/exists.txt")
	assert.True(t, proceed, "an unconditional PUT is unaffected")
}

// TestPutPreconditionIfNoneMatchStar is the create-only case: a client using
// it must not silently overwrite.
func TestPutPreconditionIfNoneMatchStar(t *testing.T) {
	code, proceed := runPreconditionCase(t,
		map[string]string{"If-None-Match": "*"}, "/exists.txt")
	assert.False(t, proceed)
	assert.Equal(t, http.StatusPreconditionFailed, code)

	_, proceedNew := runPreconditionCase(t,
		map[string]string{"If-None-Match": "*"}, "/brand-new.txt")
	assert.True(t, proceedNew, "create-only succeeds when nothing is there")
}

// TestPutPreconditionIfMatch covers compare-and-swap in both directions.
func TestPutPreconditionIfMatch(t *testing.T) {
	backend := newPStoreTestBackend(t, "/")
	fs := backend.FileSystem()
	f, err := fs.OpenFile(t.Context(), "/obj.txt", os.O_WRONLY|os.O_CREATE, 0644)
	require.NoError(t, err)
	_, err = f.Write([]byte("v1"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	current := currentETagOf(t, backend, "/obj.txt")

	newReq := func(hdr, val string) (*gin.Context, *httptest.ResponseRecorder) {
		gin.SetMode(gin.TestMode)
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPut, "http://origin/obj.txt", nil)
		c.Request.Header.Set(hdr, val)
		return c, rec
	}

	t.Run("matching tag proceeds", func(t *testing.T) {
		c, _ := newReq("If-Match", current)
		cond, ok := checkPutPreconditions(c, backend, "/obj.txt")
		assert.True(t, ok)
		assert.Equal(t, current, cond.requireETag,
			"a single-tag If-Match is carried down for the backend to re-check at commit")
	})

	t.Run("stale tag is refused", func(t *testing.T) {
		c, rec := newReq("If-Match", `"0000000000000000"`)
		_, ok := checkPutPreconditions(c, backend, "/obj.txt")
		assert.False(t, ok)
		assert.Equal(t, http.StatusPreconditionFailed, rec.Code)
	})

	t.Run("star requires existence", func(t *testing.T) {
		c, _ := newReq("If-Match", "*")
		cond, ok := checkPutPreconditions(c, backend, "/obj.txt")
		assert.True(t, ok)
		assert.False(t, cond.isSet(), "\"*\" asserts existence, which no backend can re-check at commit")

		c2, rec2 := newReq("If-Match", "*")
		_, ok = checkPutPreconditions(c2, backend, "/absent.txt")
		assert.False(t, ok)
		assert.Equal(t, http.StatusPreconditionFailed, rec2.Code)
	})

	t.Run("tag stops matching after an overwrite", func(t *testing.T) {
		f2, wErr := fs.OpenFile(t.Context(), "/obj.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		require.NoError(t, wErr)
		_, wErr = f2.Write([]byte("v2"))
		require.NoError(t, wErr)
		require.NoError(t, f2.Close())

		c, rec := newReq("If-Match", current)
		_, ok := checkPutPreconditions(c, backend, "/obj.txt")
		assert.False(t, ok, "the old generation must no longer satisfy If-Match")
		assert.Equal(t, http.StatusPreconditionFailed, rec.Code)
	})
}

// TestPutPreconditionIfNoneMatchTag covers the entity-tag form, as opposed to
// the "*" form.
func TestPutPreconditionIfNoneMatchTag(t *testing.T) {
	backend := newPStoreTestBackend(t, "/")
	fs := backend.FileSystem()
	f, err := fs.OpenFile(t.Context(), "/obj.txt", os.O_WRONLY|os.O_CREATE, 0644)
	require.NoError(t, err)
	_, err = f.Write([]byte("v1"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	current := currentETagOf(t, backend, "/obj.txt")

	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPut, "http://origin/obj.txt", nil)
	c.Request.Header.Set("If-None-Match", current)
	_, ok := checkPutPreconditions(c, backend, "/obj.txt")
	assert.False(t, ok)
	assert.Equal(t, http.StatusPreconditionFailed, rec.Code)

	rec2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(rec2)
	c2.Request = httptest.NewRequest(http.MethodPut, "http://origin/obj.txt", nil)
	c2.Request.Header.Set("If-None-Match", `"some-other-tag"`)
	_, ok = checkPutPreconditions(c2, backend, "/obj.txt")
	assert.True(t, ok, "a non-matching tag does not block the write")
}
