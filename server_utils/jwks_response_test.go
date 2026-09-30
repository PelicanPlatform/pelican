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

package server_utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// publicKeySet builds a single-key public JWKS for use in the writer tests.
func publicKeySet(t *testing.T, kid string) jwk.Set {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubJWK, err := jwk.PublicKeyOf(privKey)
	require.NoError(t, err)
	require.NoError(t, pubJWK.Set(jwk.KeyIDKey, kid))
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pubJWK))
	return set
}

// TestWriteJWKS verifies the inline-by-default / attachment-when-named
// contract of the shared JWKS response writer.
func TestWriteJWKS(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("no filename serves inline with no attachment header", func(t *testing.T) {
		rec := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(rec)

		WriteJWKS(ctx, publicKeySet(t, "inline-key"))

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Empty(t, rec.Header().Get("Content-Disposition"),
			"machine-facing responses must not set an attachment disposition")
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.Contains(t, rec.Body.String(), "inline-key")
	})

	t.Run("filename sets an attachment disposition", func(t *testing.T) {
		rec := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(rec)

		WriteJWKS(ctx, publicKeySet(t, "download-key"), "public-key-server-7.jwks")

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, `attachment; filename=public-key-server-7.jwks`,
			rec.Header().Get("Content-Disposition"))
		assert.Contains(t, rec.Body.String(), "download-key")
	})

	t.Run("a filename with unsafe characters cannot inject a header", func(t *testing.T) {
		rec := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(rec)

		WriteJWKS(ctx, publicKeySet(t, "safe-key"), "evil\r\nX-Injected: 1")

		require.Equal(t, http.StatusOK, rec.Code)
		disposition := rec.Header().Get("Content-Disposition")
		assert.NotContains(t, disposition, "\r")
		assert.NotContains(t, disposition, "\n")
		assert.Empty(t, rec.Header().Get("X-Injected"))
	})
}
