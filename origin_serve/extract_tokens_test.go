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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

// TestExtractTokens pins the token sources the origin accepts and, in
// particular, that a token forwarded by an XRootD cache as
// "?authz=Bearer%20<jwt>" comes out without the HTTP scheme attached.
// Before the fix for issue #3755 the scheme was kept, the JWT failed to
// parse, and every cache-mediated read of a private namespace on a Go
// (non-XRootD) origin was rejected even though direct reads worked.
// String-level edge cases of the scheme removal itself are covered by
// TestCutBearerPrefix in the token package.
func TestExtractTokens(t *testing.T) {
	const jwt1 = "eyJ1.eyJ2.sig1"
	const jwt2 = "eyJ3.eyJ4.sig2"

	cases := []struct {
		name    string
		target  string
		headers map[string]string
		want    []string
	}{
		{
			name:    "authorization-header",
			target:  "/data/f",
			headers: map[string]string{"Authorization": "Bearer " + jwt1},
			want:    []string{jwt1},
		},
		{
			name:    "authorization-header-case-insensitive",
			target:  "/data/f",
			headers: map[string]string{"Authorization": "bearer " + jwt1},
			want:    []string{jwt1},
		},
		{
			name:    "authorization-header-multiple",
			target:  "/data/f",
			headers: map[string]string{"Authorization": "Bearer " + jwt1 + ", Bearer " + jwt2},
			want:    []string{jwt1, jwt2},
		},
		{
			name:    "authorization-header-non-bearer-ignored",
			target:  "/data/f",
			headers: map[string]string{"Authorization": "Basic dXNlcjpwYXNz"},
			want:    []string{},
		},
		{
			name:   "access-token-query",
			target: "/data/f?access_token=" + jwt1,
			want:   []string{jwt1},
		},
		{
			name:   "authz-query-bare",
			target: "/data/f?authz=" + jwt1,
			want:   []string{jwt1},
		},
		{
			// Exactly what an XRootD cache emits via "http.header2cgi
			// Authorization authz" and xrdcl-pelican forwards to the origin.
			name:   "authz-query-xrootd-bearer-prefix",
			target: "/data/f?authz=Bearer%20" + jwt1,
			want:   []string{jwt1},
		},
		{
			name:   "authz-query-plus-encoded-space",
			target: "/data/f?authz=Bearer+" + jwt1,
			want:   []string{jwt1},
		},
		{
			name:   "authz-query-lowercase-scheme",
			target: "/data/f?authz=bearer%20" + jwt1,
			want:   []string{jwt1},
		},
		{
			// A doubly-encoded value decodes to a literal "Bearer%20", the
			// spelling XrdSciTokens also tolerates.
			name:   "authz-query-double-encoded",
			target: "/data/f?authz=Bearer%2520" + jwt1,
			want:   []string{jwt1},
		},
		{
			name:   "access-token-query-bearer-prefix",
			target: "/data/f?access_token=Bearer%20" + jwt1,
			want:   []string{jwt1},
		},
		{
			name:   "authz-query-multi-valued",
			target: "/data/f?authz=Bearer%20" + jwt1 + "&authz=" + jwt2,
			want:   []string{jwt1, jwt2},
		},
		{
			name:   "empty-and-scheme-only-values-skipped",
			target: "/data/f?authz=&authz=Bearer%20&access_token=",
			want:   []string{},
		},
		{
			// Header first, then access_token, then authz.
			name:    "all-sources-ordered",
			target:  "/data/f?access_token=" + jwt2 + "&authz=Bearer%20" + jwt1,
			headers: map[string]string{"Authorization": "Bearer hdr.tok.en"},
			want:    []string{"hdr.tok.en", jwt2, jwt1},
		},
		{
			name:   "no-token",
			target: "/data/f?directread",
			want:   []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			assert.Equal(t, tc.want, extractTokens(req))
		})
	}
}

// startTestIssuer serves a JWKS and the OpenID discovery document that points
// at it, so the origin's key loader can verify tokens minted with key.
func startTestIssuer(t *testing.T, key jwk.Key) string {
	t.Helper()
	pubKey, err := key.PublicKey()
	require.NoError(t, err)
	require.NoError(t, pubKey.Set(jwk.KeyIDKey, "test-key"))
	require.NoError(t, pubKey.Set(jwk.AlgorithmKey, jwa.ES256))
	jwks := jwk.NewSet()
	require.NoError(t, jwks.AddKey(pubKey))

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		data, err := json.Marshal(jwks)
		require.NoError(t, err)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		data, err := json.Marshal(map[string]string{
			"issuer":   "http://" + r.Host,
			"jwks_uri": "http://" + r.Host + "/jwks",
		})
		require.NoError(t, err)
		_, _ = w.Write(data)
	})
	svr := httptest.NewServer(mux)
	t.Cleanup(svr.Close)
	return svr.URL
}

// TestAuthMiddlewareAcceptsCacheForwardedAuthz runs a real, signed token
// through authMiddleware the way an XRootD cache presents it -- as a
// "?authz=Bearer%20<jwt>" query parameter with no Authorization header -- and
// checks it is honored exactly like the same token in the header (issue #3755).
func TestAuthMiddlewareAcceptsCacheForwardedAuthz(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	key := generateTestKey(t)
	issuerURL := startTestIssuer(t, key)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	egrp := &errgroup.Group{}

	exports := []server_utils.OriginExport{
		{
			FederationPrefix: "/data",
			StoragePrefix:    t.TempDir(),
			IssuerUrls:       []string{issuerURL},
			Capabilities: server_structs.Capabilities{
				Reads: true, // private: no PublicReads
			},
		},
	}
	require.NoError(t, InitAuthConfig(ctx, egrp, exports))

	engine := gin.New()
	engine.GET("/data/*path", authMiddleware(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	tok := createTestToken(t, key, issuerURL, "alice", nil,
		"storage.read:/secret.txt", "https://wlcg.cern.ch/jwt/v1/any")

	do := func(target string, header string) int {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		return rec.Code
	}

	t.Run("control-header", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, do("/data/secret.txt", "Bearer "+tok))
	})
	t.Run("control-bare-authz-query", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, do("/data/secret.txt?authz="+tok, ""))
	})
	t.Run("xrootd-cache-forwarded-authz", func(t *testing.T) {
		// url.QueryEscape spells the separator as "+"; XRootD spells it "%20".
		// Go decodes both to a space, so exercise the XRootD spelling verbatim.
		assert.Equal(t, http.StatusOK, do("/data/secret.txt?authz=Bearer%20"+tok, ""),
			"a token forwarded by an XRootD cache as ?authz=Bearer%20<jwt> must authorize the read")
		assert.Equal(t, http.StatusOK, do("/data/secret.txt?authz="+url.QueryEscape("Bearer "+tok), ""))
	})
	t.Run("wrong-path-still-rejected", func(t *testing.T) {
		// Stripping the scheme must not widen what the token authorizes.
		assert.Equal(t, http.StatusUnauthorized, do("/data/other.txt?authz=Bearer%20"+tok, ""))
	})
	t.Run("no-token-rejected", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, do("/data/secret.txt", ""))
	})
}
