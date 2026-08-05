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

// Authorization for the administrative storage-introspection routes, wired
// exactly as the launcher wires it.
//
// The other storage_api tests stub the middleware out so they can exercise the
// handlers. These do the opposite: they run the real web_ui pair and never
// reach a handler, because the bug being pinned was in the registration
// itself. RegisterStorageAPI was mounted with AdminAuthHandler alone, which
// reads the "User" that an authentication handler is supposed to have put in
// the context and 401s when it is empty -- so every caller, administrator or
// not, was rejected and the authorization it implements had never once run.

package origin_serve

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/web_ui"
)

// newAuthenticatedStorageAPI mounts the storage routes behind the same
// middleware pair the launcher uses.
func newAuthenticatedStorageAPI(t *testing.T) *gin.Engine {
	t.Helper()

	require.NoError(t, param.Origin_StorageType.Set(string(server_structs.OriginStoragePStore)))
	t.Cleanup(func() { _ = param.Origin_StorageType.Set("posix") })

	// web_ui.AuthHandler refuses bearer tokens outright unless the server
	// knows its own URL, since that is what it pins the issuer to.
	require.NoError(t, param.Server_ExternalWebUrl.Set("https://origin.example.com"))
	t.Cleanup(func() { _ = param.Server_ExternalWebUrl.Set("") })

	// Brings up the store (and, via InitIssuerKeyForTests, the local issuer
	// key that signs and verifies the tokens below).
	_ = newPStoreTestBackend(t, "/")

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	RegisterStorageAPI(engine.Group("/api/v1.0"), web_ui.AuthHandler, web_ui.AdminAuthHandler)
	return engine
}

// localBearerToken mints a token this server would accept as its own: signed
// by the local issuer key, with the issuer pinned to GetLocalIssuerUrl().
func localBearerToken(t *testing.T, subject string) string {
	t.Helper()

	key, err := config.GetIssuerPrivateJWK()
	require.NoError(t, err)

	tok, err := jwt.NewBuilder().
		Issuer(config.GetLocalIssuerUrl()).
		Subject(subject).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Build()
	require.NoError(t, err)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, key))
	require.NoError(t, err)
	return string(signed)
}

// TestStorageAPIRejectsUnauthenticated covers the fail-closed half.
func TestStorageAPIRejectsUnauthenticated(t *testing.T) {
	engine := newAuthenticatedStorageAPI(t)

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/api/v1.0/origin/storage/pstore/usage", nil))

	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"an anonymous caller must be told to authenticate: %s", rec.Body.String())
}

// TestStorageAPIRejectsNonAdmin is the case that could never happen before:
// with only AdminAuthHandler mounted, a perfectly valid non-admin token still
// produced a 401, so the administrator check itself was dead code.
func TestStorageAPIRejectsNonAdmin(t *testing.T) {
	engine := newAuthenticatedStorageAPI(t)

	for _, route := range []string{"usage", "ls/", "stat/x", "digest/x"} {
		t.Run(route, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet,
				"/api/v1.0/origin/storage/pstore/"+route, nil)
			req.Header.Set("Authorization", "Bearer "+localBearerToken(t, "not-an-admin"))

			rec := httptest.NewRecorder()
			engine.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusForbidden, rec.Code,
				"an authenticated non-administrator must get 403, not 401: %s", rec.Body.String())
		})
	}
}

// TestStorageAPIAdmitsAdmin closes the loop: with the pair mounted, an
// administrator actually reaches the handler.  Without it, this route was
// unreachable by anyone and `pelican-server origin introspect` could never succeed.
func TestStorageAPIAdmitsAdmin(t *testing.T) {
	engine := newAuthenticatedStorageAPI(t)

	require.NoError(t, param.Server_UIAdminUsers.Set([]string{"the-admin"}))
	t.Cleanup(func() { _ = param.Server_UIAdminUsers.Set(nil) })

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1.0/origin/storage/pstore/usage", nil)
	req.Header.Set("Authorization", "Bearer "+localBearerToken(t, "the-admin"))

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code,
		"an administrator must reach the handler: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), "usedBytes")
}
