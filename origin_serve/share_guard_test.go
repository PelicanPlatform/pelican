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

// Defense-in-depth for the share design: when Origin.Multiuser is on,
// any inbound `share.access:/$ID` token must be refused. The primary
// enforcement is the create-time gate (origin/collections.go's
// handleCreateCollectionShare); this test pins the runtime guard
// that catches stale tokens minted before multi-user was enabled.

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// mintTokenWithScope produces a minimally valid JWT that carries the
// supplied `scope` claim. We don't verify the signature in
// MapTokenToUser; this just needs to parse cleanly.
func mintTokenWithScope(t *testing.T, scope string) string {
	t.Helper()
	key, err := jwk.FromRaw([]byte("test-key-please-ignore"))
	require.NoError(t, err)
	tok, err := jwt.NewBuilder().
		Subject("alice").
		Claim("scope", scope).
		Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, key))
	require.NoError(t, err)
	return string(signed)
}

func TestTokenCarriesShareAccess(t *testing.T) {
	t.Run("share.access:/id is detected", func(t *testing.T) {
		tok := mintTokenWithScope(t, "storage.read:/foo share.access:/abc1234 storage.modify:/foo")
		assert.True(t, tokenCarriesShareAccess(tok))
	})
	t.Run("token without share.access returns false", func(t *testing.T) {
		tok := mintTokenWithScope(t, "storage.read:/foo storage.modify:/foo")
		assert.False(t, tokenCarriesShareAccess(tok))
	})
	t.Run("look-alike scope name does NOT match", func(t *testing.T) {
		// `share.access` requires the colon separator — a scope named
		// "share.accessor" must not be mistaken for one. Guard against
		// the classic strings.HasPrefix bug.
		tok := mintTokenWithScope(t, "share.accessor:/abc")
		assert.False(t, tokenCarriesShareAccess(tok))
	})
	t.Run("malformed token returns false (let upstream verifier reject)", func(t *testing.T) {
		assert.False(t, tokenCarriesShareAccess("not-a-jwt"))
		assert.False(t, tokenCarriesShareAccess(""))
	})
}

func TestShareTokenForbiddenInMultiuser(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	t.Run("not multiuser: never forbidden", func(t *testing.T) {
		require.NoError(t, param.Origin_Multiuser.Set(false))
		assert.False(t, shareTokenForbiddenInMultiuser(
			mintTokenWithScope(t, "share.access:/abc")),
			"share tokens are fine when multi-user is OFF — single-identity backends serve them directly")
	})
	t.Run("multiuser without share scope: not forbidden", func(t *testing.T) {
		require.NoError(t, param.Origin_Multiuser.Set(true))
		assert.False(t, shareTokenForbiddenInMultiuser(
			mintTokenWithScope(t, "storage.read:/foo")),
			"a regular non-share token is fine in multi-user mode")
	})
	t.Run("multiuser with share scope: forbidden (defense-in-depth)", func(t *testing.T) {
		require.NoError(t, param.Origin_Multiuser.Set(true))
		assert.True(t, shareTokenForbiddenInMultiuser(
			mintTokenWithScope(t, "share.access:/abc storage.read:/foo")),
			"share tokens MUST be refused on multi-user backends per docs/collections-design.md")
	})
}
