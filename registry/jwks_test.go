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

package registry

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
)

// keyIDs returns the set of key IDs present in set.
func keyIDs(t *testing.T, set jwk.Set) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	_ = config.ForEachKey(set, func(k jwk.Key) error {
		out[k.KeyID()] = true
		return nil
	})
	return out
}

// newTestPrivateJWK returns a fresh EC private key as a jwk.Key with the
// given kid.
func newTestPrivateJWK(t *testing.T, kid string) jwk.Key {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	privJWK, err := jwk.FromRaw(privKey)
	require.NoError(t, err)
	require.NoError(t, privJWK.Set(jwk.KeyIDKey, kid))
	return privJWK
}

// newTestSymmetricJWK returns a symmetric (kty=oct) key with the given kid.
// Such a key has no public projection and must never be published.
func newTestSymmetricJWK(t *testing.T, kid string) jwk.Key {
	t.Helper()
	symKey, err := jwk.FromRaw(make([]byte, 32))
	require.NoError(t, err)
	require.NoError(t, symKey.Set(jwk.KeyIDKey, kid))
	return symKey
}

// TestPublicJWKSForServing verifies that the registry's serving sanitizer
// strips private material from a publishable key and silently skips a key it
// cannot publish, so one bad registrant-submitted key cannot fail the whole
// endpoint. It also verifies the hard-error boundary: a non-empty stored set
// that projects to nothing is an error, while a genuinely empty set is not.
// Private-key stripping through the HTTP handlers is covered by
// jwks-strips-private-key (registry_test.go) and TestGetNamespaceJWKSStripsPrivateKey
// (registry_ui_test.go); this focuses on the projection policy.
func TestPublicJWKSForServing(t *testing.T) {
	t.Run("skips-unpublishable-key-among-good", func(t *testing.T) {
		set := jwk.NewSet()
		require.NoError(t, set.AddKey(newTestPrivateJWK(t, "good-key")))
		require.NoError(t, set.AddKey(newTestSymmetricJWK(t, "sym-key")))

		out, err := publicJWKSForServing(set)
		require.NoError(t, err)

		present := keyIDs(t, out)
		assert.True(t, present["good-key"],
			"a publishable key must survive sanitization")
		assert.False(t, present["sym-key"],
			"a symmetric key must be skipped, not published")

		// The surviving key must carry no private material.
		good, ok := out.LookupKeyID("good-key")
		require.True(t, ok)
		_, hasPrivate := good.Get("d")
		assert.False(t, hasPrivate,
			"private key parameter must not be present on the published key")
	})

	t.Run("errors-when-all-keys-unpublishable", func(t *testing.T) {
		set := jwk.NewSet()
		require.NoError(t, set.AddKey(newTestSymmetricJWK(t, "sym-key")))

		out, err := publicJWKSForServing(set)
		require.Error(t, err,
			"a non-empty set that projects to empty must be an error")
		assert.Nil(t, out)
	})

	t.Run("empty-input-is-not-an-error", func(t *testing.T) {
		out, err := publicJWKSForServing(jwk.NewSet())
		require.NoError(t, err,
			"an empty input set must not be treated as a fault")
		assert.Equal(t, 0, out.Len())
	})
}
