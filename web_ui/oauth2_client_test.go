/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package web_ui

import (
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

func base64encode(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func TestGenerateOAuthState(t *testing.T) {
	t.Run("generate-correct-state-string", func(t *testing.T) {
		get := GenerateOAuthState(map[string]string{"key1": "val1"})
		assert.Equal(t, base64encode("key1=val1"), get)
	})

	t.Run("generate-url-encoded-state-string", func(t *testing.T) {
		val1Raw := "https://example.com"
		val1Encoded := url.QueryEscape(val1Raw)
		get := GenerateOAuthState(map[string]string{"key1": val1Raw})
		assert.Equal(t, base64encode("key1="+val1Encoded), get)
	})
}

func TestParseOAuthState(t *testing.T) {
	t.Run("parse-non-url-string", func(t *testing.T) {
		get, err := ParseOAuthState(base64encode("key1=val1&key2=val2"))
		require.NoError(t, err)
		assert.EqualValues(t, map[string]string{"key1": "val1", "key2": "val2"}, get)
	})

	t.Run("parse-url-encoded-string", func(t *testing.T) {
		val2Raw := "https://example.com"
		val2Encoded := url.QueryEscape(val2Raw)
		get, err := ParseOAuthState(base64encode("key1=val1&key2=" + val2Encoded))
		require.NoError(t, err)
		assert.EqualValues(t, map[string]string{"key1": "val1", "key2": val2Raw}, get)
	})

	t.Run("duplicated-keys-returns-err", func(t *testing.T) {
		get, err := ParseOAuthState(base64encode("key1=val1&key1=val2"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicated keys")
		assert.Nil(t, get)
	})
}

func TestGenerateUserGroupInfo(t *testing.T) {
	// Note: These tests will fail at the database access point since we don't have a database initialized.
	// However, they validate that we properly parse the claims and don't error out with missing claim errors.
	// If we reach the database call, it means the claim parsing worked correctly.

	t.Run("handles-numeric-subject-claim-from-github", func(t *testing.T) {
		// GitHub returns numeric user IDs
		userInfo := map[string]interface{}{
			"login": "testuser",
			"id":    float64(67890),
		}
		idToken := make(map[string]interface{})

		require.NoError(t, param.Set(param.Issuer_OIDCAuthenticationUserClaim.GetName(), "login"))
		require.NoError(t, param.Set(param.Issuer_OIDCSubjectClaim.GetName(), "id"))
		require.NoError(t, param.Set(param.OIDC_Issuer.GetName(), "https://github.com"))
		defer param.Reset()

		// This should convert the numeric ID to a string and not error with parsing errors
		_, _, err := generateUserGroupInfo(userInfo, idToken)
		// We will get a database-related error (nil pointer), but not a parsing error
		if err != nil {
			assert.NotContains(t, err.Error(), "did not return a string for the subject claim", "Should handle numeric subject claims")
			assert.NotContains(t, err.Error(), "did not return a value for the subject claim", "Should find the 'id' claim")
		}
	})

	t.Run("handles-missing-issuer-claim-with-fallback", func(t *testing.T) {
		// GitHub doesn't return an "iss" claim
		userInfo := map[string]interface{}{
			"login": "testuser",
			"id":    float64(11111),
		}
		idToken := make(map[string]interface{})

		require.NoError(t, param.Set(param.Issuer_OIDCAuthenticationUserClaim.GetName(), "login"))
		require.NoError(t, param.Set(param.Issuer_OIDCSubjectClaim.GetName(), "id"))
		require.NoError(t, param.Set(param.OIDC_Issuer.GetName(), "https://github.com"))
		defer param.Reset()

		// This should fall back to using OIDC.Issuer
		_, _, err := generateUserGroupInfo(userInfo, idToken)
		// We will get a database-related error, but not a parsing error about missing issuer
		if err != nil {
			assert.NotContains(t, err.Error(), "did not return an issuer", "Should fall back to OIDC.Issuer when 'iss' claim is missing")
			assert.NotContains(t, err.Error(), "identity provider did not return an issuer claim value", "Should not require 'iss' claim when fallback is available")
		}
	})

	t.Run("handles-missing-sub-claim-fallback-to-username", func(t *testing.T) {
		// If no sub/id claim exists, fall back to username
		userInfo := map[string]interface{}{
			"login": "testuser",
		}
		idToken := make(map[string]interface{})

		require.NoError(t, param.Set(param.Issuer_OIDCAuthenticationUserClaim.GetName(), "login"))
		require.NoError(t, param.Set(param.OIDC_Issuer.GetName(), "https://example.com"))
		defer param.Reset()

		// This should use the username as the subject
		_, _, err := generateUserGroupInfo(userInfo, idToken)
		// We will get a database-related error, but not a parsing error about missing subject
		if err != nil {
			assert.NotContains(t, err.Error(), "did not return a subject for logged-in user", "Should fall back to username when subject claim is missing")
		}
	})
}
