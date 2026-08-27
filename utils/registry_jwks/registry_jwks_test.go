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

package registry_jwks

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetJWKSURLFromIssuerURL(t *testing.T) {
	t.Run("succeeds with minimal openid-configuration", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/.well-known/openid-configuration", r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"jwks_uri": "https://example.com/jwks"}`)
		}))
		defer srv.Close()

		got, err := GetJWKSURLFromIssuerURL(srv.URL)
		require.NoError(t, err)
		assert.Equal(t, "https://example.com/jwks", got)
	})

	// Regression test for https://github.com/PelicanPlatform/pelican/issues/2941:
	// The previous map[string]string unmarshal target failed whenever the OpenID
	// configuration document contained array-valued fields such as
	// token_endpoint_auth_methods_supported. The struct-based approach only
	// extracts jwks_uri and ignores all other fields regardless of their type.
	t.Run("succeeds when openid-configuration contains array-valued fields", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"issuer": "https://example.com",
				"jwks_uri": "https://example.com/jwks",
				"token_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt"],
				"scopes_supported": ["openid", "email", "profile"],
				"claims_supported": ["sub", "iss", "aud"]
			}`)
		}))
		defer srv.Close()

		got, err := GetJWKSURLFromIssuerURL(srv.URL)
		require.NoError(t, err)
		assert.Equal(t, "https://example.com/jwks", got)
	})

	t.Run("returns error when jwks_uri is absent", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"issuer": "https://example.com"}`)
		}))
		defer srv.Close()

		_, err := GetJWKSURLFromIssuerURL(srv.URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no key found")
	})

	t.Run("falls back to issuer.jwks path on 404", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		got, err := GetJWKSURLFromIssuerURL(srv.URL)
		require.NoError(t, err)
		assert.Contains(t, got, ".well-known/issuer.jwks")
	})

	t.Run("returns error on invalid JSON body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `not valid json`)
		}))
		defer srv.Close()

		_, err := GetJWKSURLFromIssuerURL(srv.URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal")
	})
}
