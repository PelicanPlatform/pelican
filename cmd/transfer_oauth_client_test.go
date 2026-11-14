//go:build client || server

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

package main

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/transfer"
)

// TestBuildOAuthClientCreateRequestSendsGrantTypes is the regression test for
// the defect this function was extracted to fix: the add command built its
// body as an ad-hoc map that never named grant_types, so the field never
// reached the server.  The server then stored a client with no grant types,
// and findOAuthClientForGrant skips any client whose grant types do not
// include the one being requested -- so the client could not be selected for
// either bootstrap flow, and the only symptom was a later "no OAuth client
// configured for this issuer".
//
// The assertion is made against the marshalled JSON rather than the struct,
// because the struct carrying the value is not the part that was broken.
func TestBuildOAuthClientCreateRequestSendsGrantTypes(t *testing.T) {
	req, err := buildOAuthClientCreateRequest("example", "https://issuer.example.com",
		"client-id", "client-secret", transfer.GrantTypeTokenExchange, "")
	require.NoError(t, err)

	body, err := json.Marshal(req)
	require.NoError(t, err)

	var wire map[string]any
	require.NoError(t, json.Unmarshal(body, &wire))

	require.Contains(t, wire, "grant_types", "the request must carry grant_types or the client can never be selected")
	assert.Equal(t, transfer.GrantTypeTokenExchange, wire["grant_types"])
	assert.Equal(t, "example", wire["name"])
	assert.Equal(t, "https://issuer.example.com", wire["issuer_url"])
	assert.Equal(t, "client-id", wire["client_id"])
	assert.Equal(t, "client-secret", wire["client_secret"])
}

// TestBuildOAuthClientCreateRequestGrantTypeSpelling pins the wire spelling of
// the grants.  The CLI and findOAuthClientForGrant agree only because both
// read the same constants; this test fails if a constant is edited to
// something the OAuth specs do not name, which would otherwise show up as
// clients that silently never match.
func TestBuildOAuthClientCreateRequestGrantTypeSpelling(t *testing.T) {
	assert.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", transfer.GrantTypeTokenExchange)
	assert.Equal(t, "authorization_code", transfer.GrantTypeAuthorizationCode)
}

func TestBuildOAuthClientCreateRequest(t *testing.T) {
	t.Run("joins several grants with whitespace", func(t *testing.T) {
		// The CLI takes them comma-separated, matching
		// `origin issuer client create`; the server matches on
		// strings.Fields, so they have to go out whitespace-separated.
		req, err := buildOAuthClientCreateRequest("n", "https://i.example.com", "id", "secret",
			transfer.GrantTypeAuthorizationCode+", "+transfer.GrantTypeTokenExchange, "")
		require.NoError(t, err)
		assert.Equal(t,
			transfer.GrantTypeAuthorizationCode+" "+transfer.GrantTypeTokenExchange,
			req.GrantTypes)
		assert.Equal(t, []string{transfer.GrantTypeAuthorizationCode, transfer.GrantTypeTokenExchange},
			strings.Fields(req.GrantTypes), "the server splits this field on whitespace")
	})

	t.Run("joins scopes with whitespace", func(t *testing.T) {
		req, err := buildOAuthClientCreateRequest("n", "https://i.example.com", "id", "secret",
			transfer.GrantTypeTokenExchange, "storage.read:/, storage.modify:/")
		require.NoError(t, err)
		assert.Equal(t, "storage.read:/ storage.modify:/", req.Scopes)
	})

	t.Run("omits scopes when none are given", func(t *testing.T) {
		// An empty Scopes is how a client says "usable for any scope";
		// findOAuthClientForGrant keeps such clients as fallbacks.
		req, err := buildOAuthClientCreateRequest("n", "https://i.example.com", "id", "secret",
			transfer.GrantTypeTokenExchange, "")
		require.NoError(t, err)
		assert.Empty(t, req.Scopes)
	})

	t.Run("rejects an unsupported grant", func(t *testing.T) {
		// The server never rejects this -- it just never matches -- so
		// the CLI has to.
		_, err := buildOAuthClientCreateRequest("n", "https://i.example.com", "id", "secret",
			"client_credentials", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported grant type")
		assert.Contains(t, err.Error(), transfer.GrantTypeTokenExchange,
			"the error should name the values that are accepted")
	})

	t.Run("rejects a near-miss spelling", func(t *testing.T) {
		_, err := buildOAuthClientCreateRequest("n", "https://i.example.com", "id", "secret",
			"token-exchange", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported grant type")
	})

	for _, empty := range []string{"", "   ", ",", " , "} {
		t.Run("rejects empty grant types "+strconv.Quote(empty), func(t *testing.T) {
			_, err := buildOAuthClientCreateRequest("n", "https://i.example.com", "id", "secret", empty, "")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "--grant-types is required")
		})
	}
}
