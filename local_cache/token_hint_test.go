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

package local_cache

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// TestSetTokenHintHeaders pins the headers a cache attaches when it refuses a
// request for a namespace that wants a credential: the same three the director
// would have sent, and in the same form its parser reads back.
func TestSetTokenHintHeaders(t *testing.T) {
	ac := &authConfig{}
	issuerURL, err := url.Parse("https://issuer.example.com")
	require.NoError(t, err)
	require.NoError(t, ac.updateConfig([]server_structs.NamespaceAd{
		{
			Path: "/protected",
			Caps: server_structs.Capabilities{Reads: true}, // PublicReads false -> require-token
			Issuer: []server_structs.TokenIssuer{
				{IssuerUrl: *issuerURL, BasePaths: []string{"/protected"}},
			},
			Generation: []server_structs.TokenGen{
				{
					Strategy:         server_structs.OAuthStrategy,
					MaxScopeDepth:    3,
					CredentialIssuer: *issuerURL,
				},
			},
		},
	}))

	hdr := http.Header{}
	ac.SetTokenHintHeaders(hdr, "/protected/secret.txt")

	assert.Equal(t, "namespace=/protected, require-token=true", hdr.Get("X-Pelican-Namespace"))
	assert.Equal(t, "issuer=https://issuer.example.com", hdr.Get("X-Pelican-Authorization"))
	assert.Contains(t, hdr.Get("X-Pelican-Token-Generation"), "strategy=OAuth2")

	// The client reads these with the director-response parser, so the round
	// trip is what makes the hint usable at all.
	var ns server_structs.XPelNs
	require.NoError(t, (&ns).ParseRawHeader(&hdr))
	assert.Equal(t, "/protected", ns.Namespace)
	assert.True(t, ns.RequireToken)
}

// TestHandleErrorAttachesTokenHints pins the wiring rather than the header
// text: the refusal the client actually receives is the one that has to carry
// the hint, and only a refusal a credential could fix.
func TestHandleErrorAttachesTokenHints(t *testing.T) {
	issuerURL, err := url.Parse("https://issuer.example.com")
	require.NoError(t, err)
	ac := &authConfig{}
	require.NoError(t, ac.updateConfig([]server_structs.NamespaceAd{
		{
			Path:   "/protected",
			Caps:   server_structs.Capabilities{Reads: true},
			Issuer: []server_structs.TokenIssuer{{IssuerUrl: *issuerURL, BasePaths: []string{"/protected"}}},
		},
	}))
	pc := &PersistentCache{ac: ac}
	reqLog := log.NewEntry(log.New())

	rec := httptest.NewRecorder()
	pc.handleError(rec, newAuthorizationDenied("no token provided"), "/protected/secret.txt", false, reqLog)
	require.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "namespace=/protected, require-token=true", rec.Header().Get("X-Pelican-Namespace"))
	assert.Equal(t, "issuer=https://issuer.example.com", rec.Header().Get("X-Pelican-Authorization"))

	// An upstream failure is not an invitation to go get a credential.
	rec = httptest.NewRecorder()
	pc.handleError(rec, errors.New("origin went away"), "/protected/secret.txt", false, reqLog)
	assert.Empty(t, rec.Header().Get("X-Pelican-Namespace"))
}

// TestSetTokenHintHeadersMostSpecificNamespace pins that the hint describes the
// namespace that actually covers the object, not merely one that shares a
// prefix with it: nested namespaces can name different issuers.
func TestSetTokenHintHeadersMostSpecificNamespace(t *testing.T) {
	outer, err := url.Parse("https://outer.example.com")
	require.NoError(t, err)
	inner, err := url.Parse("https://inner.example.com")
	require.NoError(t, err)

	ac := &authConfig{}
	require.NoError(t, ac.updateConfig([]server_structs.NamespaceAd{
		{
			Path:   "/foo",
			Caps:   server_structs.Capabilities{Reads: true},
			Issuer: []server_structs.TokenIssuer{{IssuerUrl: *outer, BasePaths: []string{"/foo"}}},
		},
		{
			Path:   "/foo/bar",
			Caps:   server_structs.Capabilities{Reads: true},
			Issuer: []server_structs.TokenIssuer{{IssuerUrl: *inner, BasePaths: []string{"/foo/bar"}}},
		},
	}))

	hdr := http.Header{}
	ac.SetTokenHintHeaders(hdr, "/foo/bar/baz.txt")
	assert.Equal(t, "namespace=/foo/bar, require-token=true", hdr.Get("X-Pelican-Namespace"))
	assert.Equal(t, "issuer=https://inner.example.com", hdr.Get("X-Pelican-Authorization"))

	hdr = http.Header{}
	ac.SetTokenHintHeaders(hdr, "/foo/other.txt")
	assert.Equal(t, "namespace=/foo, require-token=true", hdr.Get("X-Pelican-Namespace"))
	assert.Equal(t, "issuer=https://outer.example.com", hdr.Get("X-Pelican-Authorization"))
}

// TestSetTokenHintHeadersCollectionsUrl pins that a listing-capable namespace is
// advertised with this cache as its collections URL: the cache proxies PROPFIND
// to the origin, so a client that reached the cache can list through it rather
// than being sent elsewhere.
func TestSetTokenHintHeadersCollectionsUrl(t *testing.T) {
	const cacheDataUrl = "https://cache.example.com/api/v1.0/cache/data/fed.example.com"
	require.NoError(t, param.Cache_Url.Set(cacheDataUrl))
	t.Cleanup(func() { require.NoError(t, param.Cache_Url.Set("")) })

	issuerURL, err := url.Parse("https://issuer.example.com")
	require.NoError(t, err)
	ac := &authConfig{}
	require.NoError(t, ac.updateConfig([]server_structs.NamespaceAd{
		{
			Path:   "/protected",
			Caps:   server_structs.Capabilities{Reads: true, Listings: true},
			Issuer: []server_structs.TokenIssuer{{IssuerUrl: *issuerURL, BasePaths: []string{"/protected"}}},
		},
	}))

	hdr := http.Header{}
	ac.SetTokenHintHeaders(hdr, "/protected/dir/")
	assert.Equal(t,
		"namespace=/protected, require-token=true, collections-url="+cacheDataUrl,
		hdr.Get("X-Pelican-Namespace"))

	var ns server_structs.XPelNs
	require.NoError(t, (&ns).ParseRawHeader(&hdr))
	require.NotNil(t, ns.CollectionsUrl)
	assert.Equal(t, cacheDataUrl, ns.CollectionsUrl.String())
}

// TestSetTokenHintHeadersNoCollectionsWhenListingsDisabled pins that the cache
// does not offer to list a namespace whose origin does not allow it, however
// willing the cache itself is to proxy the request.
func TestSetTokenHintHeadersNoCollectionsWhenListingsDisabled(t *testing.T) {
	require.NoError(t, param.Cache_Url.Set("https://cache.example.com/api/v1.0/cache/data/fed.example.com"))
	t.Cleanup(func() { require.NoError(t, param.Cache_Url.Set("")) })

	ac := &authConfig{}
	require.NoError(t, ac.updateConfig([]server_structs.NamespaceAd{
		{Path: "/protected", Caps: server_structs.Capabilities{Reads: true}}, // Listings false
	}))

	hdr := http.Header{}
	ac.SetTokenHintHeaders(hdr, "/protected/x.txt")
	assert.Equal(t, "namespace=/protected, require-token=true", hdr.Get("X-Pelican-Namespace"))
}

// TestSetTokenHintHeadersPublicNamespace pins that a public namespace is
// reported as needing no token.  A client acts on a hint only when it says a
// credential is required, so this is what stops one from being acquired for a
// refusal that a credential would not have fixed.
func TestSetTokenHintHeadersPublicNamespace(t *testing.T) {
	ac := &authConfig{}
	require.NoError(t, ac.updateConfig([]server_structs.NamespaceAd{
		{Path: "/public", Caps: server_structs.Capabilities{Reads: true, PublicReads: true}},
	}))

	hdr := http.Header{}
	ac.SetTokenHintHeaders(hdr, "/public/x.txt")
	assert.Equal(t, "namespace=/public, require-token=false", hdr.Get("X-Pelican-Namespace"))
}

// TestSetTokenHintHeadersNoMatch pins that a path no namespace covers gets no
// hint at all: the cache has nothing to say about it, and an empty
// X-Pelican-Namespace would be read as a claim it does.
func TestSetTokenHintHeadersNoMatch(t *testing.T) {
	ac := &authConfig{}
	require.NoError(t, ac.updateConfig([]server_structs.NamespaceAd{{Path: "/foo"}}))

	hdr := http.Header{}
	ac.SetTokenHintHeaders(hdr, "/bar/x.txt")
	assert.Empty(t, hdr.Get("X-Pelican-Namespace"))
	assert.Empty(t, hdr.Get("X-Pelican-Authorization"))
	assert.Empty(t, hdr.Get("X-Pelican-Token-Generation"))

	// A cache that has not yet heard from its director knows no namespaces at
	// all; it must not panic on the way to saying nothing.
	hdr = http.Header{}
	(&authConfig{}).SetTokenHintHeaders(hdr, "/foo/x.txt")
	assert.Empty(t, hdr.Get("X-Pelican-Namespace"))
}
