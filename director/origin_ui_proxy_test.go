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

package director

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsOriginUIProxyPath(t *testing.T) {
	// Origin-owned API paths are proxied.
	assert.True(t, isOriginUIProxyPath("/api/v1.0/origin_ui/exports"))
	assert.True(t, isOriginUIProxyPath("/api/v1.0/auth/whoami"))
	assert.True(t, isOriginUIProxyPath("/api/v1.0/auth/oauth/callback"))
	assert.True(t, isOriginUIProxyPath("/api/v1.0/config"))
	assert.True(t, isOriginUIProxyPath("/api/v1.0/issuer/ns/foo/device"))

	// Pages and static assets are served by the director's own bundle, never proxied.
	assert.False(t, isOriginUIProxyPath("/view/origin/config"))
	assert.False(t, isOriginUIProxyPath("/view/_next/static/chunk.js"))
	// The director's own APIs and the control endpoints stay local.
	assert.False(t, isOriginUIProxyPath("/api/v1.0/director_ui/servers"))
	assert.False(t, isOriginUIProxyPath("/api/v1.0/origin-ui/exit"))
	// Not a prefix match: origin_ui must be a real segment boundary.
	assert.False(t, isOriginUIProxyPath("/api/v1.0/origin_uixyz"))
}

func TestBridgeOriginSetCookies(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Add("Set-Cookie", "login=jwt123; Path=/; HttpOnly; Secure; SameSite=Strict")
	resp.Header.Add("Set-Cookie", "pelican-session=sess456; Path=/; HttpOnly")
	// A cookie the proxy doesn't bridge is passed through untouched.
	resp.Header.Add("Set-Cookie", "csrf_token=tok; Path=/api/v1.0/issuer/ns/foo/device")

	bridgeOriginSetCookies(resp)

	got := resp.Header["Set-Cookie"]
	require.Len(t, got, 3)
	assert.Equal(t, "origin-login=jwt123; Path=/; HttpOnly; Secure; SameSite=Strict", got[0])
	assert.Equal(t, "origin-pelican-session=sess456; Path=/; HttpOnly", got[1])
	assert.Equal(t, "csrf_token=tok; Path=/api/v1.0/issuer/ns/foo/device", got[2])
}

func TestBridgeBrowserCookieHeader(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://director.example/api/v1.0/auth/whoami", nil)
	require.NoError(t, err)
	// The browser carries the origin's bridged cookies, the director's own login,
	// and an unrelated cookie.
	req.Header.Set("Cookie", "origin-login=jwt123; login=director-jwt; origin-pelican-session=sess456; theme=dark")

	bridgeBrowserCookieHeader(req)

	// The origin sees its cookies under their real names; the director's own login
	// is dropped; unrelated cookies survive.
	sent := req.Header.Get("Cookie")
	assert.Contains(t, sent, "login=jwt123")
	assert.Contains(t, sent, "pelican-session=sess456")
	assert.Contains(t, sent, "theme=dark")
	assert.NotContains(t, sent, "director-jwt")
	assert.NotContains(t, sent, "origin-login=")
}

func TestBridgeBrowserCookieHeader_OnlyDirectorLoginIsDropped(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://director.example/api/v1.0/auth/whoami", nil)
	require.NoError(t, err)
	// If the browser has only the director's own login (no managed-origin session
	// cookie), it must not be forwarded to the origin as a valid login.
	req.Header.Set("Cookie", "login=director-jwt")

	bridgeBrowserCookieHeader(req)

	assert.Empty(t, req.Header.Get("Cookie"))
}

// TestRewriteOriginRequestHeaders covers the CSRF/same-origin fix: a proxied
// request must present the origin's own host in Origin/Referer, or the origin
// rejects a POST (e.g. login) as cross-origin.
func TestRewriteOriginRequestHeaders(t *testing.T) {
	originWebURL := url.URL{Scheme: "https", Host: "origin.example:8445"}

	req, err := http.NewRequest(http.MethodPost, "https://director.example/api/v1.0/auth/login", nil)
	require.NoError(t, err)
	req.Header.Set("Origin", "https://director.example")
	req.Header.Set("Referer", "https://director.example/view/origin/login/")

	rewriteOriginRequestHeaders(req, originWebURL)

	assert.Equal(t, "https://origin.example:8445", req.Header.Get("Origin"))
	assert.Equal(t, "https://origin.example:8445/view/origin/login/", req.Header.Get("Referer"))

	// Absent headers stay absent (no spurious values injected).
	req2, err := http.NewRequest(http.MethodGet, "https://director.example/api/v1.0/auth/whoami", nil)
	require.NoError(t, err)
	rewriteOriginRequestHeaders(req2, originWebURL)
	assert.Empty(t, req2.Header.Get("Origin"))
	assert.Empty(t, req2.Header.Get("Referer"))
}

func TestRewriteOriginRedirectLocation(t *testing.T) {
	originHost := "origin.example:8443"
	directorHost := "director.example"

	// An absolute redirect to the origin host is re-pointed at the director.
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("Location", "https://origin.example:8443/view/foo/")
	rewriteOriginRedirectLocation(resp, originHost, directorHost)
	assert.Equal(t, "https://director.example/view/foo/", resp.Header.Get("Location"))

	// A relative redirect (Location path only) is left alone — it resolves against
	// the director host in the browser.
	resp = &http.Response{Header: http.Header{}}
	resp.Header.Set("Location", "/view/login/?returnURL=%2Fview%2Forigin")
	rewriteOriginRedirectLocation(resp, originHost, directorHost)
	assert.Equal(t, "/view/login/?returnURL=%2Fview%2Forigin", resp.Header.Get("Location"))

	// An OIDC bounce to an external IdP whose redirect_uri points back at the
	// origin has that redirect_uri re-pointed at the director (the IdP host is
	// left as-is so the browser still goes to the IdP).
	resp = &http.Response{Header: http.Header{}}
	resp.Header.Set("Location",
		"https://idp.example/authorize?client_id=abc&redirect_uri=https%3A%2F%2Forigin.example%3A8443%2Fapi%2Fv1.0%2Fauth%2Foauth%2Fcallback")
	rewriteOriginRedirectLocation(resp, originHost, directorHost)
	loc := resp.Header.Get("Location")
	assert.Contains(t, loc, "https://idp.example/authorize")
	assert.Contains(t, loc, "redirect_uri=https%3A%2F%2Fdirector.example%2Fapi%2Fv1.0%2Fauth%2Foauth%2Fcallback")
	assert.NotContains(t, loc, "origin.example")
}
