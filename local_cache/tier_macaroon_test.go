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
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"gopkg.in/macaroon.v2"
)

// This is the macaroon half of the fake dCache door (see tier_webdav_test.go):
// it issues and verifies real macaroons, with its own transcription of
// dCache's caveat rules -- deliberately not sharing the cache's, so the two
// can disagree.  Like the rest of the WebDAV tests, these need no external
// service and run on every platform.

// issueMacaroon follows MacaroonRequestHandler.buildMacaroon.
func (f *fakeDCache) issueMacaroon(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.macaroonRequests++
	status, session, prefix := f.macaroonStatus, f.sessionLifetime, f.prefixRestriction
	refuse, refuseInPage, xrootdName := f.refuseRestriction, f.refuseInPageOnly, f.xrootdName
	f.mu.Unlock()
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	if refuse {
		// dCache's answer to a token with storage.* scopes.
		const reason = "Cannot serialise restriction MultiTargetedRestriction"
		if refuseInPage {
			http.Error(w, "<html><body><h2>HTTP ERROR 400 "+reason+"</h2></body></html>", http.StatusBadRequest)
		} else {
			f.writeWithReason(w, http.StatusBadRequest, reason)
		}
		return
	}
	var req struct {
		Caveats  []string `json:"caveats"`
		Validity string   `json:"validity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Unable to parse JSON", http.StatusBadRequest)
		return
	}
	now := time.Now()
	var expiry time.Time
	switch {
	case req.Validity != "":
		secs, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(req.Validity, "PT"), "S"))
		if err != nil {
			http.Error(w, "Bad validity value", http.StatusBadRequest)
			return
		}
		expiry = now.Add(time.Duration(secs) * time.Second)
		if session > 0 && expiry.After(now.Add(session)) {
			http.Error(w, "before: cannot extend session lifetime", http.StatusBadRequest)
			return
		}
	case session > 0:
		expiry = now.Add(session)
	default:
		expiry = now.Add(time.Hour)
	}

	scope := strings.TrimRight(r.URL.Path, "/")
	if prefix != "" {
		scope = prefix
	}
	m, err := macaroon.New(f.key, []byte("fake-secret-id"), "Optional["+scope+"]", macaroon.V1)
	require.NoError(f.t, err)
	caveats := []string{"iid:dGVzdA", "id:1000;1000;pelican", "before:" + expiry.UTC().Format(time.RFC3339Nano)}
	if scope != "" {
		caveats = append(caveats, "path:"+scope)
	}
	caveats = append(caveats, req.Caveats...)
	if xrootdName {
		caveats = append(caveats, "name:pelican")
	}
	for _, c := range caveats {
		require.NoError(f.t, m.AddFirstPartyCaveat([]byte(c)))
	}
	data, err := m.MarshalBinary()
	require.NoError(f.t, err)
	// jmacaroons' v1 serializer: base64url without padding.
	encoded := base64.RawURLEncoding.EncodeToString(data)

	f.mu.Lock()
	f.issued++
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"macaroon": encoded,
		"uri": map[string]string{
			"targetWithMacaroon": f.url(r.URL.Path) + "?authz=" + encoded,
			"target":             f.url(r.URL.Path),
		},
	})
}

// writeWithReason answers with reason as the status line's reason phrase, as
// dCache's door explains some refusals.  net/http's ResponseWriter always
// writes the standard phrase, so the response is written on the hijacked
// connection.
func (f *fakeDCache) writeWithReason(w http.ResponseWriter, code int, reason string) {
	conn, buf, err := http.NewResponseController(w).Hijack()
	require.NoError(f.t, err)
	defer conn.Close()
	_, _ = fmt.Fprintf(buf, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, reason)
	_ = buf.Flush()
}

// dcacheChroot is FsPath.chroot, transcribed: path is resolved against base
// even when absolute, and ".." never walks above base.
func dcacheChroot(base []string, path string) []string {
	i := strings.LastIndex(path, "/")
	var parent []string
	var name string
	switch i {
	case -1:
		parent, name = base, path
	case 0:
		parent, name = base, path[1:]
	default:
		parent, name = dcacheChroot(base, path[:i]), path[i+1:]
	}
	switch name {
	case "", ".":
		return parent
	case "..":
		if len(parent) == len(base) {
			return parent
		}
		return parent[:len(parent)-1]
	default:
		return append(append([]string(nil), parent...), name)
	}
}

var dcacheActivities = []string{"READ_METADATA", "UPDATE_METADATA", "LIST", "DOWNLOAD", "MANAGE", "UPLOAD", "DELETE"}

// authorize verifies a macaroon and checks the request against its caveats,
// returning the caveats.
func (f *fakeDCache) authorize(r *http.Request, encoded string) ([]string, error) {
	raw, err := macaroon.Base64Decode([]byte(encoded))
	if err != nil {
		return nil, errors.Wrap(err, "not a macaroon")
	}
	var m macaroon.Macaroon
	if err := m.UnmarshalBinary(raw); err != nil {
		return nil, errors.Wrap(err, "not a macaroon")
	}
	caveats, err := m.VerifySignature(f.key, nil)
	if err != nil {
		return nil, errors.Wrap(err, "invalid macaroon")
	}

	f.mu.Lock()
	xrootd := f.xrootd
	f.mu.Unlock()
	target := dcacheChroot(nil, r.URL.Path)
	var scope []string
	allowed := map[string]bool{}
	for _, a := range dcacheActivities {
		allowed[a] = true
	}
	for _, c := range caveats {
		kind, value, _ := strings.Cut(c, ":")
		switch kind {
		case "iid", "id":
		case "before":
			expiry, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return nil, errors.Errorf("Bad ISO 8601 timestamp: %s", c)
			}
			if time.Now().After(expiry) {
				return nil, errors.Errorf("expired: %s", c)
			}
		case "path":
			if !xrootd {
				scope = dcacheChroot(scope, value)
				break
			}
			// XRootD: each path: is absolute, checked on its own.
			if !hasPathPrefix(target, dcacheChroot(nil, value)) {
				return nil, errors.Errorf("path not allowed: %s", c)
			}
		case "name":
			if !xrootd {
				return nil, errors.Errorf("unknown caveat: %s", c)
			}
		case "activity":
			next := map[string]bool{}
			for _, a := range strings.Split(value, ",") {
				a = strings.TrimSpace(a)
				if !allowed[a] {
					return nil, errors.Errorf("attempt to enlarge activity set: %s", c)
				}
				next[a] = true
			}
			allowed = next
		case "ip":
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			ok := false
			for _, cidr := range strings.Split(value, ",") {
				if _, n, err := net.ParseCIDR(cidr); err == nil && n.Contains(net.ParseIP(host)) {
					ok = true
				}
			}
			if !ok {
				return nil, errors.Errorf("client address not allowed: %s", c)
			}
		default:
			return nil, errors.Errorf("unknown caveat: %s", c)
		}
	}

	// Any granted activity implies READ_METADATA.
	if len(allowed) > 0 {
		allowed["READ_METADATA"] = true
	}
	need := map[string]string{
		http.MethodGet: "DOWNLOAD", http.MethodHead: "READ_METADATA", "PROPFIND": "LIST",
		http.MethodPut: "UPLOAD", http.MethodDelete: "DELETE", "MKCOL": "MANAGE",
	}[r.Method]
	if need == "" || !allowed[need] {
		return nil, errors.Errorf("%s is not permitted", r.Method)
	}
	if !hasPathPrefix(target, scope) {
		return nil, errors.New("path is outside the macaroon's scope")
	}
	return caveats, nil
}

// hasPathPrefix reports whether path lies at or under prefix, element-wise.
func hasPathPrefix(path, prefix []string) bool {
	if len(path) < len(prefix) {
		return false
	}
	for i := range prefix {
		if path[i] != prefix[i] {
			return false
		}
	}
	return true
}

// TestMacaroonInteropWithJmacaroons pins the Go library to the bytes
// jmacaroons -- the library dCache uses -- produces for the example in its
// README, so a macaroon dCache issues decodes here and one minted here
// verifies there: the same v1 packet layout, the same key derivation, the
// same base64url-without-padding encoding, and the same HMAC chain.
func TestMacaroonInteropWithJmacaroons(t *testing.T) {
	m, err := macaroon.New([]byte("this is our super secret key; only we should know it"),
		[]byte("we used our secret key"), "http://www.example.org", macaroon.V1)
	require.NoError(t, err)
	data, err := m.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, "MDAyNGxvY2F0aW9uIGh0dHA6Ly93d3cuZXhhbXBsZS5vcmcKMDAyNmlkZW50aWZpZXIgd2UgdXNlZCBvdXIgc2VjcmV0IGtleQowMDJmc2lnbmF0dXJlIOPZ4CkIUmxMADmuFRFBFdl_3Wi_K6N5s0Kq8PYX0FUvCg",
		base64.RawURLEncoding.EncodeToString(data))
	assert.Equal(t, "e3d9e02908526c4c0039ae15114115d97fdd68bf2ba379b342aaf0f617d0552f", hex.EncodeToString(m.Signature()))

	// Attenuation needs no secret: only the signature so far.
	require.NoError(t, m.AddFirstPartyCaveat([]byte("account = 3735928559")))
	assert.Equal(t, "1efe4763f290dbce0c1d08477367e11f4eee456a64933cf662d79772dbb82128", hex.EncodeToString(m.Signature()))
}

func TestChrootPath(t *testing.T) {
	for _, tc := range []struct {
		base []string
		path string
		want []string
	}{
		{nil, "/data/pelican", []string{"data", "pelican"}},
		{[]string{"data"}, "/pelican/aa", []string{"data", "pelican", "aa"}},
		{[]string{"data"}, "pelican/./aa/", []string{"data", "pelican", "aa"}},
		{[]string{"data"}, "/x/../y", []string{"data", "y"}},
		// ".." cannot climb out of the scope it is resolved against.
		{[]string{"data"}, "/../../etc", []string{"data", "etc"}},
	} {
		got := chrootPath(tc.base, tc.path)
		assert.Equal(t, tc.want, got, "%v + %q", tc.base, tc.path)
		// The cache's composition must agree with dCache's.
		assert.Equal(t, tc.want, dcacheChroot(tc.base, tc.path), "dCache's rule for %v + %q", tc.base, tc.path)
	}
}

// TestWebDAVMacaroonRedirect follows a minted URL to the fake door, which
// verifies the macaroon cryptographically and checks every caveat.
func TestWebDAVMacaroonRedirect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, tc := range []struct {
		name string
		// prefixRestriction makes the door scope the root macaroon to a
		// path above the requested collection, as it does for a login
		// restricted to a path prefix.
		prefixRestriction string
		// wantPath is the path caveat the cache must add: the object
		// relative to the root macaroon's scope.
		wantPath string
	}{
		{name: "RequestPathScope", wantPath: "path:/aa/bb/object"},
		{name: "LoginPrefixScope", prefixRestriction: "/data/pelican", wantPath: "path:/cache/aa/bb/object"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeDCache(t)
			f.set(func(f *fakeDCache) { f.prefixRestriction = tc.prefixRestriction })
			b := newFakeDCacheBackend(t, f, "pelican/cache", false)
			putString(t, b, "aa/bb/object", "redirected bytes")
			putString(t, b, "aa/bb/other", "not for this URL")

			probe, ok := b.probeRedirect(ctx)
			require.True(t, ok, "a door that issues macaroons can redirect")
			assert.NotContains(t, probe, "authz", "the probe URL must not carry a credential")
			probeURL, err := url.Parse(probe)
			require.NoError(t, err)
			assert.Equal(t, f.srv.Listener.Addr().String(), probeURL.Host)

			redirect, err := b.RedirectURL(ctx, "aa/bb/object", 5*time.Minute, nil)
			require.NoError(t, err)
			u, err := url.Parse(redirect)
			require.NoError(t, err)
			assert.Equal(t, "/data/pelican/cache/aa/bb/object", u.Path)
			require.NotEmpty(t, u.Query().Get("authz"))

			// No Authorization header: the URL authorizes itself.
			resp, err := http.Get(redirect)
			require.NoError(t, err)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
			assert.Equal(t, "redirected bytes", string(body))
			_, reads, caveats := f.stats()
			assert.Equal(t, 1, reads)
			assert.Contains(t, caveats, "activity:DOWNLOAD")
			assert.Contains(t, caveats, tc.wantPath)

			mac := u.Query().Get("authz")
			// The macaroon is good for that object only...
			other := *u
			other.Path = "/data/pelican/cache/aa/bb/other"
			assertDoorStatus(t, http.MethodGet, other.String(), nil, http.StatusForbidden)
			// ...for reading only...
			assertDoorStatus(t, http.MethodPut, redirect, strings.NewReader("overwrite"), http.StatusForbidden)
			assertDoorStatus(t, http.MethodDelete, redirect, nil, http.StatusForbidden)
			// ...and only as minted: a forged signature fails.
			forged := u.Query()
			forged.Set("authz", mac[:len(mac)-4]+flipBase64(mac[len(mac)-4:]))
			tampered := *u
			tampered.RawQuery = forged.Encode()
			assertDoorStatus(t, http.MethodGet, tampered.String(), nil, http.StatusForbidden)

			// A URL minted with a clock an hour slow is already expired at
			// the door.
			b.macaroons.now = func() time.Time { return time.Now().Add(-time.Hour) }
			stale, err := b.RedirectURL(ctx, "aa/bb/object", 5*time.Minute, nil)
			b.macaroons.now = time.Now
			require.NoError(t, err)
			assertDoorStatus(t, http.MethodGet, stale, nil, http.StatusForbidden)
		})
	}
}

// flipBase64 changes every character of s to a different base64url one.
func flipBase64(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c == 'A' {
			out[i] = 'B'
		} else {
			out[i] = 'A'
		}
	}
	return string(out)
}

func assertDoorStatus(t *testing.T, method, target string, body io.Reader, want int) {
	t.Helper()
	req, err := http.NewRequest(method, target, body)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	msg, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	assert.Equal(t, want, resp.StatusCode, "%s %s: %s", method, target, msg)
}

// TestWebDAVMacaroonsRefused covers a door that does not issue macaroons --
// macaroons disabled, or not dCache at all: the target is proxy-only, and no
// refresher keeps asking.
func TestWebDAVMacaroonsRefused(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := newFakeDCache(t)
	f.set(func(f *fakeDCache) { f.macaroonStatus = http.StatusMethodNotAllowed })
	b := newFakeDCacheBackend(t, f, "cache", false)

	_, ok := b.probeRedirect(ctx)
	assert.False(t, ok)
	_, err := b.RedirectURL(ctx, "aa/bb/object", 5*time.Minute, nil)
	assert.Error(t, err)
	assert.Nil(t, b.macaroons, "a refused door gets no refresher")
}

// TestWebDAVMacaroonOutage covers a door that cannot issue a macaroon for a
// while: redirects fail (so the cache proxies) until the refresher gets one.
func TestWebDAVMacaroonOutage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prev := tierMacaroonRefreshInterval
	tierMacaroonRefreshInterval = 20 * time.Millisecond
	t.Cleanup(func() { tierMacaroonRefreshInterval = prev })

	f := newFakeDCache(t)
	f.set(func(f *fakeDCache) { f.macaroonStatus = http.StatusServiceUnavailable })
	b := newFakeDCacheBackend(t, f, "cache", false)
	putString(t, b, "aa/bb/object", "eventually redirected")

	// An outage is not a refusal: the target stays redirect-capable...
	_, ok := b.probeRedirect(ctx)
	require.True(t, ok)
	// ...but has nothing to mint from yet.
	_, err := b.RedirectURL(ctx, "aa/bb/object", 5*time.Minute, nil)
	require.Error(t, err)

	f.set(func(f *fakeDCache) { f.macaroonStatus = 0 })
	var redirect string
	require.Eventually(t, func() bool {
		redirect, err = b.RedirectURL(ctx, "aa/bb/object", 5*time.Minute, nil)
		return err == nil
	}, 10*time.Second, 10*time.Millisecond, "the refresher should obtain a macaroon once the door recovers")
	assertDoorStatus(t, http.MethodGet, redirect, nil, http.StatusOK)

	// The refresher keeps replacing it.
	issued, _, _ := f.stats()
	require.Eventually(t, func() bool {
		now, _, _ := f.stats()
		return now > issued
	}, 10*time.Second, 10*time.Millisecond)
}

// TestWebDAVMacaroonShortSession covers a login session that ends sooner than
// the root macaroon the cache asks for.  dCache refuses to issue a macaroon
// that outlives a session with an expiry of its own -- a login made with a
// macaroon, the only kind that carries one in dCache 11.2; the cache then
// takes what the door will give, and uses it only while it outlasts the URLs
// minted from it.
func TestWebDAVMacaroonShortSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := newFakeDCache(t)
	f.set(func(f *fakeDCache) { f.sessionLifetime = 7 * time.Minute })
	b := newFakeDCacheBackend(t, f, "cache", false)
	putString(t, b, "aa/bb/object", "short session")

	_, ok := b.probeRedirect(ctx)
	require.True(t, ok)
	// Seven minutes is enough for a five-minute URL...
	redirect, err := b.RedirectURL(ctx, "aa/bb/object", 5*time.Minute, nil)
	require.NoError(t, err)
	assertDoorStatus(t, http.MethodGet, redirect, nil, http.StatusOK)
	// ...but not for a ten-minute one, which would die early at the door.
	_, err = b.RedirectURL(ctx, "aa/bb/object", 10*time.Minute, nil)
	assert.ErrorContains(t, err, "too soon")
}

func TestParseRootMacaroon(t *testing.T) {
	key := []byte("k")
	mint := func(caveats ...string) string {
		m, err := macaroon.New(key, []byte("id"), "loc", macaroon.V1)
		require.NoError(t, err)
		for _, c := range caveats {
			require.NoError(t, m.AddFirstPartyCaveat([]byte(c)))
		}
		data, err := m.MarshalBinary()
		require.NoError(t, err)
		return base64.RawURLEncoding.EncodeToString(data)
	}
	soon := time.Now().Add(time.Hour).UTC()
	later := soon.Add(time.Hour)

	root, err := parseRootMacaroon(mint("iid:x", "id:1;1;u", "before:"+later.Format(time.RFC3339Nano),
		"root:/vo", "path:/data", "activity:DOWNLOAD,LIST", "before:"+soon.Format(time.RFC3339Nano), "path:pelican"))
	require.NoError(t, err)
	assert.True(t, root.expiry.Equal(soon), "the earliest expiry wins")
	assert.Equal(t, []string{"data", "pelican"}, root.scope)

	// Standard base64 with padding, as other tools print it, decodes too.
	m, err := macaroon.New(key, []byte("id"), "loc", macaroon.V1)
	require.NoError(t, err)
	require.NoError(t, m.AddFirstPartyCaveat([]byte("before:"+soon.Format(time.RFC3339Nano))))
	data, err := m.MarshalBinary()
	require.NoError(t, err)
	_, err = parseRootMacaroon(base64.StdEncoding.EncodeToString(data))
	require.NoError(t, err)

	for name, encoded := range map[string]string{
		"NoExpiry":      mint("path:/data"),
		"NoDownload":    mint("before:"+soon.Format(time.RFC3339Nano), "activity:UPLOAD,LIST"),
		"RootAfterPath": mint("before:"+soon.Format(time.RFC3339Nano), "path:/data", "root:/vo"),
		"NotAMacaroon":  base64.RawURLEncoding.EncodeToString([]byte("hello")),
		"UnknownCaveat": mint("before:"+soon.Format(time.RFC3339Nano), "name:xrootd-user"),
	} {
		_, err := parseRootMacaroon(encoded)
		assert.Error(t, err, name)
	}
}

// TestWebDAVNonDCacheIssuer covers a server that speaks dCache's macaroon
// request protocol without dCache's caveat semantics -- XRootD, which adds a
// name: caveat and reads every path: as absolute.  Attenuating its macaroon
// the dCache way would mint URLs that fail at the server, so its macaroons are
// refused and the target is proxy-only.
func TestWebDAVNonDCacheIssuer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := newFakeDCache(t)
	f.set(func(f *fakeDCache) { f.xrootd, f.xrootdName = true, true })
	b := newFakeDCacheBackend(t, f, "cache", false)

	_, err := b.macaroons.fetch(ctx)
	require.ErrorIs(t, err, errMacaroonsRefused)
	assert.ErrorContains(t, err, "not dCache")
	_, ok := b.probeRedirect(ctx)
	assert.False(t, ok)
}

// captureWarnings collects what is logged at warning level or above until the
// test ends.
func captureWarnings(t *testing.T) func() []string {
	saved := log.StandardLogger().ReplaceHooks(make(log.LevelHooks))
	hook := logrustest.NewLocal(log.StandardLogger())
	t.Cleanup(func() { log.StandardLogger().ReplaceHooks(saved) })
	return func() []string {
		var out []string
		for _, e := range hook.AllEntries() {
			if e.Level <= log.WarnLevel {
				out = append(out, e.Message)
			}
		}
		return out
	}
}

// TestWebDAVMacaroonRefusedForScopedToken covers dCache's refusal to issue a
// macaroon for a token with storage.* scopes, recognized from the reason
// phrase or, as over HTTP/2, from the error page alone: the target is
// proxy-only, the request is not retried (no validity changes the answer),
// and the one warning names the cause and what to do about it.
func TestWebDAVMacaroonRefusedForScopedToken(t *testing.T) {
	for _, tc := range []struct {
		name       string
		inPageOnly bool
	}{
		{name: "ReasonPhrase"},
		{name: "ErrorPageOnly", inPageOnly: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			warnings := captureWarnings(t)
			f := newFakeDCache(t)
			f.set(func(f *fakeDCache) { f.refuseRestriction, f.refuseInPageOnly = true, tc.inPageOnly })
			b := newFakeDCacheBackend(t, f, "cache", false)

			_, err := b.macaroons.fetch(ctx)
			require.ErrorIs(t, err, errScopedTokenRefused)
			require.ErrorIs(t, err, errMacaroonsRefused)
			if !tc.inPageOnly {
				assert.ErrorContains(t, err, "400 Cannot serialise restriction MultiTargetedRestriction")
			}
			f.mu.Lock()
			assert.Equal(t, 1, f.macaroonRequests, "the refusal is not retried")
			f.mu.Unlock()

			_, ok := b.probeRedirect(ctx)
			assert.False(t, ok)
			assert.Nil(t, b.macaroons, "the target is proxy-only")
			logged := warnings()
			require.Len(t, logged, 1)
			assert.Contains(t, logged[0], b.display)
			assert.Contains(t, logged[0], "carries storage.* scopes")
			assert.Contains(t, logged[0], scopedTokenRemedy)
		})
	}
}

// TestWebDAVMacaroonRefusedForToken covers a door that refuses a macaroon for
// the token with a 400 and no reason the cache recognizes: the request is
// retried once without a validity, then the target is proxy-only with a
// warning that quotes the door's answer.
func TestWebDAVMacaroonRefusedForToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	warnings := captureWarnings(t)
	f := newFakeDCache(t)
	f.set(func(f *fakeDCache) { f.macaroonStatus = http.StatusBadRequest })
	b := newFakeDCacheBackend(t, f, "cache", false)

	_, err := b.macaroons.fetch(ctx)
	require.ErrorIs(t, err, errMacaroonsRefused)
	assert.NotErrorIs(t, err, errScopedTokenRefused)
	assert.ErrorContains(t, err, "refused to issue a macaroon for this token")
	f.mu.Lock()
	assert.Equal(t, 2, f.macaroonRequests, "retried once without a validity")
	f.mu.Unlock()

	_, ok := b.probeRedirect(ctx)
	assert.False(t, ok)
	logged := warnings()
	require.Len(t, logged, 1)
	assert.Contains(t, logged[0], "did not issue a macaroon")
	assert.NotContains(t, logged[0], "storage.*")
}

// TestWebDAVMacaroonRefresherStopsWithCache: closing the storage manager
// stops each WebDAV target's macaroon refresher, which would otherwise run
// until the cache's context ends.
func TestWebDAVMacaroonRefresherStopsWithCache(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	InitIssuerKeyForTests(t)
	f := newFakeDCache(t)
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte(fakeDCacheToken), 0600))
	tmpDir := t.TempDir()
	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{tmpDir}, 0, egrp)
	require.NoError(t, err)
	t.Cleanup(func() { storage.Close() })

	cfg := TierTargetConfig{WebDavUrl: f.url("/data"), Prefix: "cache", TokenFile: tokenFile, MaxSize: 1 << 30}
	require.NoError(t, cfg.validate())
	registered, err := storage.RegisterTierTargets(ctx, []TierTargetConfig{cfg})
	require.NoError(t, err)
	require.Len(t, registered, 1)
	var target *tierTarget
	for id := range registered {
		target = storage.getTierTarget(id)
	}
	b, ok := target.backend.(*webdavTierBackend)
	require.True(t, ok)
	require.NotNil(t, b.macaroons)
	done := b.macaroons.done
	require.NotNil(t, done, "registration starts the refresher")

	storage.Close()
	select {
	case <-done:
	default:
		t.Fatal("the macaroon refresher is still running after the storage manager closed")
	}
}
