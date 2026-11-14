//go:build !windows

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

// The !windows constraint matches the package's other tests that run a whole
// PersistentCache; nothing here is platform-specific.

package local_cache

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// These tests run the WebDAV tiering target against a real dCache, which
// github_scripts/dcache-e2e/run.sh starts (with the configuration in that
// directory) before running them.  Without it they are skipped.  They check
// what the fake door in tier_webdav_test.go and tier_macaroon_test.go can only
// assume: that dCache's gPlazma accepts the cache's WLCG token, issues it a
// macaroon, and honours -- and confines -- the URLs the cache mints from it,
// door-to-pool redirect included.
//
// The environment, which run.sh sets (deliberately not PELICAN_*, which the
// configuration loader would read as configuration keys):
//
//	DCACHE_E2E_WEBDAV_URL  the door, e.g. https://localhost:2880
//	DCACHE_E2E_CA_FILE     the CA that signed the door's and pools' certificates
//	DCACHE_E2E_ISSUER_URL  the issuer gPlazma trusts (exactly the iss to use)
//	DCACHE_E2E_ISSUER_KEY  that issuer's RSA signing key, PEM
//
// The dCache user the tokens map to owns /data/pelican, and gPlazma's WLCG
// prefix is /data (see github_scripts/dcache-e2e/dcache).

const (
	// dcacheE2ECollection is the collection the cache's user owns.
	dcacheE2ECollection = "/data/pelican"
	// dcacheE2ESubject is the token subject gPlazma maps to that user.
	dcacheE2ESubject = "pelican-cache"
	// dcacheE2ERenewedSubject maps to the same uid as dcacheE2ESubject
	// under another user name.
	dcacheE2ERenewedSubject = "pelican-renewed"
	// dcacheE2EKeyID must match the kid the issuer publishes.
	dcacheE2EKeyID = "dcache-e2e-1"
)

type dcacheE2E struct {
	door      string
	issuer    string
	key       jwk.Key
	transport *http.Transport
	caFile    string
}

// newDCacheE2E skips the test unless run.sh has started dCache.
func newDCacheE2E(t *testing.T) *dcacheE2E {
	test_utils.SkipIfShort(t, "needs a dCache instance (github_scripts/dcache-e2e/run.sh)")
	door := os.Getenv("DCACHE_E2E_WEBDAV_URL")
	if door == "" {
		t.Skip("DCACHE_E2E_WEBDAV_URL is not set; github_scripts/dcache-e2e/run.sh runs this test against a dCache")
	}
	e := &dcacheE2E{
		door:   strings.TrimRight(door, "/"),
		issuer: os.Getenv("DCACHE_E2E_ISSUER_URL"),
		caFile: os.Getenv("DCACHE_E2E_CA_FILE"),
	}
	require.NotEmpty(t, e.issuer, "DCACHE_E2E_ISSUER_URL")
	require.NotEmpty(t, e.caFile, "DCACHE_E2E_CA_FILE")

	keyPEM, err := os.ReadFile(os.Getenv("DCACHE_E2E_ISSUER_KEY"))
	require.NoError(t, err, "DCACHE_E2E_ISSUER_KEY")
	e.key, err = jwk.ParseKey(keyPEM, jwk.WithPEM(true))
	require.NoError(t, err)
	require.NoError(t, e.key.Set(jwk.KeyIDKey, dcacheE2EKeyID))

	caPEM, err := os.ReadFile(e.caFile)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caPEM), "no certificate in DCACHE_E2E_CA_FILE")
	e.transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	t.Cleanup(e.transport.CloseIdleConnections)
	return e
}

// token mints a WLCG-profile token for sub, valid for lifetime.
func (e *dcacheE2E) token(t *testing.T, sub string, lifetime time.Duration, scope string) (string, time.Time) {
	t.Helper()
	now := time.Now()
	exp := now.Add(lifetime).Truncate(time.Second)
	tok, err := jwt.NewBuilder().
		Issuer(e.issuer).
		Subject(sub).
		Audience([]string{"https://wlcg.cern.ch/jwt/v1/any"}).
		IssuedAt(now).
		NotBefore(now.Add(-time.Minute)).
		Expiration(exp).
		JwtID(randomHex(t)).
		Claim("wlcg.ver", "1.0").
		Claim("scope", scope).
		Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, e.key))
	require.NoError(t, err)
	return string(signed), exp
}

func randomHex(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 8)
	_, err := rand.Read(buf)
	require.NoError(t, err)
	return hex.EncodeToString(buf)
}

// client is a plain HTTP client trusting the test CA: what a federation
// client following a redirect looks like.  It follows redirects (door to
// pool) and carries no credential but what is in the URL.
func (e *dcacheE2E) client() *http.Client { return &http.Client{Transport: e.transport} }

// do sends a request with an optional bearer token and returns the status
// and body.
func (e *dcacheE2E) do(t *testing.T, method, target, token string, body []byte) (int, []byte) {
	t.Helper()
	contentType := ""
	if body != nil {
		contentType = "application/octet-stream"
	}
	return e.doTyped(t, method, target, token, contentType, body)
}

func (e *dcacheE2E) doTyped(t *testing.T, method, target, token, contentType string, body []byte) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, target, rd)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := e.client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, data
}

// writeToken writes a token file the way a renewal agent would: to a
// temporary file, then renamed into place, so the cache never reads half of
// one.
func writeToken(t *testing.T, path, token string) {
	t.Helper()
	tmp := path + ".tmp"
	require.NoError(t, os.WriteFile(tmp, []byte(token+"\n"), 0600))
	require.NoError(t, os.Rename(tmp, path))
}

// useDCacheCA makes the process transport, which the cache uses for the door
// and its redirect self-test, trust the test CA.
func (e *dcacheE2E) useDCacheCA(t *testing.T) {
	t.Helper()
	require.NoError(t, param.Server_TLSCACertificateFile.Set(e.caFile))
	config.ResetClientInitialized()
}

// newBackend builds the WebDAV backend for a fresh collection below
// dcacheE2ECollection, with the token in a file.
func (e *dcacheE2E) newBackend(t *testing.T, token string) (*webdavTierBackend, string) {
	t.Helper()
	return e.newBackendAt(t, dcacheE2ECollection, token)
}

// newBackendAt is newBackend below collection, a path on the door as the
// token's user sees it.
func (e *dcacheE2E) newBackendAt(t *testing.T, collection, token string) (*webdavTierBackend, string) {
	t.Helper()
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeToken(t, tokenFile, token)
	prefix := "e2e-" + randomHex(t)
	cfg := TierTargetConfig{
		WebDavUrl: e.door + collection, Prefix: prefix, TokenFile: tokenFile, MaxSize: 1 << 30,
	}
	require.NoError(t, cfg.validate())
	b, err := newWebDAVTierBackend(cfg, fileTokenSource{path: cfg.TokenFile})
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })
	return b, prefix
}

// TestDCacheMacaroonExchange checks, against a real door, what the cache
// assumes about obtaining a root macaroon for its collection.
func TestDCacheMacaroonExchange(t *testing.T) {
	e := newDCacheE2E(t)
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	e.useDCacheCA(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("IdentityToken", func(t *testing.T) {
		// A token with no storage.* scopes: dCache authorizes by the
		// user it maps to, which it can express as macaroon caveats.
		tok, _ := e.token(t, dcacheE2ESubject, time.Hour, "openid")
		b, prefix := e.newBackend(t, tok)
		putString(t, b, "aa/object", "bytes for the macaroon")

		root, err := b.macaroons.fetch(ctx)
		require.NoError(t, err)
		t.Logf("root macaroon caveats: %q", caveatIDs(root))
		// Requested for the collection, the macaroon is scoped to it.
		assert.Equal(t, []string{"data", "pelican", prefix}, root.scope)
		assert.WithinDuration(t, time.Now().Add(b.macaroons.validity), root.expiry, time.Minute,
			"the requested validity is granted")
	})

	t.Run("ScopedTokenIsRefused", func(t *testing.T) {
		// dCache cannot serialise a WLCG token's scope-based
		// authorization (MultiTargetedRestriction) as caveats, whether
		// the scopes cover the whole prefix or a path below it, and the
		// cache recognizes its answer.
		for _, scope := range []string{
			"storage.read:/ storage.create:/ storage.modify:/",
			"storage.read:/pelican storage.create:/pelican storage.modify:/pelican",
		} {
			tok, _ := e.token(t, dcacheE2ESubject, time.Hour, scope)
			b, _ := e.newBackend(t, tok)
			// The token is good for everything else.
			putString(t, b, "aa/object", "written with a scoped token")
			_, err := b.macaroons.fetch(ctx)
			require.ErrorIs(t, err, errScopedTokenRefused, "scope %q", scope)
			_, ok := b.probeRedirect(ctx)
			assert.False(t, ok, "scope %q: proxy-only", scope)
		}
	})
}

// macaroonUser is the user name in a macaroon's id: caveat
// ("id:<uid>;<gids>;<user name>"), or "" if it has none.
func macaroonUser(root *rootMacaroon) string {
	for _, c := range caveatIDs(root) {
		if id, ok := strings.CutPrefix(c, "id:"); ok {
			fields := strings.Split(id, ";")
			return fields[len(fields)-1]
		}
	}
	return ""
}

func caveatIDs(root *rootMacaroon) []string {
	var out []string
	for _, c := range root.m.Caveats() {
		out = append(out, string(c.Id))
	}
	return out
}

// TestDCacheMintedURLs follows URLs minted the cache's way to the real door
// and pool, with no credential but the URL's own.
func TestDCacheMintedURLs(t *testing.T) {
	e := newDCacheE2E(t)
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	e.useDCacheCA(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, tc := range []struct {
		name string
		sub  string
		// collection is the WebDavUrl path, in the user's view.
		collection string
		// wantScope is the root macaroon's scope, as the cache reads it.
		wantScope func(prefix string) []string
	}{
		{
			// The macaroon carries path:/data/pelican/<prefix>, the
			// collection asked for.
			name: "UserRootIsSlash", sub: dcacheE2ESubject, collection: dcacheE2ECollection,
			wantScope: func(prefix string) []string { return []string{"data", "pelican", prefix} },
		},
		{
			// A user whose storage-authzdb root is /data/chroot sees
			// that as "/".  Its macaroon carries root:/data/chroot
			// and no path: at all -- the whole root, not the
			// collection asked for -- so the cache names objects by
			// their full path below the root.
			name: "ChrootedUser", sub: "pelican-chroot", collection: "",
			wantScope: func(string) []string { return nil },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok, _ := e.token(t, tc.sub, time.Hour, "openid")
			b, prefix := e.newBackendAt(t, tc.collection, tok)
			putString(t, b, "aa/bb/object", "redirected bytes")
			putString(t, b, "aa/bb/other", "not for this URL")

			_, ok := b.probeRedirect(ctx)
			require.True(t, ok, "the door issued a macaroon")
			root := b.macaroons.root.Load()
			require.NotNil(t, root)
			t.Logf("root macaroon caveats: %q", caveatIDs(root))
			assert.Equal(t, tc.wantScope(prefix), root.scope)

			redirect, err := b.RedirectURL(ctx, "aa/bb/object", 5*time.Minute, nil)
			require.NoError(t, err)
			u, err := url.Parse(redirect)
			require.NoError(t, err)
			require.NotEmpty(t, u.Query().Get("authz"))

			// A client with nothing but the URL follows the door's
			// redirect to the pool and gets the bytes.
			status, body := e.do(t, http.MethodGet, redirect, "", nil)
			require.Equal(t, http.StatusOK, status, string(body))
			assert.Equal(t, "redirected bytes", string(body))

			// Only that object...
			other := *u
			other.Path = strings.TrimSuffix(u.Path, "object") + "other"
			status, _ = e.do(t, http.MethodGet, other.String(), "", nil)
			assert.Equal(t, http.StatusForbidden, status, "another object")
			// ...only for reading...
			status, _ = e.do(t, http.MethodPut, redirect, "", []byte("overwrite"))
			assert.Equal(t, http.StatusForbidden, status, "PUT")
			status, _ = e.do(t, http.MethodDelete, redirect, "", nil)
			assert.Equal(t, http.StatusForbidden, status, "DELETE")
			// ...and only until it expires: minted with a clock an
			// hour slow.
			b.macaroons.now = func() time.Time { return time.Now().Add(-time.Hour) }
			stale, err := b.RedirectURL(ctx, "aa/bb/object", 5*time.Minute, nil)
			b.macaroons.now = time.Now
			require.NoError(t, err)
			status, _ = e.do(t, http.MethodGet, stale, "", nil)
			assert.Equal(t, http.StatusUnauthorized, status, "expired")

			// None of that touched the object.
			status, body = e.do(t, http.MethodGet, b.urlFor(b.rootRel("aa/bb/object"), false), tok, nil)
			require.Equal(t, http.StatusOK, status)
			assert.Equal(t, "redirected bytes", string(body))
		})
	}
}

// TestDCacheUploadOfFormTypedObject: dCache consumes the body of a PUT
// labelled application/x-www-form-urlencoded as a form and stores nothing, so
// the backend must not send an object's own type when it is a form type.
func TestDCacheUploadOfFormTypedObject(t *testing.T) {
	e := newDCacheE2E(t)
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	e.useDCacheCA(t)

	tok, _ := e.token(t, dcacheE2ESubject, time.Hour, "openid")
	b, _ := e.newBackend(t, tok)

	// The door's behaviour this guards against, sent raw.
	status, body := e.doTyped(t, http.MethodPut, b.urlFor(b.rootRel("raw-form"), false), tok,
		"application/x-www-form-urlencoded", []byte("a=1&b=2"))
	t.Logf("raw form-typed PUT: %d %s", status, body)
	assert.Equal(t, http.StatusInternalServerError, status, "a form-typed PUT sent as-is, the case the backend avoids")

	data := "a=1&b=2 is just bytes to the cache"
	info, err := b.Put(context.Background(), "aa/form", "application/x-www-form-urlencoded",
		int64(len(data)), strings.NewReader(data))
	require.NoError(t, err)
	rc, err := b.OpenRange(context.Background(), "aa/form", 0, &info)
	require.NoError(t, err)
	assert.Equal(t, data, readAll(t, rc))
}

// TestDCacheTieringLifecycle runs a cache with a dCache tiering target: an
// object is tiered to dCache, a GET is redirected to it with a minted
// macaroon that a plain client can follow to the bytes, the cache proxies
// once it holds no usable macaroon, and the background refresher picks up a
// renewed token.
func TestDCacheTieringLifecycle(t *testing.T) {
	e := newDCacheE2E(t)
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	InitIssuerKeyForTests(t)
	e.useDCacheCA(t)

	// Refresh often, so the renewed token is picked up within the test.
	oldInterval := tierMacaroonRefreshInterval
	tierMacaroonRefreshInterval = time.Second
	t.Cleanup(func() { tierMacaroonRefreshInterval = oldInterval })

	ctx, cancel := context.WithCancel(context.Background())
	egrp, _ := errgroup.WithContext(ctx)
	t.Cleanup(func() {
		cancel()
		_ = egrp.Wait()
	})
	config.SetFederation(pelican_url.FederationDiscovery{
		DiscoveryEndpoint: "https://cache.example:8443",
		DirectorEndpoint:  "https://cache.example:8443",
	})

	// The first token is short-lived; a renewed one replaces it below.
	// The renewed token's subject maps to the same uid under another user
	// name, and dCache writes the user name into every macaroon's id:
	// caveat, so each root macaroon shows which token obtained it.
	tok1, exp1 := e.token(t, dcacheE2ESubject, 2*time.Minute, "openid")
	tokenFile := filepath.Join(t.TempDir(), "dcache.token")
	writeToken(t, tokenFile, tok1)
	prefix := "e2e-" + randomHex(t)
	setTierTargets(t, []interface{}{
		map[string]interface{}{
			"WebDavUrl": e.door + dcacheE2ECollection,
			"Prefix":    prefix,
			"TokenFile": tokenFile,
			"MaxSize":   "1GB",
		},
	})
	require.NoError(t, param.Cache_TieringThreshold.Set("1KB"))

	tmpDir := t.TempDir()
	pc, err := NewPersistentCache(ctx, egrp, PersistentCacheConfig{
		Mode:        CacheModeServer,
		BaseDir:     tmpDir,
		StorageDirs: []StorageDirConfig{{Path: tmpDir}},
		DeferConfig: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	require.NotNil(t, pc.tierUploader)

	var tierID StorageID
	for id := range pc.storage.tierTargets {
		tierID = id
	}
	target := pc.storage.getTierTarget(tierID)
	require.True(t, target.canRedirect, "dCache issued a macaroon, so the target can redirect")
	require.True(t, target.redirectUsable(), "the redirect self-test fetched the identity object through dCache: %s",
		target.lastRedirectError.Load())
	assert.Equal(t, 1.0, testutil.ToFloat64(tierRedirectCapable.WithLabelValues(target.metricLabel())))
	backend, ok := target.backend.(*webdavTierBackend)
	require.True(t, ok)
	first := backend.macaroons.root.Load()
	require.NotNil(t, first)
	assert.Equal(t, "pelican", macaroonUser(first), "the first root macaroon was obtained with the first token")

	// The token is renewed in place before it expires, as a renewal agent
	// would do it.
	tok2, _ := e.token(t, dcacheE2ERenewedSubject, time.Hour, "openid")
	writeToken(t, tokenFile, tok2)
	require.True(t, time.Now().Before(exp1), "setup took longer than the first token's lifetime")

	require.NoError(t, pc.ac.updateConfig([]server_structs.NamespaceAd{{
		Path: "/test",
		Caps: server_structs.Capabilities{PublicReads: true, Reads: true},
	}}))

	const objectPath = "/test/dcache_object.bin"
	const etag = "dcache-e2e-etag"
	objectHash := pc.db.ObjectHash(pc.normalizePath(objectPath))
	instanceHash := pc.db.InstanceHash(etag, objectHash)
	var diskID StorageID
	for id := range pc.storage.GetDirs() {
		diskID = id
	}
	data := bytes.Repeat([]byte("tiered to a real dCache\n"), 1000)
	storeTestObject(t, ctx, pc.storage, instanceHash, data, diskID, NamespaceID(1))
	require.NoError(t, pc.db.SetLatestETag(objectHash, etag, time.Now()))
	require.NoError(t, pc.db.MergeMetadata(instanceHash, &CacheMetadata{ETag: etag}))

	pc.tierUploader.MaybeEnqueue(instanceHash)
	require.Eventually(t, func() bool {
		meta, err := pc.storage.GetMetadata(instanceHash)
		return err == nil && meta != nil && meta.StorageID == tierID
	}, 60*time.Second, 100*time.Millisecond, "object should be tiered to dCache")

	// The object is in dCache, where the cache put it.
	objectURL := e.door + dcacheE2ECollection + "/" + prefix + "/" + GetInstanceStoragePath(instanceHash)
	status, body := e.do(t, http.MethodGet, objectURL, tok2, nil)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, data, body)

	srv := httptest.NewServer(http.HandlerFunc(pc.serveObject))
	t.Cleanup(srv.Close)
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// The GET is redirected to the door, with a macaroon...
	resp, err := noRedirect.Get(srv.URL + objectPath)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, objectURL, location.Scheme+"://"+location.Host+location.Path)
	require.NotEmpty(t, location.Query().Get("authz"))

	// ...which a client with nothing but the URL follows, door to pool,
	// to the bytes.
	status, body = e.do(t, http.MethodGet, location.String(), "", nil)
	require.Equal(t, http.StatusOK, status, string(body))
	assert.Equal(t, data, body)
	// The URL reads nothing else and writes nothing.
	identity := *location
	identity.Path = dcacheE2ECollection + "/" + prefix + "/" + tierIdentityKey
	status, _ = e.do(t, http.MethodGet, identity.String(), "", nil)
	assert.Equal(t, http.StatusForbidden, status, "the target's identity object")
	status, _ = e.do(t, http.MethodDelete, location.String(), "", nil)
	assert.Equal(t, http.StatusForbidden, status, "DELETE")

	// Renewal: the refresher presents the renewed token -- the user name
	// in each root macaroon's id: caveat tells the tokens apart -- and goes
	// on obtaining macaroons after the first token has expired, requested
	// after that expiry, as their own expiry shows.
	validity := backend.macaroons.validity
	require.Eventually(t, func() bool {
		cur := backend.macaroons.root.Load()
		return cur != nil && macaroonUser(cur) == "pelicanrenewed"
	}, 30*time.Second, 100*time.Millisecond, "the refresher should present the renewed token")
	require.Eventually(t, func() bool {
		cur := backend.macaroons.root.Load()
		return time.Now().After(exp1) && cur.expiry.After(exp1.Add(validity))
	}, 3*time.Minute, 250*time.Millisecond, "the refresher should go on obtaining macaroons after the first token expired")
	resp, err = noRedirect.Get(srv.URL + objectPath)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	status, body = e.do(t, http.MethodGet, resp.Header.Get("Location"), "", nil)
	require.Equal(t, http.StatusOK, status, string(body))
	assert.Equal(t, data, body)

	// With no root macaroon good for a whole redirect, the cache proxies,
	// reading from dCache with its token.
	cur := backend.macaroons.root.Load()
	backend.macaroons.stop()
	backend.macaroons.root.Store(&rootMacaroon{m: cur.m, scope: cur.scope, expiry: time.Now().Add(time.Second)})
	proxied := testutil.ToFloat64(tierRequestsTotal.WithLabelValues(target.metricLabel(), tierServedByProxy))
	resp, err = noRedirect.Get(srv.URL + objectPath)
	require.NoError(t, err)
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	assert.Empty(t, resp.Header.Get("Location"))
	assert.Equal(t, data, body)
	assert.Equal(t, proxied+1, testutil.ToFloat64(tierRequestsTotal.WithLabelValues(target.metricLabel(), tierServedByProxy)))

	// A proxied range, pinned to the entity tag dCache reported.
	req, err := http.NewRequest(http.MethodGet, srv.URL+objectPath, nil)
	require.NoError(t, err)
	req.Header.Set("Range", "bytes=4000-4999")
	resp, err = noRedirect.Do(req)
	require.NoError(t, err)
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusPartialContent, resp.StatusCode, string(body))
	assert.Equal(t, data[4000:5000], body)
}
