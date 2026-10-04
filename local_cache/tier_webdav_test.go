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
	"bytes"
	"context"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/webdav"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// These tests need no external service, so they run on every platform.  The
// fake dCache door below serves WebDAV from golang.org/x/net/webdav; its
// macaroon half is in tier_macaroon_test.go.

const fakeDCacheToken = "fake-dcache-bearer-token"

// fakeDCache is a WebDAV door that issues macaroons the way dCache's
// MacaroonRequestHandler does and authorizes requests with them the way
// dCache's MacaroonProcessor and ContextExtractingCaveatVerifier do.
type fakeDCache struct {
	t   *testing.T
	srv *httptest.Server
	key []byte
	dav http.Handler

	mu sync.Mutex
	// macaroonStatus, when non-zero, is how macaroon requests are answered
	// instead of issuing one (405: not dCache; 503: an outage).
	macaroonStatus int
	// sessionLifetime, when non-zero, is how long the login session stays
	// valid; dCache refuses a macaroon that would outlive a session with
	// an expiry of its own -- a login made with a macaroon, the only kind
	// that carries one in dCache 11.2.
	sessionLifetime time.Duration
	// prefixRestriction emulates a login restricted to a path prefix (by
	// gPlazma's omnisession prefix:, say): dCache then puts the prefix in
	// the path caveat rather than the request path.
	prefixRestriction string
	// refuseRestriction emulates a token with storage.* scopes, whose
	// restriction dCache cannot serialise as caveats whatever paths the
	// scopes name: every macaroon request is answered "400 Cannot
	// serialise restriction MultiTargetedRestriction".  With
	// refuseInPageOnly the reason is only in the error page, as over
	// HTTP/2, which has no reason phrase.
	refuseRestriction bool
	refuseInPageOnly  bool
	// xrootd makes the door issue and check macaroons the way XRootD's
	// XrdMacaroons does: every path: caveat is an absolute prefix of the
	// request path, rather than relative to the one before.  xrootdName
	// adds the name: caveat XRootD writes into the macaroons it issues.
	xrootd     bool
	xrootdName bool
	// macaroonRequests counts the macaroon requests the door received,
	// and issued those it answered with a macaroon.
	macaroonRequests int
	issued           int
	// macaroonReads counts data requests a macaroon authorized, and
	// lastCaveats is the verified caveat list of the latest one.
	macaroonReads int
	lastCaveats   []string
}

func newFakeDCache(t *testing.T) *fakeDCache { return newFakeDCacheWrapping(t, nil) }

// newFakeDCacheWrapping is newFakeDCache with its WebDAV handler wrapped by
// wrap, to model a server's quirks.
func newFakeDCacheWrapping(t *testing.T, wrap func(http.Handler) http.Handler) *fakeDCache {
	t.Helper()
	fs := webdav.NewMemFS()
	require.NoError(t, fs.Mkdir(context.Background(), "/data", 0755))
	f := &fakeDCache{
		t:   t,
		key: []byte("fake dCache macaroon secret; only the door knows it"),
		dav: &webdav.Handler{FileSystem: fs, LockSystem: webdav.NewMemLS()},
	}
	if wrap != nil {
		f.dav = wrap(f.dav)
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// url is the door URL of path.
func (f *fakeDCache) url(path string) string { return f.srv.URL + path }

func (f *fakeDCache) set(fn func(f *fakeDCache)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeDCache) stats() (issued, reads int, caveats []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.issued, f.macaroonReads, append([]string(nil), f.lastCaveats...)
}

func (f *fakeDCache) serve(w http.ResponseWriter, r *http.Request) {
	var macaroons []string
	if q := r.URL.Query()["authz"]; len(q) > 0 {
		macaroons = append(macaroons, q...)
	}
	bearer, hasBearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if hasBearer && bearer != fakeDCacheToken {
		macaroons = append(macaroons, bearer)
	}

	// Macaroon requests go to the handler only with exactly this type.
	if r.Method == http.MethodPost && r.Header.Get("Content-Type") == macaroonRequestType {
		if bearer != fakeDCacheToken {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		f.issueMacaroon(w, r)
		return
	}

	switch {
	case len(macaroons) > 1:
		http.Error(w, "3rd party macaroons currently not supported", http.StatusBadRequest)
		return
	case len(macaroons) == 1:
		caveats, err := f.authorize(r, macaroons[0])
		if err != nil {
			http.Error(w, "macaroon login denied: "+err.Error(), http.StatusForbidden)
			return
		}
		f.mu.Lock()
		f.macaroonReads++
		f.lastCaveats = caveats
		f.mu.Unlock()
	case bearer != fakeDCacheToken:
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}
	f.dav.ServeHTTP(w, r)
}

// newFakeDCacheBackend builds a WebDAV backend against f with the given
// prefix, closing it when the test ends.
func newFakeDCacheBackend(t *testing.T, f *fakeDCache, prefix string, disableMacaroons bool) *webdavTierBackend {
	t.Helper()
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte(fakeDCacheToken+"\n"), 0600))
	cfg := TierTargetConfig{
		WebDavUrl: f.url("/data/"), Prefix: prefix, TokenFile: tokenFile,
		DisableMacaroons: disableMacaroons, MaxSize: 1 << 30,
	}
	require.NoError(t, cfg.validate())
	b, err := newWebDAVTierBackend(cfg, fileTokenSource{path: cfg.TokenFile})
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func putString(t *testing.T, b TierBackend, key, data string) TierObjectInfo {
	t.Helper()
	info, err := b.Put(context.Background(), key, "application/octet-stream", int64(len(data)), strings.NewReader(data))
	require.NoError(t, err)
	return info
}

func readAll(t *testing.T, rc io.ReadCloser) string {
	t.Helper()
	defer rc.Close()
	data, err := io.ReadAll(rc)
	require.NoError(t, err)
	return string(data)
}

// TestWebDAVTierBackendContract runs the TierBackend contract against the
// fake door.
func TestWebDAVTierBackendContract(t *testing.T) {
	ctx := context.Background()
	f := newFakeDCache(t)
	b := newFakeDCacheBackend(t, f, "pelican/cache", true)

	// Listing a target nothing was written to is empty, not an error.
	require.NoError(t, b.List(ctx, func(string, int64, time.Time) error {
		t.Fatal("an empty target listed an object")
		return nil
	}))

	// Put creates the prefix and fan-out collections on demand.
	info := putString(t, b, "aa/bb/object-one", "hello, dCache")
	assert.Equal(t, int64(13), info.Size)
	assert.NotEmpty(t, info.ETag)
	assert.False(t, info.ModTime.IsZero())
	putString(t, b, "aa/bb/object-two", "second")
	putString(t, b, ".pelican-cache-id", "not-in-the-layout")
	// A sibling whose key sorts before the "a/..." keys, though its name
	// sorts after "a": '-' < '/'.
	putString(t, b, "a-b", "x")
	putString(t, b, "a/zz/first", "y")

	got, exists, err := b.Stat(ctx, "aa/bb/object-one")
	require.NoError(t, err)
	require.True(t, exists)
	assert.Equal(t, info.ETag, got.ETag, "Stat and Put must report the same entity tag")
	_, exists, err = b.Stat(ctx, "aa/bb/missing")
	require.NoError(t, err)
	assert.False(t, exists)

	// Ranged and pinned reads.
	rc, err := b.OpenRange(ctx, "aa/bb/object-one", 7, &info)
	require.NoError(t, err)
	assert.Equal(t, "dCache", readAll(t, rc))
	rc, err = b.OpenRange(ctx, "aa/bb/object-one", 0, nil)
	require.NoError(t, err)
	assert.Equal(t, "hello, dCache", readAll(t, rc))

	// Overwriting the object changes its entity tag, and a read pinned to
	// the recorded copy is refused.
	require.Eventually(t, func() bool {
		// The fake derives entity tags from the modification time, so
		// wait out the clock's granularity rather than assume it.
		return putString(t, b, "aa/bb/object-one", "HELLO, DCACHE").ETag != info.ETag
	}, 5*time.Second, time.Millisecond)
	_, err = b.OpenRange(ctx, "aa/bb/object-one", 0, &info)
	assert.ErrorIs(t, err, ErrTierObjectChanged)
	_, err = b.OpenRange(ctx, "aa/bb/object-one", 3, &info)
	assert.ErrorIs(t, err, ErrTierObjectChanged)

	// The listing is in ascending key order: the consistency sweep
	// merge-joins it.
	var keys []string
	require.NoError(t, b.List(ctx, func(key string, size int64, _ time.Time) error {
		keys = append(keys, key)
		return nil
	}))
	assert.Equal(t, []string{".pelican-cache-id", "a-b", "a/zz/first", "aa/bb/object-one", "aa/bb/object-two"}, keys)

	// A short body is an error, not a short object.  (Whatever the server
	// kept of it is removed on a best-effort basis; whether that wins the
	// race with the server noticing the aborted request is not something a
	// test can pin, and the consistency sweep removes any leftover.)
	_, err = b.Put(ctx, "aa/bb/short", "", 100, strings.NewReader("too short"))
	require.Error(t, err)

	// Delete is idempotent.
	require.NoError(t, b.Delete(ctx, "aa/bb/object-two"))
	require.NoError(t, b.Delete(ctx, "aa/bb/object-two"))
	_, exists, err = b.Stat(ctx, "aa/bb/object-two")
	require.NoError(t, err)
	assert.False(t, exists)

	// With macaroons disabled the target cannot redirect.
	_, ok := b.probeRedirect(ctx)
	assert.False(t, ok)
	issued, _, _ := f.stats()
	assert.Zero(t, issued, "a target with macaroons disabled must not ask for one")
}

func TestParseWebDAVTierTarget(t *testing.T) {
	parse := func(entry map[string]any) ([]TierTargetConfig, error) {
		server_utils.ResetTestState()
		t.Cleanup(server_utils.ResetTestState)
		require.NoError(t, param.Cache_TieringTargets.Set([]any{entry}))
		return ParseTierTargetsConfig()
	}

	targets, err := parse(map[string]any{
		"WebDavUrl": "https://dcache.example.org:2880/pnfs/example.org/data/",
		"Prefix":    "/pelican/",
		"TokenFile": "/etc/pelican/dcache.token",
		"MaxSize":   "1TB",
	})
	require.NoError(t, err)
	require.Len(t, targets, 1)
	assert.Equal(t, "https://dcache.example.org:2880/pnfs/example.org/data/pelican", targets[0].DisplayURL())
	assert.Equal(t, "https", targets[0].TransportScheme())
	assert.Empty(t, targets[0].Region, "S3 defaults do not apply to a WebDAV target")

	for name, tc := range map[string]struct {
		entry map[string]any
		want  string
	}{
		"WithBucket":       {map[string]any{"WebDavUrl": "https://d.example.org/data", "Bucket": "b", "MaxSize": "1GB"}, "object-store keys"},
		"NotHTTP":          {map[string]any{"WebDavUrl": "davs://d.example.org/data", "MaxSize": "1GB"}, "http or https"},
		"TokenInURL":       {map[string]any{"WebDavUrl": "https://d.example.org/data?authz=SECRET", "MaxSize": "1GB"}, "TokenFile"},
		"TokenFileOnS3":    {map[string]any{"ProviderURL": "mem://", "TokenFile": "/t", "MaxSize": "1GB"}, "WebDavUrl"},
		"MacaroonsOnS3":    {map[string]any{"ProviderURL": "mem://", "DisableMacaroons": true, "MaxSize": "1GB"}, "WebDavUrl"},
		"MissingMaxSize":   {map[string]any{"WebDavUrl": "https://d.example.org/data"}, "MaxSize"},
		"UserinfoInURL":    {map[string]any{"WebDavUrl": "https://u:SECRET@d.example.org/data", "MaxSize": "1GB"}, "TokenFile"},
		"QueryInWebDavUrl": {map[string]any{"WebDavUrl": "https://d.example.org/data?x=1", "MaxSize": "1GB"}, "query"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parse(tc.entry)
			require.ErrorContains(t, err, tc.want)
			assert.NotContains(t, err.Error(), "SECRET")
		})
	}
}

// TestWebDAVTierTarget registers a WebDAV target through the same path the
// cache uses, and checks the identity object and the startup probe.
func TestWebDAVTierTarget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := newFakeDCache(t)
	target := registerFakeDCacheTarget(t, ctx, f)
	assert.True(t, target.canRedirect)
	assert.Equal(t, "http", target.redirectScheme)
	assert.Equal(t, f.srv.Listener.Addr().String(), target.redirectHost)

	// The identity object landed under the prefix, through WebDAV.
	rc, err := target.backend.OpenRange(ctx, tierIdentityKey, 0, nil)
	require.NoError(t, err)
	id := readAll(t, rc)
	resp, err := doWithToken(http.MethodGet, f.url("/data/cache/"+tierIdentityKey))
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	assert.Equal(t, id, string(body))

	// The liveness probe round-trips through it too.
	require.NoError(t, target.probe(ctx))
}

// registerFakeDCacheTarget registers a target on f, with the prefix "cache",
// the way the cache registers its configured targets.
func registerFakeDCacheTarget(t *testing.T, ctx context.Context, f *fakeDCache) *tierTarget {
	t.Helper()
	InitIssuerKeyForTests(t)
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
	t.Cleanup(func() { _ = target.Close() })
	return target
}

func doWithToken(method, target string) (*http.Response, error) {
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+fakeDCacheToken)
	return http.DefaultClient.Do(req)
}

// withoutSizeFor makes PROPFIND report no getcontentlength for members named
// name, as dCache does for a file that is still being written.
func withoutSizeFor(name string) func(http.Handler) http.Handler {
	member := regexp.MustCompile(`(?s)<D:response>.*?</D:response>`)
	size := regexp.MustCompile(`<D:getcontentlength>[^<]*</D:getcontentlength>`)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "PROPFIND" {
				next.ServeHTTP(w, r)
				return
			}
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)
			body := member.ReplaceAllStringFunc(rec.Body.String(), func(resp string) string {
				if strings.Contains(resp, "/"+name+"</D:href>") {
					return size.ReplaceAllString(resp, "")
				}
				return resp
			})
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			w.Header().Del("Content-Length")
			w.WriteHeader(rec.Code)
			_, _ = io.WriteString(w, body)
		})
	}
}

// refusingIfMatch fails every conditional GET, as a server would whose
// If-Match compares a different form of the entity tag than HEAD reports.
func refusingIfMatch(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.Header.Get("If-Match") != "" {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// parsingFormBodies consumes the body of a PUT labelled as a form, as dCache's
// door does: Jetty parses it as form parameters when the door looks for its
// authz parameter, and the upload that follows finds nothing left to write.
func parsingFormBodies(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			if mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mediaType == "application/x-www-form-urlencoded" {
				_, _ = io.Copy(io.Discard, r.Body)
				http.Error(w, "Internal problem: Problem with transferred data: insufficient data written",
					http.StatusInternalServerError)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// TestWebDAVUploadOfFormTypedObject: an object whose recorded type is a form
// type still uploads.  Sent with its own type, dCache consumes the body as a
// form and stores nothing (seen against dCache 11.2.8), so the object could
// never be tiered.
func TestWebDAVUploadOfFormTypedObject(t *testing.T) {
	f := newFakeDCacheWrapping(t, parsingFormBodies)
	b := newFakeDCacheBackend(t, f, "cache", true)
	for _, contentType := range []string{
		"application/x-www-form-urlencoded",
		"Application/X-WWW-Form-Urlencoded; charset=utf-8",
		"multipart/form-data; boundary=x",
	} {
		data := "a=1&b=2 is just bytes to the cache"
		info, err := b.Put(context.Background(), "aa/bb/form", contentType, int64(len(data)), strings.NewReader(data))
		require.NoError(t, err, contentType)
		assert.Equal(t, int64(len(data)), info.Size)
		rc, err := b.OpenRange(context.Background(), "aa/bb/form", 0, &info)
		require.NoError(t, err)
		assert.Equal(t, data, readAll(t, rc))
	}
	assert.Equal(t, "text/plain; charset=utf-8", uploadContentType("text/plain; charset=utf-8"))
	assert.Equal(t, "", uploadContentType(""))
}

// TestWebDAVListToleratesSizelessMembers: dCache lists a file that is still
// being written with no size.  The walk must go on -- a failed listing skips
// the whole consistency sweep -- and report the size as unknown.
func TestWebDAVListToleratesSizelessMembers(t *testing.T) {
	ctx := context.Background()
	f := newFakeDCacheWrapping(t, withoutSizeFor("in-flight"))
	b := newFakeDCacheBackend(t, f, "cache", true)
	putString(t, b, "aa/bb/done", "complete")
	putString(t, b, "aa/bb/in-flight", "being written")

	sizes := map[string]int64{}
	require.NoError(t, b.List(ctx, func(key string, size int64, _ time.Time) error {
		sizes[key] = size
		return nil
	}))
	assert.Equal(t, map[string]int64{"aa/bb/done": 8, "aa/bb/in-flight": -1}, sizes)
}

// TestWebDAVSpuriousPreconditionFailure: a 412 for an object whose HEAD still
// reports the recorded copy fails the read but is not reported as a change,
// which would make the cache drop a good object.
func TestWebDAVSpuriousPreconditionFailure(t *testing.T) {
	ctx := context.Background()
	f := newFakeDCacheWrapping(t, refusingIfMatch)
	b := newFakeDCacheBackend(t, f, "cache", true)
	info := putString(t, b, "aa/bb/object", "still the same")

	_, err := b.OpenRange(ctx, "aa/bb/object", 0, &info)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrTierObjectChanged)

	// A copy that really changed is still reported as one.
	stale := info
	stale.ETag = `"not-the-current-tag"`
	_, err = b.OpenRange(ctx, "aa/bb/object", 0, &stale)
	assert.ErrorIs(t, err, ErrTierObjectChanged)
}

func TestFileTokenSourceRefusesAnEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(path, []byte("\n"), 0600))
	_, err := fileTokenSource{path: path}.Token(context.Background())
	assert.ErrorContains(t, err, "empty")

	require.NoError(t, os.WriteFile(path, []byte(" tok \n"), 0600))
	token, err := fileTokenSource{path: path}.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "tok", token)

	token, err = fileTokenSource{}.Token(context.Background())
	require.NoError(t, err)
	assert.Empty(t, token, "no file configured means no token")
}

// TestWebDAVProxiedReadEndsWithItsReader checks that a proxied read stalled
// on a WebDAV target ends when the request it serves ends, as reads from
// object stores do (see tierObjectStream.setReadContext), rather than when
// the server next sends something: the backend's requests must carry the
// context they are given all the way into the body.
func TestWebDAVProxiedReadEndsWithItsReader(t *testing.T) {
	const size = 4096
	released := make(chan struct{})
	release := sync.OnceFunc(func() { close(released) })
	f := newFakeDCacheWrapping(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				next.ServeHTTP(w, r)
				return
			}
			// Answer with the headers and the first half of the body,
			// then stall until the client goes.
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			w.WriteHeader(rec.Code)
			body := rec.Body.Bytes()
			_, _ = w.Write(body[:len(body)/2])
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
			case <-released:
			}
		})
	})
	// Registered after the server's own cleanup, so it runs first: a
	// handler the test left stalled must not hold up the server's close.
	t.Cleanup(release)
	b := newFakeDCacheBackend(t, f, "pelican", true)
	target := &tierTarget{backend: b}
	hash := InstanceHash("abcd000000000000000000000000000000000000000000000000000000000001")
	data := bytes.Repeat([]byte("0123456789abcdef"), size/16)
	info, err := target.uploadObject(context.Background(), hash, "", size, bytes.NewReader(data))
	require.NoError(t, err)

	// The stream outlives the request it serves, as one opened for an HTTP
	// client does; the request's context is attached for reading.
	stream := newTierObjectStream(context.Background(), target, hash, size)
	stream.expect = &info
	reqCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream.setReadContext(reqCtx)
	defer stream.Close()

	got := make([]byte, size)
	_, err = io.ReadFull(stream, got[:size/2])
	require.NoError(t, err)
	assert.Equal(t, data[:size/2], got[:size/2])

	readErr := make(chan error, 1)
	go func() {
		_, err := stream.Read(got[size/2:])
		readErr <- err
	}()
	cancel()
	select {
	case err := <-readErr:
		assert.ErrorIs(t, err, context.Canceled, "the read should end with its request, not be reopened")
	case <-time.After(10 * time.Second):
		// Let the read finish before the stream is closed under it.
		release()
		<-readErr
		t.Fatal("a read stalled on the target did not end when its request did")
	}
}
