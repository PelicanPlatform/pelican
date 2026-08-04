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

// End-to-end tests that drive real HTTP requests through the registered Gin
// engine into a live pstore.
//
// Everything here goes through InitializeHandlers and RegisterHandlers -- the
// same two calls the launcher makes -- so the middleware chain, the WebDAV
// handler, the afero adapter, the storage-prefix join, and the store all
// participate. The bugs these cover were all invisible to tests that called
// the filesystem directly: they lived in the seam between the handler and the
// backend.

package origin_serve

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pstore"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

// servedOrigin is a running origin: real exports, a real store, and a Gin
// engine with the routes RegisterHandlers produces.
type servedOrigin struct {
	engine *gin.Engine
	// key signs the test tokens; the auth config is told to trust it for each
	// issuer the exports name.
	key jwk.Key
}

// backendFor returns the pstore backend serving a federation prefix.
func (o *servedOrigin) backendFor(t *testing.T, federationPrefix string) *pstoreBackend {
	t.Helper()
	be, ok := backends[federationPrefix].(*pstoreBackend)
	require.True(t, ok, "export %s is not served by a pstore backend", federationPrefix)
	return be
}

// store returns the store the exports share.
func (o *servedOrigin) store(t *testing.T, federationPrefix string) *pstore.Store {
	return o.backendFor(t, federationPrefix).store
}

// token mints a bearer token for one of the exports' issuers.
func (o *servedOrigin) token(t *testing.T, issuer, scopes string) string {
	t.Helper()
	return createTestToken(t, o.key, issuer, "tester", []string{"testers"}, scopes)
}

// newServedOrigin brings up an origin over a pstore, through the same calls
// the launcher makes.
//
// storageDirs, when non-nil, is passed to Origin.PStoreStorageDirs so a test
// can cap the store's capacity.
func newServedOrigin(t *testing.T, exports []server_utils.OriginExport, storageDirs []any) *servedOrigin {
	t.Helper()

	local_cache.InitIssuerKeyForTests(t)
	ResetPStoreState()
	ResetHandlers()
	t.Cleanup(func() {
		ResetHandlers()
		ResetPStoreState()
	})

	require.NoError(t, param.Origin_StorageType.Set(string(server_structs.OriginStoragePStore)))
	t.Cleanup(func() { _ = param.Origin_StorageType.Set("posix") })

	storeDir := t.TempDir()
	require.NoError(t, param.Origin_PStoreLocation.Set(storeDir))
	if storageDirs != nil {
		require.NoError(t, param.Origin_PStoreStorageDirs.Set(storageDirs))
		t.Cleanup(func() { _ = param.Origin_PStoreStorageDirs.Set(nil) })
	}

	baseCtx, cancel := context.WithCancel(context.Background())
	egrp, egrpCtx := errgroup.WithContext(baseCtx)
	ctx := context.WithValue(egrpCtx, config.EgrpKey, egrp)
	// The store's background workers -- and the goroutine that closes it --
	// only stop when this context is cancelled, so tear them down before the
	// temp directory goes away.
	t.Cleanup(func() {
		cancel()
		_ = egrp.Wait()
	})

	require.NoError(t, InitializeHandlers(ctx, exports))
	require.NoError(t, InitAuthConfig(ctx, egrp, exports))

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	require.NoError(t, RegisterHandlers(engine, false))

	o := &servedOrigin{engine: engine, key: generateTestKey(t)}

	// Trust the signing key for every issuer the exports name, rather than
	// standing up a JWKS endpoint per issuer. Everything downstream of the
	// signature check -- issuer trust, audience, scope parsing, and the
	// per-export capability filtering in getAcls -- still runs for real.
	pub, err := o.key.PublicKey()
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, "test-key"))
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pub))

	ac := GetAuthConfig()
	require.NotNil(t, ac)
	for _, export := range exports {
		for _, issuer := range export.IssuerUrls {
			ac.issuerKeys.Set(issuer, authConfigItem{set: set}, ttlcache.DefaultTTL)
		}
	}

	return o
}

// do runs a request against the engine.
func (o *servedOrigin) do(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	o.engine.ServeHTTP(rec, req)
	return rec
}

// put issues an authenticated PUT with a known length.
func (o *servedOrigin) put(t *testing.T, token, url, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, url, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return o.do(req)
}

// writeObject seeds an object through the export's filesystem.
func writeObject(t *testing.T, backend *pstoreBackend, name, body string) {
	t.Helper()
	f, err := backend.FileSystem().OpenFile(context.Background(), name,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	require.NoError(t, err)
	_, err = f.Write([]byte(body))
	require.NoError(t, err)
	require.NoError(t, f.Close())
}

// unsizedBody hides a reader's type so httptest.NewRequest reports an unknown
// Content-Length, which is what a chunked-encoding PUT gives the handler --
// and the only way past the up-front capacity check into the write path.
type unsizedBody struct{ io.Reader }

// failingReader yields a prefix and then fails, standing in for a client that
// disconnects partway through an upload.
type failingReader struct {
	prefix []byte
	off    int
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.off < len(r.prefix) {
		n := copy(p, r.prefix[r.off:])
		r.off += n
		return n, nil
	}
	return 0, errors.New("simulated client disconnect")
}

// ---------------------------------------------------------------------------
// Cross-export destruction via the Destination header
// ---------------------------------------------------------------------------

// twoTenantExports is the shape the cross-tenant attack needs: two exports on
// one store, in separate storage subtrees, trusting separate issuers -- so a
// token good for one grants nothing on the other.
func twoTenantExports() []server_utils.OriginExport {
	return []server_utils.OriginExport{
		{
			FederationPrefix: "/pubA",
			StoragePrefix:    "/tenantA",
			IssuerUrls:       []string{"https://issuer-a.example.com"},
			Capabilities: server_structs.Capabilities{
				Reads: true, Writes: true, Copies: true,
			},
		},
		{
			FederationPrefix: "/privB",
			StoragePrefix:    "/tenantB",
			IssuerUrls:       []string{"https://issuer-b.example.com"},
			Capabilities: server_structs.Capabilities{
				Reads: true, Writes: true,
			},
		},
	}
}

// TestCrossExportMoveWithDotDotDestinationIsRefused is the most important test
// in this change.
//
// golang.org/x/net/webdav cleans the request path but not the Destination
// header: handleCopyMove strips its own prefix with a bare TrimPrefix and
// hands what is left to Rename and -- because RFC 4918 §9.9.3 makes MOVE
// delete an existing destination first -- RemoveAll. With pstore, whose
// containment was nothing more than path.Join(storagePrefix, name), a client
// holding storage.modify on one export could aim a MOVE at another export's
// subtree and get back 204 No Content with the whole subtree deleted.
func TestCrossExportMoveWithDotDotDestinationIsRefused(t *testing.T) {
	o := newServedOrigin(t, twoTenantExports(), nil)

	tenantA := o.backendFor(t, "/pubA")
	tenantB := o.backendFor(t, "/privB")
	writeObject(t, tenantA, "/mine.txt", "mine")
	writeObject(t, tenantB, "/keep.txt", "tenant B data")
	writeObject(t, tenantB, "/dir/deep.txt", "tenant B nested data")

	// A token that authorizes everything the attacker's own export allows.
	tok := o.token(t, "https://issuer-a.example.com",
		"storage.read:/ storage.create:/ storage.modify:/")

	req := httptest.NewRequest("MOVE", "/pubA/mine.txt", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	// path.Join("/tenantA", "/../../tenantB") == "/tenantB".
	req.Header.Set("Destination", "/pubA/../../tenantB")
	req.Header.Set("Overwrite", "T")
	rec := o.do(req)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"a destination outside the export must be refused, got %d: %s", rec.Code, rec.Body.String())

	// The point of the whole test: tenant B still has its data.
	store := o.store(t, "/privB")
	keep, err := store.ReadAll("/tenantB/keep.txt")
	require.NoError(t, err, "tenant B's object must survive")
	assert.Equal(t, "tenant B data", string(keep))
	deep, err := store.ReadAll("/tenantB/dir/deep.txt")
	require.NoError(t, err, "tenant B's subtree must survive")
	assert.Equal(t, "tenant B nested data", string(deep))

	// And the source is untouched, since the move never happened.
	mine, err := store.ReadAll("/tenantA/mine.txt")
	require.NoError(t, err)
	assert.Equal(t, "mine", string(mine))
}

// TestCrossExportCopyWithDotDotDestinationIsRefused covers the same header on
// COPY, whose Overwrite defaults to true (`!= "F"`), so the destructive form
// needs no header at all.
func TestCrossExportCopyWithDotDotDestinationIsRefused(t *testing.T) {
	o := newServedOrigin(t, twoTenantExports(), nil)

	writeObject(t, o.backendFor(t, "/pubA"), "/mine.txt", "mine")
	writeObject(t, o.backendFor(t, "/privB"), "/keep.txt", "tenant B data")

	tok := o.token(t, "https://issuer-a.example.com",
		"storage.read:/ storage.create:/ storage.modify:/")

	req := httptest.NewRequest("COPY", "/pubA/mine.txt", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Destination", "/pubA/../../tenantB/keep.txt")
	rec := o.do(req)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"got %d: %s", rec.Code, rec.Body.String())

	keep, err := o.store(t, "/privB").ReadAll("/tenantB/keep.txt")
	require.NoError(t, err)
	assert.Equal(t, "tenant B data", string(keep),
		"tenant B's object must not have been overwritten")
}

// TestAferoFileSystemConfinesEveryOperation pins the sink itself, independent
// of any handler: whatever reaches the WebDAV filesystem with a path that
// leaves the export is refused, and refused as a permission error so the
// status mapping reports 403 rather than 500.
func TestAferoFileSystemConfinesEveryOperation(t *testing.T) {
	backend := newPStoreTestBackend(t, "/tenantA")
	fs := backend.FileSystem()
	ctx := context.Background()

	// Seed a neighbouring subtree directly in the store.
	require.NoError(t, backend.store.MkdirAll("/tenantB"))
	w, err := backend.store.Create("/tenantB/keep.txt")
	require.NoError(t, err)
	_, err = w.Write([]byte("tenant B data"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	escapes := "/../../tenantB"

	t.Run("RemoveAll", func(t *testing.T) {
		err := fs.RemoveAll(ctx, escapes)
		require.Error(t, err)
		assert.ErrorIs(t, err, os.ErrPermission)
		assert.Equal(t, http.StatusForbidden, statusForBackendError(err, false))
	})
	t.Run("Rename", func(t *testing.T) {
		assert.ErrorIs(t, fs.Rename(ctx, "/a.txt", escapes), os.ErrPermission)
		assert.ErrorIs(t, fs.Rename(ctx, escapes, "/a.txt"), os.ErrPermission)
	})
	t.Run("Stat", func(t *testing.T) {
		_, err := fs.Stat(ctx, escapes+"/keep.txt")
		assert.ErrorIs(t, err, os.ErrPermission)
	})
	t.Run("OpenFile", func(t *testing.T) {
		_, err := fs.OpenFile(ctx, escapes+"/keep.txt", os.O_RDONLY, 0)
		assert.ErrorIs(t, err, os.ErrPermission)
	})
	t.Run("Mkdir", func(t *testing.T) {
		assert.ErrorIs(t, fs.Mkdir(ctx, escapes+"/new", 0755), os.ErrPermission)
	})

	// Nothing above touched the neighbour.
	body, err := backend.store.ReadAll("/tenantB/keep.txt")
	require.NoError(t, err)
	assert.Equal(t, "tenant B data", string(body))

	// A path that stays inside is unaffected.
	inside, err := confineToPrefix("/tenantA", "/sub/../ok.txt")
	require.NoError(t, err)
	assert.Equal(t, "/tenantA/ok.txt", inside)
}

// ---------------------------------------------------------------------------
// The destination is authorized in its own right
// ---------------------------------------------------------------------------

// TestReadOnlyExportIsNotWritableViaMoveDestination covers the authorization
// half of the same bug: authMiddleware only ever checked the request path, so
// the Writes capability of the export the data would land in was never
// consulted.
func TestReadOnlyExportIsNotWritableViaMoveDestination(t *testing.T) {
	issuer := "https://issuer.example.com"
	o := newServedOrigin(t, []server_utils.OriginExport{
		{
			FederationPrefix: "/rw",
			StoragePrefix:    "/tenantRW",
			IssuerUrls:       []string{issuer},
			Capabilities:     server_structs.Capabilities{Reads: true, Writes: true},
		},
		{
			// Same issuer, same token -- only the capability differs.
			FederationPrefix: "/ro",
			StoragePrefix:    "/tenantRO",
			IssuerUrls:       []string{issuer},
			Capabilities:     server_structs.Capabilities{Reads: true, Writes: false},
		},
	}, nil)

	writeObject(t, o.backendFor(t, "/rw"), "/mine.txt", "mine")

	tok := o.token(t, issuer, "storage.read:/ storage.create:/ storage.modify:/")

	req := httptest.NewRequest("MOVE", "/rw/mine.txt", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Destination", "/ro/stolen.txt")
	req.Header.Set("Overwrite", "T")
	rec := o.do(req)

	assert.Equal(t, http.StatusForbidden, rec.Code, "got %d: %s", rec.Code, rec.Body.String())

	_, err := o.store(t, "/ro").Stat("/tenantRO/stolen.txt")
	assert.Error(t, err, "nothing may be written into a read-only export")

	// The source survives: a refused MOVE must not consume it.
	body, err := o.store(t, "/rw").ReadAll("/tenantRW/mine.txt")
	require.NoError(t, err)
	assert.Equal(t, "mine", string(body))
}

// TestMoveDestinationOutsideTokenScopeIsRefused checks the finer case: the
// destination is inside the same export, so confinement alone would allow it,
// but the token's scope does not reach it.
func TestMoveDestinationOutsideTokenScopeIsRefused(t *testing.T) {
	issuer := "https://issuer.example.com"
	o := newServedOrigin(t, []server_utils.OriginExport{{
		FederationPrefix: "/data",
		StoragePrefix:    "/tenant",
		IssuerUrls:       []string{issuer},
		Capabilities:     server_structs.Capabilities{Reads: true, Writes: true},
	}}, nil)

	writeObject(t, o.backendFor(t, "/data"), "/sub/mine.txt", "mine")

	// Authorized for /data/sub only.
	tok := o.token(t, issuer, "storage.read:/sub storage.create:/sub storage.modify:/sub")

	t.Run("outside the scope", func(t *testing.T) {
		req := httptest.NewRequest("MOVE", "/data/sub/mine.txt", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Destination", "/data/elsewhere.txt")
		rec := o.do(req)

		assert.Equal(t, http.StatusForbidden, rec.Code, "got %d: %s", rec.Code, rec.Body.String())
		_, err := o.store(t, "/data").Stat("/tenant/elsewhere.txt")
		assert.Error(t, err)
	})

	t.Run("inside the scope", func(t *testing.T) {
		req := httptest.NewRequest("MOVE", "/data/sub/mine.txt", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Destination", "/data/sub/renamed.txt")
		rec := o.do(req)

		require.Less(t, rec.Code, 300, "an authorized move must still work: %s", rec.Body.String())
		body, err := o.store(t, "/data").ReadAll("/tenant/sub/renamed.txt")
		require.NoError(t, err)
		assert.Equal(t, "mine", string(body))
	})
}

// ---------------------------------------------------------------------------
// A logical StoragePrefix is not a host path
// ---------------------------------------------------------------------------

// TestPStoreGetDoesNotListTheHostFilesystem covers the confusion between an
// export's logical StoragePrefix and a path on this machine.
//
// handleGetWithETag used to call os.OpenRoot(storagePrefix) unconditionally.
// For pstore that prefix is a namespace path inside the store; "/" is the
// natural choice for a single-export origin, os.OpenRoot("/") succeeds, and a
// browser GET was answered with an HTML index of the origin host's root
// directory -- plus an ETag and Last-Modified derived from host files, which
// honored If-None-Match and became an existence-and-mtime oracle.
func TestPStoreGetDoesNotListTheHostFilesystem(t *testing.T) {
	// A directory that exists on this host and also names the export's
	// logical storage prefix, which is what makes the confusion observable.
	hostDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(hostDir, "host-only-secret.txt"),
		[]byte("this file is on the origin host, not in the store"), 0o600))

	issuer := "https://issuer.example.com"
	o := newServedOrigin(t, []server_utils.OriginExport{{
		FederationPrefix: "/pub",
		StoragePrefix:    hostDir,
		IssuerUrls:       []string{issuer},
		Capabilities:     server_structs.Capabilities{Reads: true, Writes: true, PublicReads: true},
	}}, nil)

	// Give the export a directory of its own inside the store, so the request
	// resolves to something real in the namespace rather than 404ing for an
	// unrelated reason.
	require.NoError(t, o.store(t, "/pub").MkdirAll(hostDir))
	writeObject(t, o.backendFor(t, "/pub"), "/in-the-store.txt", "store data")

	req := httptest.NewRequest(http.MethodGet, "/pub/", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rec := o.do(req)

	body := rec.Body.String()
	assert.NotContains(t, body, "host-only-secret.txt",
		"the response must never enumerate the origin host's filesystem")
	assert.NotContains(t, body, "Index of",
		"the host-filesystem directory listing must not run for a pstore export")

	// The same confusion made a GET for a host file answerable at all.
	req = httptest.NewRequest(http.MethodGet, "/pub/host-only-secret.txt", nil)
	rec = o.do(req)
	assert.Equal(t, http.StatusNotFound, rec.Code,
		"a file that exists only on the host must not be visible through the export")
	assert.Empty(t, rec.Header().Get("ETag"),
		"no host-derived validator may leak")
}

// ---------------------------------------------------------------------------
// A failed PUT must not commit
// ---------------------------------------------------------------------------

// TestPutWithFailingBodyKeepsThePreviousObject is the silent-data-loss case.
//
// webdav.handlePut calls f.Close() before it looks at the error from io.Copy,
// and a pstore Close installs whatever arrived. A client that died partway
// through an overwrite therefore replaced a complete object with a fragment
// and got a 405 -- by which time the original was gone.
func TestPutWithFailingBodyKeepsThePreviousObject(t *testing.T) {
	issuer := "https://issuer.example.com"
	o := newServedOrigin(t, []server_utils.OriginExport{{
		FederationPrefix: "/data",
		StoragePrefix:    "/tenant",
		IssuerUrls:       []string{issuer},
		Capabilities:     server_structs.Capabilities{Reads: true, Writes: true},
	}}, nil)

	tok := o.token(t, issuer, "storage.read:/ storage.create:/ storage.modify:/")

	const original = "THE COMPLETE ORIGINAL OBJECT"
	rec := o.put(t, tok, "/data/obj.txt", original, nil)
	require.Less(t, rec.Code, 300, "seeding PUT failed: %s", rec.Body.String())

	// Now overwrite it with a body that dies after seven bytes.
	req := httptest.NewRequest(http.MethodPut, "/data/obj.txt",
		unsizedBody{&failingReader{prefix: []byte("PARTIAL")}})
	req.Header.Set("Authorization", "Bearer "+tok)
	rec = o.do(req)

	assert.GreaterOrEqual(t, rec.Code, 400,
		"a PUT whose body failed must not be reported as success")

	body, err := o.store(t, "/data").ReadAll("/tenant/obj.txt")
	require.NoError(t, err, "the object must still exist")
	assert.Equal(t, original, string(body),
		"a failed PUT must leave the previous version's bytes intact")
}

// TestPstoreFileAbortsRatherThanCommitting checks the backend half on its own,
// so the guarantee does not depend on the handler wiring.
func TestPstoreFileAbortsRatherThanCommitting(t *testing.T) {
	backend := newPStoreTestBackend(t, "/")
	fs := backend.FileSystem()
	ctx := context.Background()

	f, err := fs.OpenFile(ctx, "/obj.txt", os.O_WRONLY|os.O_CREATE, 0644)
	require.NoError(t, err)
	_, err = f.Write([]byte("v1 complete"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// A second write that is told, mid-flight, that its data is incomplete.
	// The guard is what the PUT handler plants in the context, and what the
	// filesystem registers the backend file with, so going through it
	// exercises the real wiring rather than reaching for the raw handle.
	guard := &writeGuard{}
	f2, err := fs.OpenFile(contextWithWriteGuard(ctx, guard), "/obj.txt",
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	require.NoError(t, err)
	_, err = f2.Write([]byte("PARTIAL"))
	require.NoError(t, err)

	guard.fail(errors.New("client went away"))
	require.Error(t, guard.failed())

	require.Error(t, f2.Close(), "Close must report the failure rather than pretend to commit")

	body, err := backend.store.ReadAll("/obj.txt")
	require.NoError(t, err)
	assert.Equal(t, "v1 complete", string(body))
}

// ---------------------------------------------------------------------------
// Over-capacity PUT reports 507, not 405
// ---------------------------------------------------------------------------

// TestOverCapacityPutReturns507 pins the mapping to what a client actually
// sees.
//
// The ENOSPC-to-507 entry in MapToHTTPStatus had no caller on any request
// path, so every over-capacity write came out of golang.org/x/net/webdav as
// 405 Method Not Allowed -- which tells a client the method is unsupported and
// that retrying is pointless, the opposite of the truth.
func TestOverCapacityPutReturns507(t *testing.T) {
	issuer := "https://issuer.example.com"
	capped := t.TempDir()
	o := newServedOrigin(t, []server_utils.OriginExport{{
		FederationPrefix: "/data",
		StoragePrefix:    "/tenant",
		IssuerUrls:       []string{issuer},
		Capabilities:     server_structs.Capabilities{Reads: true, Writes: true},
	}}, []any{
		// Shaped as viper delivers a YAML list of objects.
		map[string]any{"Path": capped, "MaxSize": "256KB"},
	})

	tok := o.token(t, issuer, "storage.read:/ storage.create:/ storage.modify:/")

	// Ask for far more than the store can hold, rather than probing for the
	// exact threshold: the placement granularity is an implementation detail.
	oversized := strings.Repeat("x", 8<<20)

	t.Run("declared length is refused up front", func(t *testing.T) {
		rec := o.put(t, tok, "/data/big.bin", oversized, nil)
		assert.Equal(t, http.StatusInsufficientStorage, rec.Code,
			"got %d: %s", rec.Code, rec.Body.String())
	})

	t.Run("unknown length is refused by the write path", func(t *testing.T) {
		// No Content-Length, so the up-front check cannot help and the error
		// has to survive the WebDAV handler's own 405.
		req := httptest.NewRequest(http.MethodPut, "/data/chunked.bin",
			unsizedBody{strings.NewReader(oversized)})
		req.Header.Set("Authorization", "Bearer "+tok)
		require.EqualValues(t, -1, req.ContentLength, "the test needs an unknown length")

		rec := o.do(req)
		assert.Equal(t, http.StatusInsufficientStorage, rec.Code,
			"an out-of-space write must report 507, not the WebDAV handler's 405; got %d: %s",
			rec.Code, rec.Body.String())
	})

	t.Run("the object is not left behind", func(t *testing.T) {
		_, err := o.store(t, "/data").Stat("/tenant/chunked.bin")
		assert.Error(t, err)
	})
}

// TestStatusForBackendError covers the mapping directly, including the cases
// no client-visible path exercises today.
func TestStatusForBackendError(t *testing.T) {
	assert.Equal(t, http.StatusInsufficientStorage,
		statusForBackendError(&os.PathError{Op: "write", Path: "/x", Err: pstore.ErrNoSpace}, false))
	assert.Equal(t, http.StatusConflict,
		statusForBackendError(errors.Wrap(pstore.ErrDraining, "close"), false))
	assert.Equal(t, http.StatusPreconditionFailed,
		statusForBackendError(&os.PathError{Op: "close", Path: "/x", Err: pstore.ErrPreconditionFailed}, false))
	assert.Equal(t, http.StatusPreconditionFailed,
		statusForBackendError(&os.PathError{Op: "close", Path: "/x", Err: pstore.ErrExist}, true),
		"ErrExist is a failed precondition only when the request carried one")
	assert.Equal(t, 0,
		statusForBackendError(&os.PathError{Op: "close", Path: "/x", Err: pstore.ErrExist}, false),
		"and an ordinary conflict is left to the WebDAV handler")
	assert.Equal(t, http.StatusForbidden,
		statusForBackendError(&os.PathError{Op: "open", Path: "/x", Err: os.ErrPermission}, false))
	assert.Equal(t, 0, statusForBackendError(nil, false))
	assert.Equal(t, 0, statusForBackendError(errors.New("something unrecognized"), false),
		"an unrecognized error must not be given a made-up status")
}

// ---------------------------------------------------------------------------
// 6 & 7. Conditional writes
// ---------------------------------------------------------------------------

// TestConcurrentCreateOnlyPutsElectOneWinner is the compare-and-swap
// guarantee.
//
// checkPutPreconditions is a stat followed by a write, so on its own two
// "If-None-Match: *" PUTs to the same path both observe an absent object and
// both commit -- and the store's own RequireAbsent, which would have caught
// it, had no caller anywhere in the repo. The condition is now carried into
// the transaction that installs the new version.
func TestConcurrentCreateOnlyPutsElectOneWinner(t *testing.T) {
	issuer := "https://issuer.example.com"
	o := newServedOrigin(t, []server_utils.OriginExport{{
		FederationPrefix: "/data",
		StoragePrefix:    "/tenant",
		IssuerUrls:       []string{issuer},
		Capabilities:     server_structs.Capabilities{Reads: true, Writes: true},
	}}, nil)

	tok := o.token(t, issuer, "storage.read:/ storage.create:/ storage.modify:/")

	const racers = 4
	start := make(chan struct{})
	codes := make([]int, racers)
	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rec := o.put(t, tok, "/data/create-only.txt",
				fmt.Sprintf("written by racer %d", i),
				map[string]string{"If-None-Match": "*"})
			codes[i] = rec.Code
		}()
	}
	close(start)
	wg.Wait()

	created := 0
	for _, code := range codes {
		switch {
		case code >= 200 && code < 300:
			created++
		case code == http.StatusPreconditionFailed:
			// Refused, either by the early check or by the commit.
		case code == webdavStatusLocked:
			// golang.org/x/net/webdav takes an exclusive lock for the
			// duration of a PUT, so a request that overlaps the winner
			// exactly is turned away before it ever reaches the
			// precondition. That is still a refusal, and still leaves
			// exactly one writer.
		default:
			t.Errorf("unexpected status %d from a create-only PUT (all: %v)", code, codes)
		}
	}
	assert.Equal(t, 1, created, "exactly one create-only PUT may succeed: %v", codes)

	// And one of them is what is actually stored.
	body, err := o.store(t, "/data").ReadAll("/tenant/create-only.txt")
	require.NoError(t, err)
	assert.Contains(t, string(body), "written by racer")
}

// webdavStatusLocked is golang.org/x/net/webdav's StatusLocked (RFC 4918
// §11.3), which the package exports but net/http does not define.
const webdavStatusLocked = 423

// TestConcurrentConditionalWritesElectOneWinner is the same race one layer
// down, where the WebDAV lock system is not there to serialize it -- so the
// store's own commit-time check is the only thing standing between the two
// writers.
//
// Before this change WriteHandle.RequireAbsent had no caller anywhere in the
// repo, and webdav.handlePut opens with O_RDWR|O_CREATE|O_TRUNC (no O_EXCL),
// so nothing reached it: both writers committed and the create-only guarantee
// was simply not delivered.
func TestConcurrentConditionalWritesElectOneWinner(t *testing.T) {
	backend := newPStoreTestBackend(t, "/tenant")
	fs := backend.FileSystem()
	// The export's own subtree exists before the race, so the only thing the
	// racers contend for is the object itself.
	require.NoError(t, backend.store.MkdirAll("/tenant"))
	condCtx := contextWithWriteCondition(context.Background(), writeCondition{requireAbsent: true})

	const racers = 4
	start := make(chan struct{})
	errs := make([]error, racers)
	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, err := fs.OpenFile(condCtx, "/create-only.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				errs[i] = err
				return
			}
			if _, err := f.Write([]byte(fmt.Sprintf("racer %d", i))); err != nil {
				errs[i] = err
				_ = f.Close()
				return
			}
			<-start
			errs[i] = f.Close()
		}()
	}
	close(start)
	wg.Wait()

	won := 0
	for i, err := range errs {
		if err == nil {
			won++
			continue
		}
		// A loser either finds the winner's entry (ErrExist) or is aborted by
		// the index's serializable isolation before it can (ErrConflict).
		// Either way it did not create the object, and either way the origin
		// must give the client a status that says so rather than a 500.
		assert.True(t,
			errors.Is(err, pstore.ErrExist) || errors.Is(err, pstore.ErrConflict),
			"racer %d lost with an unexpected error: %v", i, err)
		status := statusForBackendError(err, true)
		assert.Contains(t, []int{http.StatusPreconditionFailed, http.StatusConflict}, status,
			"racer %d's failure must map to a 4xx a client can act on, got %d (%v)", i, status, err)
	}
	assert.Equal(t, 1, won, "exactly one conditional create may commit; errors: %v", errs)

	// Whatever happened, exactly one version is installed and it is complete.
	body, err := backend.store.ReadAll("/tenant/create-only.txt")
	require.NoError(t, err)
	assert.Regexp(t, `^racer \d$`, string(body))
}

// TestConditionalPutEnforcedAtCommit checks the enforcement point rather than
// the race: the object is changed out from under the request after the early
// check has already passed, which is exactly what the early check cannot see.
func TestConditionalPutEnforcedAtCommit(t *testing.T) {
	backend := newPStoreTestBackend(t, "/tenant")
	ctx := context.Background()

	writeObject(t, backend, "/obj.txt", "v1")
	info, err := backend.FileSystem().Stat(ctx, "/obj.txt")
	require.NoError(t, err)
	staleTag, err := info.(interface {
		ETag(context.Context) (string, error)
	}).ETag(ctx)
	require.NoError(t, err)

	// Open a conditional write against the tag we just read...
	condCtx := contextWithWriteCondition(ctx, writeCondition{requireETag: staleTag})
	f, err := backend.FileSystem().OpenFile(condCtx, "/obj.txt",
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	require.NoError(t, err)
	_, err = f.Write([]byte("v3 from the conditional writer"))
	require.NoError(t, err)

	// ...then let someone else win the race before it commits.
	writeObject(t, backend, "/obj.txt", "v2 from the interloper")

	err = f.Close()
	require.Error(t, err, "the commit must notice the generation moved")
	assert.ErrorIs(t, err, pstore.ErrPreconditionFailed)
	assert.Equal(t, http.StatusPreconditionFailed, statusForBackendError(err, true))

	body, err := backend.store.ReadAll("/tenant/obj.txt")
	require.NoError(t, err)
	assert.Equal(t, "v2 from the interloper", string(body),
		"the losing conditional write must not have installed anything")
}

// TestIfNoneMatchStarInAListDoesNotOverwrite guards against a fail-open
// parse.
//
// `If-None-Match: *, "junk"` is not string-equal to "*". A parser that
// compares the whole header value takes the entity-tag branch, where "*" is
// just a tag matching nothing, and silently downgrades a create-only request
// to an unconditional overwrite. RFC 9110 requires "*" to be the sole
// member, so any "*" in the list is the wildcard form.
func TestIfNoneMatchStarInAListDoesNotOverwrite(t *testing.T) {
	issuer := "https://issuer.example.com"
	o := newServedOrigin(t, []server_utils.OriginExport{{
		FederationPrefix: "/data",
		StoragePrefix:    "/tenant",
		IssuerUrls:       []string{issuer},
		Capabilities:     server_structs.Capabilities{Reads: true, Writes: true},
	}}, nil)

	tok := o.token(t, issuer, "storage.read:/ storage.create:/ storage.modify:/")

	rec := o.put(t, tok, "/data/obj.txt", "original", nil)
	require.Less(t, rec.Code, 300, "seeding PUT failed: %s", rec.Body.String())

	for _, header := range []string{`*, "junk"`, `"junk", *`, `  *  `} {
		t.Run(header, func(t *testing.T) {
			rec := o.put(t, tok, "/data/obj.txt", "overwritten",
				map[string]string{"If-None-Match": header})
			assert.Equal(t, http.StatusPreconditionFailed, rec.Code,
				"any list containing * is the create-only form; got %d: %s",
				rec.Code, rec.Body.String())

			body, err := o.store(t, "/data").ReadAll("/tenant/obj.txt")
			require.NoError(t, err)
			assert.Equal(t, "original", string(body))
		})
	}
}

// ---------------------------------------------------------------------------
// Digest lookups are confined too
// ---------------------------------------------------------------------------

// TestGetDigestsRefusesTraversal covers the checksum path, which joined the
// request-relative path onto the storage prefix without re-confining it: a
// HEAD for "/../two/secret.txt" on one export returned real digests for
// another export's object.
func TestGetDigestsRefusesTraversal(t *testing.T) {
	backend := newPStoreTestBackend(t, "/exports/one")

	// A neighbour to reach for.
	require.NoError(t, backend.store.MkdirAll("/exports/two"))
	w, err := backend.store.Create("/exports/two/secret.txt")
	require.NoError(t, err)
	_, err = w.Write([]byte("another export's data"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	cs := backend.Checksummer()
	require.NotNil(t, cs)

	digests, err := cs.GetDigests("/../two/secret.txt", "md5,crc32c")
	assert.Error(t, err, "a digest lookup must not resolve outside the export")
	assert.ErrorIs(t, err, os.ErrPermission)
	assert.Empty(t, digests)

	// The same lookup for the export's own object still works.
	writeObject(t, backend, "/mine.txt", "my data")
	digests, err = cs.GetDigests("/mine.txt", "md5")
	require.NoError(t, err)
	assert.NotEmpty(t, digests, "digests for the export's own objects are unaffected")
}
