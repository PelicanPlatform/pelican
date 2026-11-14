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

package client

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/utils"
)

// setFileRedirectRoots points Client.FileRedirectRoots at the given roots for
// the duration of the test, and returns a redirector, as an engine would
// have, to follow redirects under them.
func setFileRedirectRoots(t *testing.T, roots ...string) *fileRedirector {
	t.Helper()
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	require.NoError(t, param.Client_FileRedirectRoots.Set(roots))
	fr := newFileRedirector()
	// Registered after t.TempDir's cleanups, so it runs before them: an open
	// root would keep Windows from removing the directory.
	t.Cleanup(fr.close)
	return fr
}

// fileURL spells a local path as a file:// URL, the way a cache would.
func fileURL(path string) string { return utils.PathToFileURL(path).String() }

// skipUnlessVerifiable skips a test that follows a file:// redirect on a
// platform where the client cannot check the directory it reads from, and
// so never follows one.
func skipUnlessVerifiable(t *testing.T) {
	t.Helper()
	if !fileTargetsVerifiable {
		t.Skip("file:// redirects are not followed on this platform")
	}
}

// makeFileTarget lays dir out as a cache's shared-filesystem target -- an
// identity file below it -- and returns what the cache would send in
// X-Pelican-File-Target for it.
func makeFileTarget(t *testing.T, dir, id string) string {
	t.Helper()
	identity := filepath.Join(dir, filepath.FromSlash(server_structs.FileTargetIdentityFile))
	require.NoError(t, os.MkdirAll(filepath.Dir(identity), 0o755))
	require.NoError(t, os.WriteFile(identity, []byte(id), 0o644))
	return fileTargetOf(t, dir, id)
}

// fileTargetOf is the X-Pelican-File-Target value for dir as it is now.
func fileTargetOf(t *testing.T, dir, id string) string {
	t.Helper()
	info, err := os.Stat(dir)
	require.NoError(t, err)
	_, inode, ok := utils.FileVFSID(info)
	require.True(t, ok)
	return server_structs.FileTarget{Root: dir, Inode: inode, ID: id}.String()
}

// redirectingCache answers every request as a cache would: a redirect to
// location, naming the directory it lies in.
func redirectingCache(t *testing.T, location, fileTarget string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fileTarget != "" {
			w.Header().Set(server_structs.FileTargetHeader, fileTarget)
		}
		http.Redirect(w, r, location, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// fetch follows a redirect from srv, returning the status and body.
func fetch(t *testing.T, client *http.Client, srv *httptest.Server) (int, []byte) {
	t.Helper()
	resp, err := client.Get(srv.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, body
}

// TestFileRedirectsOffByDefault pins the default: with no roots configured
// the client neither advertises the capability nor gains the ability to
// follow a file:// redirect.  Both halves matter — a cache only sends such a
// redirect to a client that asked, so staying silent is the primary control
// and refusing to follow one is the backstop.
func TestFileRedirectsOffByDefault(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	engine := newFileRedirector()
	t.Cleanup(engine.close)
	base := &http.Client{Transport: &http.Transport{}}
	// A transfer made without an engine has no redirector at all.
	for name, fr := range map[string]*fileRedirector{"an engine's": engine, "none": nil} {
		assert.False(t, fr.enabled(), name)
		assert.Empty(t, fr.openRoots(), name)

		req := httptest.NewRequest(http.MethodGet, "https://cache.example.org/ns/obj", nil)
		fr.advertise(req)
		assert.Empty(t, req.Header.Get(server_structs.AcceptRedirectHeader),
			"%s: a client that cannot follow file:// must not advertise that it can", name)

		assert.Same(t, base, fr.httpClient(base),
			"%s: the shared client must be handed back untouched when the feature is off", name)
	}
}

// TestFileRedirectAdvertisedWhenConfigured covers the other side of the
// handshake: configuring a root is what makes the client say so -- and that
// it will check the directory, which is what a cache waits to hear.
func TestFileRedirectAdvertisedWhenConfigured(t *testing.T) {
	fr := setFileRedirectRoots(t, t.TempDir())

	require.True(t, fr.enabled())
	req := httptest.NewRequest(http.MethodGet, "https://cache.example.org/ns/obj", nil)
	fr.advertise(req)
	if fileTargetsVerifiable {
		assert.Equal(t, "file-verified", req.Header.Get(server_structs.AcceptRedirectHeader))
	} else {
		assert.Empty(t, req.Header.Get(server_structs.AcceptRedirectHeader),
			"a client that cannot check the directory must not offer to follow file://")
	}
}

// TestFileRedirectFollowedWithinRoot is the end-to-end happy path: a cache
// answers with a 307 to a file:// URL and the client reads the object from
// the shared filesystem instead of over the network.
func TestFileRedirectFollowedWithinRoot(t *testing.T) {
	skipUnlessVerifiable(t)
	root := t.TempDir()
	payload := []byte("tiered object contents")
	objPath := filepath.Join(root, "42", "obj.dat")
	require.NoError(t, os.MkdirAll(filepath.Dir(objPath), 0755))
	require.NoError(t, os.WriteFile(objPath, payload, 0644))
	target := makeFileTarget(t, root, "cache-id")
	fr := setFileRedirectRoots(t, root)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "file-verified", r.Header.Get(server_structs.AcceptRedirectHeader))
		w.Header().Set(server_structs.FileTargetHeader, target)
		http.Redirect(w, r, fileURL(objPath), http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	fr.advertise(req)

	client := fr.httpClient(&http.Client{Transport: &http.Transport{}})
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, payload, body)
	assert.Equal(t, int64(len(payload)), resp.ContentLength)
}

// TestFileRedirectContainment is the security boundary.  A cache chooses the
// path in a file:// redirect, so the client must refuse anything the operator
// did not sanction — including, crucially, a symlink that lives inside an
// allowed root but points outside it.  Cleaning ".." (all that http.Dir does)
// would let that one through.
func TestFileRedirectContainment(t *testing.T) {
	skipUnlessVerifiable(t)
	root := t.TempDir()
	outside := t.TempDir()

	secret := filepath.Join(outside, "id_rsa")
	require.NoError(t, os.WriteFile(secret, []byte("PRIVATE KEY"), 0600))
	allowed := filepath.Join(root, "ok.dat")
	require.NoError(t, os.WriteFile(allowed, []byte("fine"), 0644))

	escape := filepath.Join(root, "escape")
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not reliably available on Windows CI")
	}
	require.NoError(t, os.Symlink(secret, escape))

	subdir := filepath.Join(root, "sub")
	require.NoError(t, os.MkdirAll(subdir, 0755))

	// A sibling whose name merely starts with the root's name must not be
	// treated as inside it.
	sibling := root + "-other"
	require.NoError(t, os.MkdirAll(sibling, 0755))
	t.Cleanup(func() { os.RemoveAll(sibling) })
	siblingFile := filepath.Join(sibling, "secret.dat")
	require.NoError(t, os.WriteFile(siblingFile, []byte("nope"), 0644))

	// A symlink that stays inside the root is legitimate and must still
	// work: os.Root follows links, it just will not let one leave the tree.
	internal := filepath.Join(subdir, "link-to-ok")
	require.NoError(t, os.Symlink(filepath.Join("..", filepath.Base(allowed)), internal))
	// os.Root refuses an *absolute* symlink even when its target is inside
	// the root, so pin that too rather than let it surprise someone later.
	absInternal := filepath.Join(subdir, "abs-link-to-ok")
	require.NoError(t, os.Symlink(allowed, absInternal))

	target := makeFileTarget(t, root, "cache-id")
	fr := setFileRedirectRoots(t, root)
	client := fr.httpClient(&http.Client{Transport: &http.Transport{}})

	tests := []struct {
		name   string
		target string
		status int
	}{
		{"inside the root", fileURL(allowed), http.StatusOK},
		{"relative symlink staying inside the root", fileURL(internal), http.StatusOK},
		{"absolute symlink, even to a file inside", fileURL(absInternal), http.StatusForbidden},
		{"symlink escaping the root", fileURL(escape), http.StatusForbidden},
		{"absolute path outside the root", fileURL(secret), http.StatusForbidden},
		{"traversal out of the root", fileURL(filepath.Join(root, "..", filepath.Base(outside), "id_rsa")), http.StatusForbidden},
		{"root-prefixed sibling directory", fileURL(siblingFile), http.StatusForbidden},
		{"a directory rather than a file", fileURL(subdir), http.StatusForbidden},
		{"missing file", fileURL(filepath.Join(root, "absent.dat")), http.StatusNotFound},
		{"remote host", remoteHostURL(allowed), http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, _ := fetch(t, client, redirectingCache(t, tt.target, target))
			assert.Equal(t, tt.status, status)
		})
	}
}

// TestFileRedirectSymlinkedRoot covers a root configured through a symlink —
// a mount point reached via /mnt/<name> that really lives elsewhere is an
// ordinary way to deploy this.  The cache may send either spelling of the
// path, so both have to resolve to the same root.
func TestFileRedirectSymlinkedRoot(t *testing.T) {
	skipUnlessVerifiable(t)
	real := t.TempDir()
	payload := []byte("via a symlinked root")
	require.NoError(t, os.WriteFile(filepath.Join(real, "obj.dat"), payload, 0644))
	makeFileTarget(t, real, "cache-id")

	linkDir := t.TempDir()
	link := filepath.Join(linkDir, "mount")
	require.NoError(t, os.Symlink(real, link))

	fr := setFileRedirectRoots(t, link)
	client := fr.httpClient(&http.Client{Transport: &http.Transport{}})

	for _, dir := range []string{
		link, // as configured
		real, // as resolved
	} {
		srv := redirectingCache(t, fileURL(filepath.Join(dir, "obj.dat")), fileTargetOf(t, dir, "cache-id"))
		status, body := fetch(t, client, srv)
		assert.Equal(t, http.StatusOK, status, "spelling %q", dir)
		assert.Equal(t, payload, body)
	}
}

// TestFileRedirectRefusedWhenDisabled covers defence in depth: even if a
// cache sends a file:// redirect to a client that never advertised support,
// the transport refuses it rather than reading the path.
func TestFileRedirectRefusedWhenDisabled(t *testing.T) {
	root := t.TempDir()
	objPath := filepath.Join(root, "obj.dat")
	require.NoError(t, os.WriteFile(objPath, []byte("contents"), 0644))
	var target string
	if fileTargetsVerifiable {
		target = makeFileTarget(t, root, "cache-id")
	}

	// Build the file-capable client while a root is configured...
	fr := setFileRedirectRoots(t, root)
	client := fr.httpClient(&http.Client{Transport: &http.Transport{}})
	// ...then take the configuration away.
	require.NoError(t, param.Client_FileRedirectRoots.Set([]string{}))
	require.False(t, fr.enabled())

	status, _ := fetch(t, client, redirectingCache(t, fileURL(objPath), target))
	assert.Equal(t, http.StatusForbidden, status)
}

// remoteHostURL is a file URL for path on some other machine.
func remoteHostURL(path string) string {
	u := utils.PathToFileURL(path)
	u.Host = "elsewhere.example.org"
	return u.String()
}

// TestFileRedirectPercentInName follows a redirect to a file whose name
// contains a percent sign, end to end.
func TestFileRedirectPercentInName(t *testing.T) {
	skipUnlessVerifiable(t)
	root := t.TempDir()
	payload := []byte("percent")
	objPath := filepath.Join(root, "a%41.dat")
	require.NoError(t, os.WriteFile(objPath, payload, 0644))
	target := makeFileTarget(t, root, "cache-id")
	fr := setFileRedirectRoots(t, root)

	status, body := fetch(t, fr.httpClient(&http.Client{Transport: &http.Transport{}}),
		redirectingCache(t, fileURL(objPath), target))
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, payload, body)
}

// TestFileRedirectChecksTheDirectory: nothing is read unless the redirect
// names the directory it points into, and the directory at that path is the
// one named -- by inode and by the ID in its identity file.
func TestFileRedirectChecksTheDirectory(t *testing.T) {
	skipUnlessVerifiable(t)
	parent := t.TempDir()
	dir := filepath.Join(parent, "cache")
	objPath := filepath.Join(dir, "objects", "obj.dat")
	target := makeFileTarget(t, dir, "cache-id")
	require.NoError(t, os.WriteFile(objPath, []byte("contents"), 0o644))
	elsewhere := t.TempDir()
	fr := setFileRedirectRoots(t, parent)
	client := fr.httpClient(&http.Client{Transport: &http.Transport{}})

	good, err := server_structs.ParseFileTarget(target)
	require.NoError(t, err)
	wrongInode, wrongID, outside := good, good, good
	wrongInode.Inode++
	wrongID.ID = "another-cache"
	outside.Root = elsewhere
	for name, tc := range map[string]struct {
		header string
		status int
	}{
		"as named":                 {target, http.StatusOK},
		"no header":                {"", http.StatusForbidden},
		"malformed header":         {"root=relative&inode=1&id=x", http.StatusForbidden},
		"another inode":            {wrongInode.String(), http.StatusForbidden},
		"another ID":               {wrongID.String(), http.StatusForbidden},
		"the path is not below it": {outside.String(), http.StatusForbidden},
		"names the root's parent":  {fileTargetOf(t, parent, "cache-id"), http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			fr.forgetVerified()
			status, _ := fetch(t, client, redirectingCache(t, fileURL(objPath), tc.header))
			assert.Equal(t, tc.status, status)
		})
	}
}

// TestFileRedirectSurvivesASwap: once an engine has checked a directory, it
// reads through the directory it checked, so someone who then renames the
// cache's directory away and puts their own in its place reaches nothing;
// an engine that has not checked yet finds the new directory is not the
// cache's and reads nothing from it either.
func TestFileRedirectSurvivesASwap(t *testing.T) {
	skipUnlessVerifiable(t)
	parent := t.TempDir() // writable by someone other than the cache, say
	dir := filepath.Join(parent, "cache")
	target := makeFileTarget(t, dir, "cache-id")
	objPath := filepath.Join(dir, "objects", "obj.dat")
	require.NoError(t, os.WriteFile(objPath, []byte("genuine"), 0o644))
	fr := setFileRedirectRoots(t, parent)
	client := fr.httpClient(&http.Client{Transport: &http.Transport{}})
	srv := redirectingCache(t, fileURL(objPath), target)

	status, body := fetch(t, client, srv)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "genuine", string(body))

	// The swap: the identity file is readable, so it can be copied too.
	require.NoError(t, os.Rename(dir, filepath.Join(parent, "moved")))
	makeFileTarget(t, dir, "cache-id")
	require.NoError(t, os.WriteFile(objPath, []byte("planted"), 0o644))

	status, body = fetch(t, client, srv)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "genuine", string(body), "the directory checked is the one read")

	other := newFileRedirector() // another engine, which has checked nothing
	t.Cleanup(other.close)
	status, body = fetch(t, other.httpClient(&http.Client{Transport: &http.Transport{}}), srv)
	assert.Equal(t, http.StatusForbidden, status)
	assert.NotEqual(t, "planted", string(body))
}

// TestFileRedirectFollowsARecreatedDirectory: when the cache's directory is
// recreated, the cache names the new one, and the client checks it afresh
// rather than holding on to the old.
func TestFileRedirectFollowsARecreatedDirectory(t *testing.T) {
	skipUnlessVerifiable(t)
	parent := t.TempDir()
	dir := filepath.Join(parent, "cache")
	objPath := filepath.Join(dir, "objects", "obj.dat")
	first := makeFileTarget(t, dir, "first-id")
	require.NoError(t, os.WriteFile(objPath, []byte("first"), 0o644))
	fr := setFileRedirectRoots(t, parent)
	client := fr.httpClient(&http.Client{Transport: &http.Transport{}})

	status, body := fetch(t, client, redirectingCache(t, fileURL(objPath), first))
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "first", string(body))

	require.NoError(t, os.Rename(dir, filepath.Join(parent, "retired")))
	second := makeFileTarget(t, dir, "second-id")
	require.NoError(t, os.WriteFile(objPath, []byte("second"), 0o644))

	status, body = fetch(t, client, redirectingCache(t, fileURL(objPath), second))
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "second", string(body))
}

// TestFileRedirectRechecksAFailingDirectory: a held directory that stops
// working -- removed on the file server, say -- is checked afresh rather
// than failing every later redirect.
func TestFileRedirectRechecksAFailingDirectory(t *testing.T) {
	skipUnlessVerifiable(t)
	root := t.TempDir()
	objPath := filepath.Join(root, "objects", "obj.dat")
	target := makeFileTarget(t, root, "cache-id")
	require.NoError(t, os.WriteFile(objPath, []byte("contents"), 0o644))
	fr := setFileRedirectRoots(t, root)
	client := fr.httpClient(&http.Client{Transport: &http.Transport{}})
	srv := redirectingCache(t, fileURL(objPath), target)

	status, _ := fetch(t, client, srv)
	require.Equal(t, http.StatusOK, status)

	// Break the held handle, as a stale one would be.
	fr.mu.Lock()
	for _, v := range fr.verified {
		require.NoError(t, v.root.Close())
	}
	fr.mu.Unlock()

	status, body := fetch(t, client, srv)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "contents", string(body))
}

// TestFileRangeHeader: the client's own Range spellings pick out the bytes
// they name; a range past the end cannot be satisfied; anything else is
// answered with the whole file.
func TestFileRangeHeader(t *testing.T) {
	for header, want := range map[string]struct {
		start, end          int64
		ranged, satisfiable bool
	}{
		"":               {0, 9, false, true},
		"bytes=0-":       {0, 9, true, true},
		"bytes=3-":       {3, 9, true, true},
		"bytes=2-5":      {2, 5, true, true},
		"bytes=2-100":    {2, 9, true, true},
		"bytes=-4":       {6, 9, true, true},
		"bytes=-40":      {0, 9, true, true},
		"bytes=10-":      {0, 0, true, false},
		"bytes=5-2":      {0, 9, false, true},
		"bytes=0-1,4-5":  {0, 9, false, true},
		"items=0-1":      {0, 9, false, true},
		"bytes=x-":       {0, 9, false, true},
		"bytes=-0":       {0, 9, false, true},
		"bytes=-1-2":     {0, 9, false, true},
		"bytes= 1 - 2 ":  {0, 9, false, true},
		"bytes=00000-01": {0, 1, true, true},
	} {
		start, end, ranged, satisfiable := fileRange(header, 10)
		assert.Equal(t, want, struct {
			start, end          int64
			ranged, satisfiable bool
		}{start, end, ranged, satisfiable}, "%q", header)
	}
}

// TestFileRedirectServesRanges: a resumed or partial download that is
// redirected to the filesystem gets the bytes it asked for, as it would from
// the cache, not the whole file.
func TestFileRedirectServesRanges(t *testing.T) {
	skipUnlessVerifiable(t)
	dir := filepath.Join(t.TempDir(), "cache")
	target := makeFileTarget(t, dir, "cache-id")
	objPath := filepath.Join(dir, "objects", "obj.dat")
	content := "0123456789"
	require.NoError(t, os.WriteFile(objPath, []byte(content), 0o644))
	fr := setFileRedirectRoots(t, dir)
	client := fr.httpClient(&http.Client{Transport: &http.Transport{}})
	srv := redirectingCache(t, fileURL(objPath), target)

	for _, tc := range []struct {
		rangeHeader, body, contentRange string
		status                          int
	}{
		{"", content, "", http.StatusOK},
		{"bytes=2-5", "2345", "bytes 2-5/10", http.StatusPartialContent},
		{"bytes=7-", "789", "bytes 7-9/10", http.StatusPartialContent},
		{"bytes=10-", "", "bytes */10", http.StatusRequestedRangeNotSatisfiable},
	} {
		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		require.NoError(t, err)
		if tc.rangeHeader != "" {
			req.Header.Set("Range", tc.rangeHeader)
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.NoError(t, err)
		assert.Equal(t, tc.status, resp.StatusCode, "%q", tc.rangeHeader)
		assert.Equal(t, tc.body, string(body), "%q", tc.rangeHeader)
		assert.Equal(t, int64(len(tc.body)), resp.ContentLength, "%q", tc.rangeHeader)
		assert.Equal(t, tc.contentRange, resp.Header.Get("Content-Range"), "%q", tc.rangeHeader)
	}
}

// TestFileRedirectCarriesValidators: the object's entity tag and checksums,
// which the cache sends with the redirect, reach the client with the file,
// so an expected version or checksum is checked against them.
func TestFileRedirectCarriesValidators(t *testing.T) {
	skipUnlessVerifiable(t)
	dir := filepath.Join(t.TempDir(), "cache")
	target := makeFileTarget(t, dir, "cache-id")
	objPath := filepath.Join(dir, "objects", "obj.dat")
	require.NoError(t, os.WriteFile(objPath, []byte("contents"), 0o644))
	fr := setFileRedirectRoots(t, dir)
	client := fr.httpClient(&http.Client{Transport: &http.Transport{}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(server_structs.FileTargetHeader, target)
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Digest", "crc32c=deadbeef")
		w.Header().Set("Set-Cookie", "session=1")
		http.Redirect(w, r, fileURL(objPath), http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)

	resp, err := client.Get(srv.URL)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, `"v1"`, resp.Header.Get("ETag"))
	assert.Equal(t, "crc32c=deadbeef", resp.Header.Get("Digest"))
	assert.Empty(t, resp.Header.Get("Set-Cookie"), "only headers describing the object are carried over")
	assert.Equal(t, fmt.Sprint(len("contents")), resp.Header.Get("Content-Length"))
}
