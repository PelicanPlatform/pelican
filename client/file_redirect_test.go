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
)

// setFileRedirectRoots points Client.FileRedirectRoots at the given roots for
// the duration of the test.
func setFileRedirectRoots(t *testing.T, roots ...string) {
	t.Helper()
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	require.NoError(t, param.Client_FileRedirectRoots.Set(roots))
}

// TestFileRedirectsOffByDefault pins the default: with no roots configured
// the client neither advertises the capability nor gains the ability to
// follow a file:// redirect.  Both halves matter — a cache only sends such a
// redirect to a client that asked, so staying silent is the primary control
// and refusing to follow one is the backstop.
func TestFileRedirectsOffByDefault(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	assert.False(t, fileRedirectsEnabled())
	assert.Empty(t, allowedFileRedirectRoots())

	req := httptest.NewRequest(http.MethodGet, "https://cache.example.org/ns/obj", nil)
	setAcceptRedirectHeader(req)
	assert.Empty(t, req.Header.Get(server_structs.AcceptRedirectHeader),
		"a client that cannot follow file:// must not advertise that it can")

	base := &http.Client{Transport: &http.Transport{}}
	assert.Same(t, base, withFileRedirects(base),
		"the shared client must be handed back untouched when the feature is off")
}

// TestFileRedirectAdvertisedWhenConfigured covers the other side of the
// handshake: configuring a root is what makes the client say so.
func TestFileRedirectAdvertisedWhenConfigured(t *testing.T) {
	setFileRedirectRoots(t, t.TempDir())

	require.True(t, fileRedirectsEnabled())
	req := httptest.NewRequest(http.MethodGet, "https://cache.example.org/ns/obj", nil)
	setAcceptRedirectHeader(req)
	assert.Equal(t, "file", req.Header.Get(server_structs.AcceptRedirectHeader))
}

// TestFileRedirectFollowedWithinRoot is the end-to-end happy path: a cache
// answers with a 307 to a file:// URL and the client reads the object from
// the shared filesystem instead of over the network.
func TestFileRedirectFollowedWithinRoot(t *testing.T) {
	root := t.TempDir()
	payload := []byte("tiered object contents")
	objPath := filepath.Join(root, "42", "obj.dat")
	require.NoError(t, os.MkdirAll(filepath.Dir(objPath), 0755))
	require.NoError(t, os.WriteFile(objPath, payload, 0644))
	setFileRedirectRoots(t, root)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "file", r.Header.Get(server_structs.AcceptRedirectHeader))
		http.Redirect(w, r, "file://"+objPath, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	setAcceptRedirectHeader(req)

	client := withFileRedirects(&http.Client{Transport: &http.Transport{}})
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

	setFileRedirectRoots(t, root)
	client := withFileRedirects(&http.Client{Transport: &http.Transport{}})

	tests := []struct {
		name   string
		target string
		status int
	}{
		{"inside the root", "file://" + allowed, http.StatusOK},
		{"relative symlink staying inside the root", "file://" + internal, http.StatusOK},
		{"absolute symlink, even to a file inside", "file://" + absInternal, http.StatusForbidden},
		{"symlink escaping the root", "file://" + escape, http.StatusForbidden},
		{"absolute path outside the root", "file://" + secret, http.StatusForbidden},
		{"traversal out of the root", "file://" + filepath.Join(root, "..", filepath.Base(outside), "id_rsa"), http.StatusForbidden},
		{"root-prefixed sibling directory", "file://" + siblingFile, http.StatusForbidden},
		{"a directory rather than a file", "file://" + subdir, http.StatusForbidden},
		{"missing file", "file://" + filepath.Join(root, "absent.dat"), http.StatusNotFound},
		{"remote host", "file://elsewhere.example.org" + allowed, http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, tt.target, http.StatusTemporaryRedirect)
			}))
			defer srv.Close()

			resp, err := client.Get(srv.URL)
			require.NoError(t, err)
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			assert.Equal(t, tt.status, resp.StatusCode)
		})
	}
}

// TestFileRedirectSymlinkedRoot covers a root configured through a symlink —
// a mount point reached via /mnt/<name> that really lives elsewhere is an
// ordinary way to deploy this.  The cache may send either spelling of the
// path, so both have to resolve to the same root.
func TestFileRedirectSymlinkedRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not reliably available on Windows CI")
	}
	real := t.TempDir()
	payload := []byte("via a symlinked root")
	require.NoError(t, os.WriteFile(filepath.Join(real, "obj.dat"), payload, 0644))

	linkDir := t.TempDir()
	link := filepath.Join(linkDir, "mount")
	require.NoError(t, os.Symlink(real, link))

	setFileRedirectRoots(t, link)
	client := withFileRedirects(&http.Client{Transport: &http.Transport{}})

	for _, spelling := range []string{
		filepath.Join(link, "obj.dat"), // as configured
		filepath.Join(real, "obj.dat"), // as resolved
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "file://"+spelling, http.StatusTemporaryRedirect)
		}))
		resp, err := client.Get(srv.URL)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		srv.Close()
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "spelling %q", spelling)
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

	// Build the file-capable client while a root is configured...
	setFileRedirectRoots(t, root)
	client := withFileRedirects(&http.Client{Transport: &http.Transport{}})
	// ...then take the configuration away.
	require.NoError(t, param.Client_FileRedirectRoots.Set([]string{}))
	require.False(t, fileRedirectsEnabled())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "file://"+objPath, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	resp, err := client.Get(srv.URL)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}
