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

// End-to-end test for a shared-filesystem tiering target: a full federation
// whose V2 cache tiers to a local directory standing in for a site-wide
// mount.  Clients that share the mount are redirected to the object's path
// and read it directly; anyone who can read the mount can browse the names
// view.

package fed_tests

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/utils"
)

// tierRedirectCount reads how many reads of objects on tiering targets the
// cache has answered with a redirect, across all targets.
func tierRedirectCount(t *testing.T) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	total := 0.0
	for _, family := range families {
		if family.GetName() != "pelican_cache_tiering_requests_total" {
			continue
		}
		for _, m := range family.GetMetric() {
			for _, label := range m.GetLabel() {
				if label.GetName() == "mode" && label.GetValue() == "redirect" {
					total += m.GetCounter().GetValue()
				}
			}
		}
	}
	return total
}

// TestCacheTierSharedFilesystemE2E fetches an object through the cache, waits
// for it to be tiered to the shared directory, and then checks every way of
// reading it: a file:// redirect to a client that asked for one, the bytes
// themselves to a client that did not, the Pelican client following the
// redirect under Client.FileRedirectRoots, and the names view.
func TestCacheTierSharedFilesystemE2E(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	sharedDir := filepath.Join(t.TempDir(), "shared-tier")
	require.NoError(t, param.Cache_EnableV2.Set(true))
	require.NoError(t, param.Cache_TieringThreshold.Set("4KB"))
	require.NoError(t, param.Cache_TieringTargets.Set([]interface{}{
		map[string]interface{}{
			"ProviderURL": utils.PathToFileURL(sharedDir).String(),
			"MaxSize":     "1GB",
		},
	}))

	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)
	token := getTempTokenForTest(t)

	const objectPath = "/test/shared_fs/dataset@v1/big.bin"
	content := writeOriginFile(t, ft, "shared_fs/dataset@v1/big.bin", 64*1024)
	cacheURL := waitForCacheRedirectURL(t, ft, objectPath, token)
	httpClient := noRedirectHTTPClient()

	// The first GET is a miss, served from local storage; the object is
	// tiered once it completes.
	resp := getWithToken(t, httpClient, cacheURL, token, "")
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "cache-miss GET failed: %s", string(body))
	require.Equal(t, content, body)

	// Once tiered, a client that advertises file:// support is redirected
	// to the object's path on the shared filesystem.
	getAdvertising := func() *http.Response {
		req, err := http.NewRequest(http.MethodGet, cacheURL, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set(server_structs.AcceptRedirectHeader, server_structs.RedirectSchemeFileVerified)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		return resp
	}
	var location string
	require.Eventually(t, func() bool {
		resp := getAdvertising()
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		location = resp.Header.Get("Location")
		return resp.StatusCode == http.StatusTemporaryRedirect
	}, 30*time.Second, 250*time.Millisecond, "the cache never redirected to the shared filesystem")
	locationURL, err := url.Parse(location)
	require.NoError(t, err)
	require.Equal(t, "file", locationURL.Scheme)
	localPath := utils.FileURLToPath(locationURL)
	assert.True(t, strings.HasPrefix(localPath, filepath.Join(sharedDir, "objects")+string(filepath.Separator)),
		"the redirect must name the object in the shared directory: %s", localPath)
	onDisk, err := os.ReadFile(localPath)
	require.NoError(t, err)
	assert.Equal(t, content, onDisk)
	info, err := os.Stat(localPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())

	// A client that did not advertise it is served the bytes by the cache.
	resp = getWithToken(t, httpClient, cacheURL, token, "")
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, content, body)

	// The names view spells the object by its federation path; the '@'
	// already in the path is escaped so it cannot be read as a version.
	// The names are made just after the object becomes redirectable, so they
	// may not be there quite yet.
	namesDir := filepath.Join(sharedDir, "names", "test", "shared_fs", "dataset%40v1")
	require.Eventually(t, func() bool {
		byName, err := os.ReadFile(filepath.Join(namesDir, "big.bin"))
		if err != nil || string(byName) != string(content) {
			return false
		}
		versioned, err := filepath.Glob(filepath.Join(namesDir, "big.bin@*"))
		return err == nil && len(versioned) > 0
	}, 30*time.Second, 100*time.Millisecond, "the bare and versioned names never appeared")
	entries, err := os.ReadDir(namesDir)
	require.NoError(t, err)
	var versions []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "big.bin@") {
			versions = append(versions, e.Name())
		}
	}
	require.Len(t, versions, 1, "one version name per cached version")
	// Every name is a hard link to the file the redirect named.
	for _, name := range []string{"big.bin", versions[0]} {
		nameInfo, err := os.Lstat(filepath.Join(namesDir, name))
		require.NoError(t, err)
		assert.True(t, nameInfo.Mode().IsRegular(), "%s is a file, not a symlink", name)
		assert.True(t, os.SameFile(info, nameInfo), "%s is the object's own file", name)
	}

	// The Pelican client, allowed to follow file:// redirects under the
	// shared directory, reads the object straight off it.
	require.NoError(t, param.Client_FileRedirectRoots.Set([]string{sharedDir}))
	redirectsBefore := tierRedirectCount(t)
	downloadFile := filepath.Join(t.TempDir(), "via_client.bin")
	fedURL := fmt.Sprintf("pelican://%s:%d%s", param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), objectPath)
	_, err = client.DoGet(ft.Ctx, fedURL, downloadFile, false, client.WithToken(token))
	require.NoError(t, err)
	downloaded, err := os.ReadFile(downloadFile)
	require.NoError(t, err)
	assert.Equal(t, content, downloaded)
	assert.Greater(t, tierRedirectCount(t), redirectsBefore,
		"the client should have been redirected to the shared filesystem rather than served by the cache")

	// A partial download is redirected too, and gets only the bytes it
	// asked for.
	redirectsBefore = tierRedirectCount(t)
	te, err := client.NewTransferEngine(ft.Ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = te.Shutdown() })
	tc, err := te.NewClient(client.WithToken(token))
	require.NoError(t, err)
	partURL, err := url.Parse(fedURL)
	require.NoError(t, err)
	var part closableBuffer
	tj, err := tc.NewTransferJob(ft.Ctx, partURL, "", false, false, client.WithWriter(&part), client.WithByteRange(100, 199))
	require.NoError(t, err)
	require.NoError(t, tc.Submit(tj))
	results, err := tc.Shutdown()
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
	assert.Equal(t, content[100:200], part.Bytes())
	assert.Greater(t, tierRedirectCount(t), redirectsBefore, "the partial download should have been redirected")
}

// closableBuffer collects a transfer's bytes; the client closes its writer
// when the transfer ends.
type closableBuffer struct{ bytes.Buffer }

func (*closableBuffer) Close() error { return nil }

// sharedDirFoldsNames reports whether dir is on a filesystem that treats
// names differing only in case as the same, where a cache refuses an
// exact-names view.
func sharedDirFoldsNames(t *testing.T, dir string) bool {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Fold"), nil, 0o600))
	defer os.Remove(filepath.Join(dir, "Fold"))
	_, err := os.Lstat(filepath.Join(dir, "fOLD"))
	return err == nil
}

// TestCacheTierSharedFilesystemAllObjectsE2E: with AllObjects, objects too
// small to tier otherwise -- one below the threshold, one small enough to be
// kept inside the cache's database -- reach the shared filesystem through a
// running cache, are served from it both ways, and appear in an exact-names
// view under their own names.
func TestCacheTierSharedFilesystemAllObjectsE2E(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	parent := t.TempDir()
	sharedDir := filepath.Join(parent, "shared-tier")
	exact := !sharedDirFoldsNames(t, parent)
	target := map[string]interface{}{
		"ProviderURL": utils.PathToFileURL(sharedDir).String(),
		"MaxSize":     "1GB",
		"AllObjects":  true,
	}
	if exact {
		target["NamesView"] = "exact"
	}
	require.NoError(t, param.Cache_EnableV2.Set(true))
	require.NoError(t, param.Cache_TieringThreshold.Set("64KB"))
	require.NoError(t, param.Cache_TieringTargets.Set([]interface{}{target}))

	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)
	token := getTempTokenForTest(t)
	httpClient := noRedirectHTTPClient()

	for _, tc := range []struct {
		file string
		size int
	}{
		{"Small.TXT", 100},        // kept inline
		{"Medium.bin", 10 * 1024}, // on disk, below the threshold
	} {
		t.Run(tc.file, func(t *testing.T) {
			objectPath := "/test/shared_fs_all/Set@2/" + tc.file
			content := writeOriginFile(t, ft, "shared_fs_all/Set@2/"+tc.file, tc.size)
			cacheURL := waitForCacheRedirectURL(t, ft, objectPath, token)

			resp := getWithToken(t, httpClient, cacheURL, token, "")
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode, "cache-miss GET failed: %s", string(body))
			require.Equal(t, content, body)

			// The names are checked only where an exact view can run; on a
			// folding filesystem the versioned view escapes them, which its
			// own tests cover.
			if exact {
				name := filepath.Join(sharedDir, "names", "test", "shared_fs_all", "Set@2", tc.file)
				require.Eventually(t, func() bool {
					got, err := os.ReadFile(name)
					return err == nil && string(got) == string(content)
				}, 30*time.Second, 100*time.Millisecond, "the object never appeared under its exact name")
			}

			// Served from the shared filesystem: by redirect to a client
			// that asks for one, by the cache to one that does not.
			var location string
			require.Eventually(t, func() bool {
				req, err := http.NewRequest(http.MethodGet, cacheURL, nil)
				require.NoError(t, err)
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set(server_structs.AcceptRedirectHeader, server_structs.RedirectSchemeFileVerified)
				resp, err := httpClient.Do(req)
				require.NoError(t, err)
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				location = resp.Header.Get("Location")
				return resp.StatusCode == http.StatusTemporaryRedirect
			}, 30*time.Second, 100*time.Millisecond, "the object was never tiered to the shared filesystem")
			locationURL, err := url.Parse(location)
			require.NoError(t, err)
			onDisk, err := os.ReadFile(utils.FileURLToPath(locationURL))
			require.NoError(t, err)
			assert.Equal(t, content, onDisk)

			resp = getWithToken(t, httpClient, cacheURL, token, "")
			body, err = io.ReadAll(resp.Body)
			resp.Body.Close()
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, content, body)
		})
	}
}
