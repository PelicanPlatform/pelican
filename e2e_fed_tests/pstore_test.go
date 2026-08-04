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

package fed_tests

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// pstoreOriginConfig builds an origin backed by the Pelican store.
//
// StoragePrefix is a logical path inside the store rather than a directory on
// disk, but NewFedTest rewrites it to a temp path regardless; that is harmless
// here because the store treats it as an opaque prefix and creates it on first
// write.
func pstoreOriginConfig(storeDir string) string {
	return fmt.Sprintf(`
Origin:
  StorageType: pstore
  PStoreLocation: %s
  Exports:
    - StoragePrefix: "/data"
      FederationPrefix: "/test"
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`, storeDir)
}

// getPStoreToken mints a token with read, create, and modify scopes.
func getPStoreToken(t *testing.T) string {
	t.Helper()
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "origin"
	tokenConfig.AddAudienceAny()

	readScope, err := token_scopes.Wlcg_Storage_Read.Path("/")
	require.NoError(t, err)
	createScope, err := token_scopes.Wlcg_Storage_Create.Path("/")
	require.NoError(t, err)
	modScope, err := token_scopes.Wlcg_Storage_Modify.Path("/")
	require.NoError(t, err)
	tokenConfig.AddScopes(readScope, createScope, modScope)

	tkn, err := tokenConfig.CreateToken()
	require.NoError(t, err)
	return tkn
}

// TestPStoreFederation drives a pstore-backed origin through the Pelican
// client over a real federation: upload, download, stat, list, and delete.
//
// The unit tests exercise the store and the WebDAV adapter directly; this
// covers everything in between -- director redirect, token authorization, the
// origin's handler chain, and the client's own transfer path.
func TestPStoreFederation(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	storeDir := t.TempDir()
	ft := fed_test_utils.NewFedTest(t, pstoreOriginConfig(storeDir))
	require.NotNil(t, ft)
	require.NotEmpty(t, ft.Exports)

	testToken := getPStoreToken(t)
	localDir := t.TempDir()
	discoveryHost := param.Server_Hostname.GetString()
	discoveryPort := param.Server_WebPort.GetInt()

	objectURL := func(name string) string {
		return fmt.Sprintf("pelican://%s:%d/test/%s", discoveryHost, discoveryPort, name)
	}

	t.Run("UploadAndDownload", func(t *testing.T) {
		content := "Hello from a pstore-backed origin!"
		src := filepath.Join(localDir, "upload.txt")
		require.NoError(t, os.WriteFile(src, []byte(content), 0644))

		_, err := client.DoPut(ft.Ctx, src, objectURL("upload.txt"),
			false, client.WithToken(testToken))
		require.NoError(t, err, "upload to the pstore origin should succeed")

		dst := filepath.Join(localDir, "download.txt")
		_, err = client.DoGet(ft.Ctx, objectURL("upload.txt"), dst,
			false, client.WithToken(testToken))
		require.NoError(t, err)

		got, err := os.ReadFile(dst)
		require.NoError(t, err)
		assert.Equal(t, content, string(got), "content survives the round trip")
	})

	t.Run("LargeObjectRoundTrip", func(t *testing.T) {
		// Past the spill threshold, so the streaming write path and its
		// chunk growth are exercised end to end rather than only in unit
		// tests.
		content := make([]byte, 10<<20)
		for i := range content {
			content[i] = byte(i % 251)
		}
		src := filepath.Join(localDir, "large.bin")
		require.NoError(t, os.WriteFile(src, content, 0644))

		_, err := client.DoPut(ft.Ctx, src, objectURL("large.bin"),
			false, client.WithToken(testToken))
		require.NoError(t, err)

		dst := filepath.Join(localDir, "large-out.bin")
		_, err = client.DoGet(ft.Ctx, objectURL("large.bin"), dst,
			false, client.WithToken(testToken))
		require.NoError(t, err)

		got, err := os.ReadFile(dst)
		require.NoError(t, err)
		assert.Equal(t, len(content), len(got))
		assert.True(t, string(content) == string(got), "large object round trips intact")
	})

	t.Run("Overwrite", func(t *testing.T) {
		// The client refuses to clobber an existing object unless this is
		// set. The subtest is about the origin swapping a new version in, not
		// about the client's guard rail.
		require.NoError(t, param.Client_EnableOverwrites.Set(true))
		t.Cleanup(func() { _ = param.Client_EnableOverwrites.Set(false) })

		src := filepath.Join(localDir, "over.txt")
		require.NoError(t, os.WriteFile(src, []byte("first"), 0644))
		_, err := client.DoPut(ft.Ctx, src, objectURL("over.txt"),
			false, client.WithToken(testToken))
		require.NoError(t, err)

		require.NoError(t, os.WriteFile(src, []byte("second"), 0644))
		_, err = client.DoPut(ft.Ctx, src, objectURL("over.txt"),
			false, client.WithToken(testToken))
		require.NoError(t, err)

		dst := filepath.Join(localDir, "over-out.txt")
		_, err = client.DoGet(ft.Ctx, objectURL("over.txt"), dst,
			false, client.WithToken(testToken))
		require.NoError(t, err)
		got, err := os.ReadFile(dst)
		require.NoError(t, err)
		assert.Equal(t, "second", string(got), "the overwrite is what is served")
	})

	t.Run("StatAndList", func(t *testing.T) {
		src := filepath.Join(localDir, "listed.txt")
		require.NoError(t, os.WriteFile(src, []byte("listed"), 0644))
		_, err := client.DoPut(ft.Ctx, src, objectURL("dir/listed.txt"),
			false, client.WithToken(testToken))
		require.NoError(t, err, "uploading into a fresh prefix must create it")

		info, err := client.DoStat(ft.Ctx, objectURL("dir/listed.txt"),
			client.WithToken(testToken))
		require.NoError(t, err)
		assert.EqualValues(t, len("listed"), info.Size)

		entries, err := client.DoList(ft.Ctx, objectURL("dir"),
			client.WithToken(testToken))
		require.NoError(t, err)
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, filepath.Base(e.Name))
		}
		assert.Contains(t, names, "listed.txt")
	})

	t.Run("Delete", func(t *testing.T) {
		src := filepath.Join(localDir, "doomed.txt")
		require.NoError(t, os.WriteFile(src, []byte("doomed"), 0644))
		_, err := client.DoPut(ft.Ctx, src, objectURL("doomed.txt"),
			false, client.WithToken(testToken))
		require.NoError(t, err)

		require.NoError(t, client.DoDelete(ft.Ctx, objectURL("doomed.txt"),
			false, client.WithToken(testToken)))

		_, err = client.DoStat(ft.Ctx, objectURL("doomed.txt"),
			client.WithToken(testToken))
		assert.Error(t, err, "a deleted object is gone")
	})

	t.Run("DataPersistsInTheStore", func(t *testing.T) {
		// The catalog and block files must actually be in the configured
		// location, rather than the origin having quietly fallen back to a
		// POSIX directory.
		entries, err := os.ReadDir(storeDir)
		require.NoError(t, err)
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		assert.Contains(t, names, "db", "the pstore catalog lives under PStoreLocation")
	})
}
