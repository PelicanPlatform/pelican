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

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
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

// TestObjectSyncCLI exercises the "pelican object sync" command for upload,
// download, third-party-copy (TPC), and TPC with --direct flag, all sharing
// a single federation to avoid sequential test isolation issues.
func TestObjectSyncCLI(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	if _, err := exec.LookPath("xrootd"); err != nil {
		t.Skip("Skipping test because xrootd is not installed")
	}

	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	require.NoError(t, param.Set(param.Origin_EnableDirectReads.GetName(), true))
	require.NoError(t, param.Set(param.Logging_DisableProgressBars.GetName(), true))

	originCfg := `
Origin:
  StorageType: "posix"
  EnableDirectReads: true
  Exports:
    - StoragePrefix: /<SHOULD BE OVERRIDDEN>
      FederationPrefix: /test
      Capabilities: ["PublicReads", "Reads", "Writes", "DirectReads", "Listings"]
`
	fed := fed_test_utils.NewFedTest(t, originCfg)

	host := fmt.Sprintf("%s:%d", param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
	exportPrefix := fed.Exports[0].FederationPrefix

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokenCfg := token.NewWLCGToken()
	tokenCfg.Lifetime = time.Minute
	tokenCfg.Issuer = issuer
	tokenCfg.Subject = "test"
	tokenCfg.AddAudienceAny()
	tokenCfg.AddResourceScopes(
		token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/"),
		token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Modify, "/"),
		token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Create, "/"),
	)
	tokStr, err := tokenCfg.CreateToken()
	require.NoError(t, err)
	tokenFile := filepath.Join(t.TempDir(), "token.jwt")
	require.NoError(t, os.WriteFile(tokenFile, []byte(tokStr), 0600))

	// Prepare a small directory tree to sync.
	srcDir := t.TempDir()
	subDir := filepath.Join(srcDir, "inner")
	require.NoError(t, os.MkdirAll(subDir, 0755))

	content1 := "first file for sync CLI"
	content2 := "second file nested"
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte(content1), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "b.txt"), []byte(content2), 0644))

	remoteBase := fmt.Sprintf("pelican://%s%s/sync_cli", host, exportPrefix)

	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetContext(context.TODO())
	})

	// ---- Upload sync ----
	t.Run("uploadSync", func(t *testing.T) {
		remoteDest := remoteBase + "/up/"
		rootCmd.SetContext(fed.Ctx)
		rootCmd.SetArgs([]string{"object", "sync", "--token", tokenFile, srcDir, remoteDest})

		err := rootCmd.Execute()
		require.NoError(t, err, "upload sync should succeed")

		// Verify the files landed by downloading them with the client library
		dlDir := t.TempDir()
		results, err := client.DoGet(fed.Ctx, remoteDest, dlDir, true, client.WithToken(tokStr))
		require.NoError(t, err)
		require.NotEmpty(t, results, "should have downloaded files")

		got, err := os.ReadFile(filepath.Join(dlDir, "a.txt"))
		require.NoError(t, err)
		assert.Equal(t, content1, string(got))
		got, err = os.ReadFile(filepath.Join(dlDir, "inner", "b.txt"))
		require.NoError(t, err)
		assert.Equal(t, content2, string(got))
	})

	// ---- Download sync ----
	t.Run("downloadSync", func(t *testing.T) {
		remoteSrc := remoteBase + "/up/"
		localDest := t.TempDir()
		rootCmd.SetContext(fed.Ctx)
		rootCmd.SetArgs([]string{"object", "sync", "--token", tokenFile, remoteSrc, localDest})

		err := rootCmd.Execute()
		require.NoError(t, err, "download sync should succeed")

		got, err := os.ReadFile(filepath.Join(localDest, "a.txt"))
		require.NoError(t, err)
		assert.Equal(t, content1, string(got))
		got, err = os.ReadFile(filepath.Join(localDest, "inner", "b.txt"))
		require.NoError(t, err)
		assert.Equal(t, content2, string(got))
	})

	// ---- TPC sync (remote-to-remote, directory) ----
	// Tests recursive third-party-copy on a directory with nested files.
	t.Run("tpcSync", func(t *testing.T) {
		remoteSrc := remoteBase + "/up/"
		remoteDest := remoteBase + "/tpc_dest/"
		rootCmd.SetContext(fed.Ctx)
		rootCmd.SetArgs([]string{"object", "sync", "--token", tokenFile, remoteSrc, remoteDest})

		err := rootCmd.Execute()
		require.NoError(t, err, "TPC sync should succeed")

		// Download the TPC destination directory to verify all files were copied
		dlDir := t.TempDir()
		_, err = client.DoGet(fed.Ctx, remoteDest, dlDir, true, client.WithToken(tokStr))
		require.NoError(t, err)

		got, err := os.ReadFile(filepath.Join(dlDir, "a.txt"))
		require.NoError(t, err)
		assert.Equal(t, content1, string(got))
		got, err = os.ReadFile(filepath.Join(dlDir, "inner", "b.txt"))
		require.NoError(t, err)
		assert.Equal(t, content2, string(got))
	})

	// ---- TPC sync skip existing ----
	// A second TPC sync on the same source should skip already-copied files.
	// Only a newly-added file should actually be transferred.
	t.Run("tpcSyncSkip", func(t *testing.T) {
		// Upload a new file to the source
		newContent := "third file added after first sync"
		newSrcFile := filepath.Join(t.TempDir(), "c.txt")
		require.NoError(t, os.WriteFile(newSrcFile, []byte(newContent), 0644))
		remoteSrcObj := remoteBase + "/up/c.txt"
		_, err := client.DoPut(fed.Ctx, newSrcFile, remoteSrcObj, false, client.WithToken(tokStr))
		require.NoError(t, err)

		// Run TPC sync again on the same directory
		remoteSrc := remoteBase + "/up/"
		remoteDest := remoteBase + "/tpc_dest/"
		rootCmd.SetContext(fed.Ctx)
		rootCmd.SetArgs([]string{"object", "sync", "--token", tokenFile, remoteSrc, remoteDest})

		err = rootCmd.Execute()
		require.NoError(t, err, "Second TPC sync should succeed")

		// Verify the new file arrived at destination
		dlDir := t.TempDir()
		_, err = client.DoGet(fed.Ctx, remoteDest, dlDir, true, client.WithToken(tokStr))
		require.NoError(t, err)

		// All three files should be present
		got, err := os.ReadFile(filepath.Join(dlDir, "a.txt"))
		require.NoError(t, err)
		assert.Equal(t, content1, string(got))
		got, err = os.ReadFile(filepath.Join(dlDir, "inner", "b.txt"))
		require.NoError(t, err)
		assert.Equal(t, content2, string(got))
		got, err = os.ReadFile(filepath.Join(dlDir, "c.txt"))
		require.NoError(t, err)
		assert.Equal(t, newContent, string(got))
	})

	// ---- TPC sync with --direct flag ----
	// Tests that TPC with --direct reads directly from the origin (bypasses cache).
	t.Run("tpcDirectRead", func(t *testing.T) {
		// Create a dedicated source file for this test
		testContent := "directread TPC via CLI test"
		drSrcFile := filepath.Join(t.TempDir(), "dr.txt")
		require.NoError(t, os.WriteFile(drSrcFile, []byte(testContent), 0644))
		remoteSrcObj := fmt.Sprintf("pelican://%s%s/tpc_dr_cli/src.txt", host, exportPrefix)
		_, err := client.DoPut(fed.Ctx, drSrcFile, remoteSrcObj, false, client.WithToken(tokStr))
		require.NoError(t, err)

		remoteDest := fmt.Sprintf("pelican://%s%s/tpc_dr_cli/dst.txt", host, exportPrefix)
		rootCmd.SetContext(fed.Ctx)
		rootCmd.SetArgs([]string{"object", "sync", "--token", tokenFile, "--direct", remoteSrcObj, remoteDest})

		err = rootCmd.Execute()
		require.NoError(t, err, "TPC sync with directread should succeed")

		// Download and verify the destination
		dlDir := t.TempDir()
		_, err = client.DoGet(fed.Ctx, remoteDest, dlDir, false, client.WithToken(tokStr))
		require.NoError(t, err)

		got, err := os.ReadFile(filepath.Join(dlDir, "dst.txt"))
		require.NoError(t, err)
		assert.Equal(t, testContent, string(got))

		// Verify the file was NOT cached (directread bypasses cache)
		cacheDataLocation := param.Cache_StorageLocation.GetString() + exportPrefix
		cachedPath := filepath.Join(cacheDataLocation, "tpc_dr_cli", "src.txt")
		_, statErr := os.Stat(cachedPath)
		assert.True(t, os.IsNotExist(statErr), "Source file should not be cached when using directread")
	})
}
