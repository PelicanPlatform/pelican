//go:build client && !windows

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
	"net/url"
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

var (
	bothAuthOriginCfg = `
Origin:
  Exports:
    - FederationPrefix: /test
      StoragePrefix: /tmp/test
      Capabilities: [Reads, Writes, DirectReads, Listings]
`
)

// Helper function to get a temporary token file
func getTempTokenForTest(t *testing.T) (tempToken *os.File, tkn string) {
	require.NoError(t, param.IssuerKeysDirectory.Set(t.TempDir()))

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	// Create a token file
	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "origin"
	tokenConfig.AddAudienceAny()

	scopes := []token_scopes.TokenScope{}
	readScope, err := token_scopes.Wlcg_Storage_Read.Path("/")
	assert.NoError(t, err)
	scopes = append(scopes, readScope)
	modScope, err := token_scopes.Wlcg_Storage_Modify.Path("/")
	assert.NoError(t, err)
	scopes = append(scopes, modScope)
	tokenConfig.AddScopes(scopes...)
	tkn, err = tokenConfig.CreateToken()
	assert.NoError(t, err)
	tmpTok := filepath.Join(t.TempDir(), "token")
	tempToken, err = os.OpenFile(tmpTok, os.O_CREATE|os.O_RDWR, 0644)
	assert.NoError(t, err, "Error opening the temp token file")
	_, err = tempToken.WriteString(tkn)
	assert.NoError(t, err, "Error writing to temp token file")

	return
}

// TestObjectPutToDirectoryInfersFilename tests that uploading to a directory
// infers the destination filename from the source file, similar to cp/scp behavior.
func TestObjectPutToDirectoryInfersFilename(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Use an authenticated origin configuration
	fed := fed_test_utils.NewFedTest(t, bothAuthOriginCfg)

	// Create test files
	testFileContent1 := "test file content for directory inference"
	tempFile1, err := os.CreateTemp(t.TempDir(), "test1-*.txt")
	require.NoError(t, err)
	defer os.Remove(tempFile1.Name())
	_, err = tempFile1.WriteString(testFileContent1)
	require.NoError(t, err)
	tempFile1.Close()

	testFileContent2 := "second test file content"
	tempFile2, err := os.CreateTemp(t.TempDir(), "test2-*.txt")
	require.NoError(t, err)
	defer os.Remove(tempFile2.Name())
	_, err = tempFile2.WriteString(testFileContent2)
	require.NoError(t, err)
	tempFile2.Close()

	// Get token
	tempToken, _ := getTempTokenForTest(t)
	defer tempToken.Close()
	defer os.Remove(tempToken.Name())

	// Disable progress bars
	require.NoError(t, param.Logging_Client_DisableProgressBars.Set(true))

	namespacePrefix := fed.Exports[0].FederationPrefix
	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)
	host := discoveryUrl.Host

	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetContext(context.TODO())
		// Cobra only copies the root's context onto a subcommand whose own
		// context is nil, so putCmd would otherwise pin this test's
		// cancelled context for every later test in the package.
		putCmd.SetContext(nil)
	})

	// First upload a file to create a "directory" at the destination
	subdirUploadURL := fmt.Sprintf("pelican://%s%s/testdir/%s", host, namespacePrefix, filepath.Base(tempFile1.Name()))

	rootCmd.SetContext(fed.Ctx)
	rootCmd.SetArgs([]string{"object", "put", "-t", tempToken.Name(), tempFile1.Name(), subdirUploadURL})

	err = rootCmd.Execute()
	require.NoError(t, err)

	// Now test that uploading to just the namespace/testdir infers the filename
	dirUploadURL := fmt.Sprintf("pelican://%s%s/testdir", host, namespacePrefix)

	rootCmd.SetContext(fed.Ctx)
	rootCmd.SetArgs([]string{"object", "put", "-t", tempToken.Name(), tempFile2.Name(), dirUploadURL})

	err = rootCmd.Execute()
	require.NoError(t, err)

	// Verify the file was uploaded to testdir/<inferred-filename>
	inferredUploadURL := fmt.Sprintf("pelican://%s%s/testdir/%s", host, namespacePrefix, filepath.Base(tempFile2.Name()))

	downloadDir := t.TempDir()
	downloadPath := filepath.Join(downloadDir, "downloaded-file.txt")

	_, err = client.DoGet(fed.Ctx, inferredUploadURL, downloadPath, false, client.WithTokenLocation(tempToken.Name()))
	require.NoError(t, err)

	// Verify the downloaded file has the correct content
	downloadedContent, err := os.ReadFile(downloadPath)
	require.NoError(t, err)
	assert.Equal(t, testFileContent2, string(downloadedContent))
}

// putSemanticsCLIOriginConfig backs the CLI-level rows of the transfer
// semantics matrix.  The /nolist export withholds Listings so uploads can be
// exercised against a namespace whose destination pre-flight has nothing to
// answer with (row P10).
const putSemanticsCLIOriginConfig = `
Origin:
  StorageType: posixv2
  Exports:
    - FederationPrefix: /public
      Capabilities: ["PublicReads", "Writes", "Listings"]
    - FederationPrefix: /nolist
      Capabilities: ["PublicReads", "Writes"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`

// TestObjectPutSemanticsCLI pins the rows of
// docs/object-transfer-semantics.md that cmd/object_put.go implements rather
// than client.DoPut: filename inference into a collection (P3-cli), the
// multi-source container rules (P8, P9), a pre-flight that cannot answer
// (P10), and the flat layout a recursive upload has to keep (P6).
//
// Every subtest drives a command line that succeeds.  putMain reports failure
// by calling os.Exit, so failure paths cannot be asserted through rootCmd;
// they live in TestInferRemoteObjectName and in the library-level
// TestObjectTransferSemantics.
func TestObjectPutSemanticsCLI(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	ft := fed_test_utils.NewFedTest(t, putSemanticsCLIOriginConfig)
	require.NotNil(t, ft)
	require.Len(t, ft.Exports, 2)

	require.NoError(t, param.Logging_Client_DisableProgressBars.Set(true))

	publicStorage := ft.Exports[0].StoragePrefix
	nolistStorage := ft.Exports[1].StoragePrefix
	remoteBase := fmt.Sprintf("pelican://%s:%d",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetContext(context.TODO())
	})

	// Cobra keeps flag values between Execute calls, and putMain reports a
	// failed upload with os.Exit -- a stale --token left behind by another
	// test in this package would take the whole test binary down here.  Set
	// every flag this test depends on before each run rather than trusting
	// what the last caller left.
	runPut := func(t *testing.T, args ...string) {
		t.Helper()
		// Not "pack": Set marks a flag as Changed, and putMain reads
		// Changed("pack") to mean "an archive was requested".
		for name, value := range map[string]string{
			"token": "", "dest-token": "", "recursive": "false", "dry-run": "false",
		} {
			require.NoError(t, putCmd.Flags().Set(name, value))
		}
		// Cobra propagates the root's context to a subcommand only while
		// the subcommand's own context is nil (command.go: `if cmd.ctx ==
		// nil`).  Once any test in this package has executed `object put`,
		// putCmd holds that test's context for the life of the process, so
		// setting it on rootCmd alone would silently run against a
		// cancelled federation.  Set it where it is read.
		rootCmd.SetContext(ft.Ctx)
		putCmd.SetContext(ft.Ctx)
		rootCmd.SetArgs(append([]string{"object", "put"}, args...))
		defer rootCmd.SetArgs(nil)
		require.NoError(t, rootCmd.Execute())
	}

	writeLocal := func(t *testing.T, dir, name, contents string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte(contents), 0o644))
		return p
	}

	t.Run("P3_cli_put_file_to_existing_collection_infers_object_name", func(t *testing.T) {
		require.NoError(t, os.MkdirAll(filepath.Join(publicStorage, "p3-cli"), 0o755))

		src := writeLocal(t, t.TempDir(), "inferred.txt", "p3 body")
		runPut(t, src, remoteBase+"/public/p3-cli")

		got, err := os.ReadFile(filepath.Join(publicStorage, "p3-cli", "inferred.txt"))
		require.NoError(t, err, "P3-cli: the object name is inferred from the local basename")
		assert.Equal(t, "p3 body", string(got))
	})

	t.Run("P8_cli_multiple_sources_to_existing_collection", func(t *testing.T) {
		require.NoError(t, os.MkdirAll(filepath.Join(publicStorage, "p8-coll"), 0o755))

		local := t.TempDir()
		first := writeLocal(t, local, "p8-a.txt", "AAA")
		second := writeLocal(t, local, "p8-b.txt", "BBB")
		runPut(t, first, second, remoteBase+"/public/p8-coll")

		gotA, err := os.ReadFile(filepath.Join(publicStorage, "p8-coll", "p8-a.txt"))
		require.NoError(t, err, "P8: every source lands under the collection by its own basename")
		assert.Equal(t, "AAA", string(gotA))
		gotB, err := os.ReadFile(filepath.Join(publicStorage, "p8-coll", "p8-b.txt"))
		require.NoError(t, err,
			"P8: the second source must not collide with the first on the write-once check")
		assert.Equal(t, "BBB", string(gotB))
	})

	t.Run("P9_cli_multiple_sources_to_nonexistent_path", func(t *testing.T) {
		local := t.TempDir()
		first := writeLocal(t, local, "p9-a.txt", "A9")
		second := writeLocal(t, local, "p9-b.txt", "B9")
		runPut(t, first, second, remoteBase+"/public/p9-new")

		gotA, err := os.ReadFile(filepath.Join(publicStorage, "p9-new", "p9-a.txt"))
		require.NoError(t, err,
			"P9: several sources make the destination a container even when it does not exist yet")
		assert.Equal(t, "A9", string(gotA))
		gotB, err := os.ReadFile(filepath.Join(publicStorage, "p9-new", "p9-b.txt"))
		require.NoError(t, err)
		assert.Equal(t, "B9", string(gotB))
	})

	t.Run("P6_cli_recursive_query_param_keeps_flat_layout", func(t *testing.T) {
		// client.DoPut enables recursion from `?recursive` as well as from
		// the flag, so the CLI has to read the query too.  Taking the
		// inference branch for a recursive upload would nest the tree
		// under basename(local) and break the layout object sync depends
		// on.
		require.NoError(t, os.MkdirAll(filepath.Join(publicStorage, "p6-query"), 0o755))

		local := t.TempDir()
		writeLocal(t, local, "leaf.txt", "leaf")
		runPut(t, local, remoteBase+"/public/p6-query?recursive")

		got, err := os.ReadFile(filepath.Join(publicStorage, "p6-query", "leaf.txt"))
		require.NoError(t, err, "P6: ?recursive lays entries flat under the collection")
		assert.Equal(t, "leaf", string(got))

		_, err = os.Stat(filepath.Join(publicStorage, "p6-query", filepath.Base(local)))
		assert.True(t, os.IsNotExist(err),
			"P6: must NOT nest under basename(local); would regress object sync")
	})

	t.Run("P6_cli_recursive_with_multiple_sources_keeps_flat_layout", func(t *testing.T) {
		// Several sources normally force container semantics, but a
		// recursive upload has to stay flat regardless: each tree's
		// contents merge into the collection without its own basename.
		require.NoError(t, os.MkdirAll(filepath.Join(publicStorage, "p6-multi"), 0o755))

		firstTree := t.TempDir()
		writeLocal(t, firstTree, "from-first.txt", "first")
		secondTree := t.TempDir()
		writeLocal(t, secondTree, "from-second.txt", "second")

		runPut(t, "-r", firstTree, secondTree, remoteBase+"/public/p6-multi")

		for name, want := range map[string]string{"from-first.txt": "first", "from-second.txt": "second"} {
			got, err := os.ReadFile(filepath.Join(publicStorage, "p6-multi", name))
			require.NoError(t, err, "P6: recursive sources merge flat into the collection")
			assert.Equal(t, want, string(got))
		}
		for _, tree := range []string{firstTree, secondTree} {
			_, err := os.Stat(filepath.Join(publicStorage, "p6-multi", filepath.Base(tree)))
			assert.True(t, os.IsNotExist(err),
				"P6: recursive uploads must NOT nest under basename(local), even with several sources")
		}
	})

	t.Run("P10_cli_upload_survives_a_namespace_without_listings", func(t *testing.T) {
		// The /nolist export grants writes but no listings, so the
		// destination pre-flight has nothing useful to report.  That must
		// not stop the upload: the destination is used exactly as given.
		src := writeLocal(t, t.TempDir(), "p10.txt", "p10 body")
		runPut(t, src, remoteBase+"/nolist/p10-object.txt")

		got, err := os.ReadFile(filepath.Join(nolistStorage, "p10-object.txt"))
		require.NoError(t, err,
			"P10: a pre-flight that cannot answer leaves the destination as given")
		assert.Equal(t, "p10 body", string(got))
	})
}

// TestInferRemoteObjectName covers the destination rewrite in isolation,
// including the sources it has to refuse.  putMain exits the process on
// failure, so the refusals cannot be reached through rootCmd.
func TestInferRemoteObjectName(t *testing.T) {
	destURL, err := url.Parse("pelican://example.org/namespace/collection?directread")
	require.NoError(t, err)

	t.Run("appends the local basename", func(t *testing.T) {
		got, err := inferRemoteObjectName(destURL, "/data/local/file.txt")
		require.NoError(t, err)
		assert.Equal(t, "pelican://example.org/namespace/collection/file.txt?directread", got)
	})

	t.Run("ignores a trailing separator on the source", func(t *testing.T) {
		got, err := inferRemoteObjectName(destURL, "/data/local/dir/")
		require.NoError(t, err)
		assert.Equal(t, "pelican://example.org/namespace/collection/dir?directread", got)
	})

	t.Run("escapes a name that would otherwise change the URL", func(t *testing.T) {
		// A '?' in a filename must be escaped into the path rather than
		// starting a query string the origin would act on.
		got, err := inferRemoteObjectName(destURL, "/data/local/odd name?recursive")
		require.NoError(t, err)
		assert.Equal(t,
			"pelican://example.org/namespace/collection/odd%20name%3Frecursive?directread", got)
	})

	for _, localSource := range []string{"/data/tree/..", "..", ".", "/", ""} {
		t.Run(fmt.Sprintf("refuses %q", localSource), func(t *testing.T) {
			// path.Join cleans its result, so a ".." here would resolve to
			// the parent of the collection the caller named.
			_, err := inferRemoteObjectName(destURL, localSource)
			require.Error(t, err, "a source with no object name to infer must be refused")
			assert.Contains(t, err.Error(), "cannot infer a remote object name")
		})
	}
}
