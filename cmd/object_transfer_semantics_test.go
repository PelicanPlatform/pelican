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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// transferSemanticsOriginConfig sets up a POSIXv2 origin (no XRootD
// dependency) with recursive-listable public reads AND writes. This lets
// one federation power every row of the object-transfer semantics
// matrix that TestObjectTransferSemantics locks in.
const transferSemanticsOriginConfig = `
Origin:
  StorageType: posixv2
  Exports:
    - FederationPrefix: /test
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`

// TestObjectTransferSemantics locks in the current get/put source/dest
// x file/collection x recursive matrix.  Subtests are named after row
// IDs (G1..G7, P1..P7) so a failure points directly at the expectation
// that regressed.  The PR that introduces or changes any row should
// also update this table and the "Uploading to a Collection" section
// of docs/app/getting-data-with-pelican/client/page.mdx.
func TestObjectTransferSemantics(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	ft := fed_test_utils.NewFedTest(t, transferSemanticsOriginConfig)
	require.NotNil(t, ft)
	require.Greater(t, len(ft.Exports), 0)

	storage := ft.Exports[0].StoragePrefix
	remoteBase := fmt.Sprintf("pelican://%s:%d/test",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	// -----------------------------------------------------------------
	// GET: single source, --recursive=false
	// -----------------------------------------------------------------

	t.Run("G1_get_file_to_existing_regular_file_overwrites", func(t *testing.T) {
		require.NoError(t, os.WriteFile(filepath.Join(storage, "g1.txt"), []byte("hello g1"), 0o644))

		localDir := t.TempDir()
		localDst := filepath.Join(localDir, "existing.txt")
		require.NoError(t, os.WriteFile(localDst, []byte("PREV"), 0o644))

		_, err := client.DoGet(ft.Ctx, remoteBase+"/g1.txt", localDst, false)
		require.NoError(t, err)

		got, err := os.ReadFile(localDst)
		require.NoError(t, err)
		assert.Equal(t, "hello g1", string(got),
			"G1: single-object get to an existing regular file overwrites")
	})

	t.Run("G2_get_file_to_existing_directory_infers_filename", func(t *testing.T) {
		require.NoError(t, os.WriteFile(filepath.Join(storage, "g2.txt"), []byte("hello g2"), 0o644))

		localDir := t.TempDir()
		_, err := client.DoGet(ft.Ctx, remoteBase+"/g2.txt", localDir, false)
		require.NoError(t, err)

		got, err := os.ReadFile(filepath.Join(localDir, "g2.txt"))
		require.NoError(t, err, "G2: filename inferred from remote basename")
		assert.Equal(t, "hello g2", string(got))
	})

	t.Run("G3_get_file_to_nonexistent_path_uses_string_as_filename", func(t *testing.T) {
		require.NoError(t, os.WriteFile(filepath.Join(storage, "g3.txt"), []byte("hello g3"), 0o644))

		localDir := t.TempDir()
		localDst := filepath.Join(localDir, "renamed.txt")
		_, err := client.DoGet(ft.Ctx, remoteBase+"/g3.txt", localDst, false)
		require.NoError(t, err)

		got, err := os.ReadFile(localDst)
		require.NoError(t, err, "G3: dst string treated as filename when non-existent")
		assert.Equal(t, "hello g3", string(got))
	})

	t.Run("G4_get_collection_nonrecursive_errors", func(t *testing.T) {
		// After this PR: a `pelican object get <coll> <existing-dir>`
		// (i.e. the CLI-level container-target gesture) errors with a
		// message symmetric to the put-side "directory but recursive
		// is not enabled" guard. This is layered on top of DoGet by
		// the CLI's inferGetDestination helper; the library itself
		// still permits the flat call so sync/client_agent are
		// unaffected. Previously it silently wrote the origin's
		// WebDAV listing to a local file named after the collection.
		subdir := filepath.Join(storage, "g4-dir")
		require.NoError(t, os.MkdirAll(subdir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(subdir, "inside.txt"), []byte("inside"), 0o644))

		localDir := t.TempDir()
		_, err := inferGetDestination(ft.Ctx, remoteBase+"/g4-dir", localDir, false)
		require.Error(t, err,
			"G4: non-recursive get of a collection must error rather than silently succeed")
		assert.Contains(t, err.Error(), "is a collection but recursive is not enabled",
			"G4: error text is symmetric with the put-side directory guard")
	})

	// -----------------------------------------------------------------
	// GET: single source, --recursive=true
	// -----------------------------------------------------------------

	t.Run("G5_get_collection_recursive_nests_under_basename", func(t *testing.T) {
		// A recursive `pelican object get remote/g5-src LOCAL` (with
		// LOCAL an existing directory) places entries under
		// `LOCAL/g5-src/…`, matching `cp -r remote/ local/`. The
		// nesting is applied by the CLI's inferGetDestination helper;
		// the library DoGet call itself receives the pre-nested path.
		// This is the symmetric counterpart to P6 (put of a directory
		// into an existing remote collection).
		subdir := filepath.Join(storage, "g5-src")
		require.NoError(t, os.MkdirAll(subdir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(subdir, "a.txt"), []byte("A"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(subdir, "b.txt"), []byte("BB"), 0o644))

		localDir := t.TempDir()
		resolvedDest, err := inferGetDestination(ft.Ctx, remoteBase+"/g5-src", localDir, true)
		require.NoError(t, err)
		_, err = client.DoGet(ft.Ctx, remoteBase+"/g5-src", resolvedDest, true)
		require.NoError(t, err)

		gotA, err := os.ReadFile(filepath.Join(localDir, "g5-src", "a.txt"))
		require.NoError(t, err,
			"G5: recursive get nests entries under LOCAL/basename(remote)")
		assert.Equal(t, "A", string(gotA))
		gotB, err := os.ReadFile(filepath.Join(localDir, "g5-src", "b.txt"))
		require.NoError(t, err)
		assert.Equal(t, "BB", string(gotB))
	})

	t.Run("G6_get_collection_recursive_to_nonexistent_path_creates_and_nests", func(t *testing.T) {
		// When the destination doesn't yet exist, we treat that path
		// itself as the target container (destination string is the
		// collection name); entries land directly under it. This
		// matches how `cp -r remote/ new_local_dir/` behaves when
		// new_local_dir doesn't yet exist. inferGetDestination is a
		// no-op here (dest is not an existing directory), so this
		// asserts the library's default recursive behaviour.
		subdir := filepath.Join(storage, "g6-src")
		require.NoError(t, os.MkdirAll(subdir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(subdir, "only.txt"), []byte("only"), 0o644))

		localDir := t.TempDir()
		newDst := filepath.Join(localDir, "does-not-yet-exist")
		resolvedDest, err := inferGetDestination(ft.Ctx, remoteBase+"/g6-src", newDst, true)
		require.NoError(t, err)
		require.Equal(t, newDst, resolvedDest, "G6: no rewrite when dst doesn't yet exist")
		_, err = client.DoGet(ft.Ctx, remoteBase+"/g6-src", resolvedDest, true)
		require.NoError(t, err)

		got, err := os.ReadFile(filepath.Join(newDst, "only.txt"))
		require.NoError(t, err,
			"G6: recursive get creates the destination and places entries directly under it")
		assert.Equal(t, "only", string(got))
	})

	// -----------------------------------------------------------------
	// PUT: single source, --recursive=false
	// -----------------------------------------------------------------

	t.Run("P1_put_file_to_nonexistent_remote_uploads_as_is", func(t *testing.T) {
		localSrc := filepath.Join(t.TempDir(), "p1.txt")
		require.NoError(t, os.WriteFile(localSrc, []byte("hello p1"), 0o644))

		_, err := client.DoPut(ft.Ctx, localSrc, remoteBase+"/p1-remote.txt", false)
		require.NoError(t, err)

		// Read it back to confirm placement.
		got, err := os.ReadFile(filepath.Join(storage, "p1-remote.txt"))
		require.NoError(t, err, "P1: file uploaded to the exact URL provided")
		assert.Equal(t, "hello p1", string(got))
	})

	t.Run("P2_put_file_to_existing_remote_object_errors", func(t *testing.T) {
		// Seed the remote with an object.
		require.NoError(t, os.WriteFile(filepath.Join(storage, "p2.txt"), []byte("EXISTING"), 0o644))

		localSrc := filepath.Join(t.TempDir(), "p2.txt")
		require.NoError(t, os.WriteFile(localSrc, []byte("SHOULD NOT LAND"), 0o644))

		_, err := client.DoPut(ft.Ctx, localSrc, remoteBase+"/p2.txt", false)
		require.Error(t, err,
			"P2: uploading over an existing remote object must error (write-once)")
		assert.Contains(t, strings.ToLower(err.Error()), "already exists",
			"P2: error must mention already-exists so callers can distinguish this case")
	})

	// P3 is the library-level pin for the row PR #2970 targets. Note
	// that PR #2970 only adds the inference at the CLI level
	// (cmd/object_put.go); client.DoPut still errors "already exists"
	// even after the PR. So this test's expectation does NOT change
	// when the PR is applied. The CLI side is pinned by
	// TestObjectPutToDirectoryInfersFilename in object_put_test.go
	// (shipped as part of the PR).
	t.Run("P3_put_file_to_existing_remote_collection_currently_errors", func(t *testing.T) {
		// Seed the remote with a collection.
		require.NoError(t, os.MkdirAll(filepath.Join(storage, "p3-dir"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(storage, "p3-dir", "sentinel"), []byte("keep"), 0o644))

		localSrc := filepath.Join(t.TempDir(), "p3.txt")
		require.NoError(t, os.WriteFile(localSrc, []byte("SHOULD NOT LAND ON MAIN"), 0o644))

		_, err := client.DoPut(ft.Ctx, localSrc, remoteBase+"/p3-dir", false)
		require.Error(t, err,
			"P3 (current main): DoPut has no filename inference for a collection dest -- fails already-exists")
		// The exact wording is origin-driven; assert the core token.
		assert.Contains(t, strings.ToLower(err.Error()), "already exists",
			"P3 (current main): error surfaces the collection-vs-object conflict as already-exists")
		// The sentinel must be untouched -- the failed upload should not
		// have overwritten anything.
		got, err := os.ReadFile(filepath.Join(storage, "p3-dir", "sentinel"))
		require.NoError(t, err)
		assert.Equal(t, "keep", string(got))
	})

	t.Run("P4_put_directory_nonrecursive_errors_client_side", func(t *testing.T) {
		localSrc := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(localSrc, "leaf.txt"), []byte("x"), 0o644))

		_, err := client.DoPut(ft.Ctx, localSrc, remoteBase+"/p4-anything", false)
		require.Error(t, err,
			"P4: uploading a local directory without --recursive must error client-side")
		assert.Contains(t, err.Error(), "is a directory but recursive is not enabled",
			"P4: expected phrase surfaces from client.DoPut")
	})

	// -----------------------------------------------------------------
	// PUT: single source, --recursive=true
	// -----------------------------------------------------------------

	t.Run("P5_put_directory_recursive_to_nonexistent_remote_creates_tree", func(t *testing.T) {
		localSrc := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(localSrc, "leaf1.txt"), []byte("leaf1"), 0o644))
		nested := filepath.Join(localSrc, "sub")
		require.NoError(t, os.MkdirAll(nested, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(nested, "leaf2.txt"), []byte("leaf2"), 0o644))

		_, err := client.DoPut(ft.Ctx, localSrc, remoteBase+"/p5-tree", true)
		require.NoError(t, err)

		got1, err := os.ReadFile(filepath.Join(storage, "p5-tree", "leaf1.txt"))
		require.NoError(t, err)
		assert.Equal(t, "leaf1", string(got1))
		got2, err := os.ReadFile(filepath.Join(storage, "p5-tree", "sub", "leaf2.txt"))
		require.NoError(t, err)
		assert.Equal(t, "leaf2", string(got2))
	})
}
