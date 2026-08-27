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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// walkStreamingOriginConfig sets up a POSIXv2 origin (no XRootD dependency)
// with recursive-listable public reads. NewFedTest overrides StoragePrefix
// with its own tempdir, so we write the test tree into
// ft.Exports[0].StoragePrefix *after* NewFedTest returns.
const walkStreamingOriginConfig = `
Origin:
  StorageType: posixv2
  Exports:
    - FederationPrefix: /test
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`

// TestWalkStreamingAPI is an integration check for the streaming client
// listing APIs (client.Walk + client.WalkSeq + client.SkipSubtree +
// client.SkipAll) end-to-end against a live POSIXv2 fed. It's deliberately
// POSIXv2-only so the test doesn't need XRootD on the runner.
func TestWalkStreamingAPI(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	ft := fed_test_utils.NewFedTest(t, walkStreamingOriginConfig)
	require.NotNil(t, ft)
	require.Greater(t, len(ft.Exports), 0)

	// Layout under ft.Exports[0].StoragePrefix:
	//   file_a.txt          10 bytes
	//   file_b.txt          20 bytes
	//   sub/nested.txt      40 bytes
	//   sub/deeper/deep.txt 80 bytes
	//
	// (NewFedTest pre-seeds a hello_world.txt at the storage root -- we
	// ignore it below since the wantEntries set is explicit.)
	storage := ft.Exports[0].StoragePrefix
	require.NoError(t, os.WriteFile(filepath.Join(storage, "file_a.txt"), []byte("aaaaaaaaaa"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(storage, "file_b.txt"), []byte("bbbbbbbbbbbbbbbbbbbb"), 0o644))
	sub := filepath.Join(storage, "sub")
	require.NoError(t, os.Mkdir(sub, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "nested.txt"), []byte("nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn"), 0o644))
	deeper := filepath.Join(sub, "deeper")
	require.NoError(t, os.Mkdir(deeper, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(deeper, "deep.txt"), []byte("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"), 0o644))

	root := fmt.Sprintf("pelican://%s:%d/test/",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	// Every path we placed in the fed. NewFedTest also drops a hello_world.txt
	// at the storage root that we don't attempt to enumerate here -- we check
	// membership rather than strict equality.
	wantEntries := []string{
		"/test/file_a.txt",
		"/test/file_b.txt",
		"/test/sub",
		"/test/sub/deeper",
		"/test/sub/deeper/deep.txt",
		"/test/sub/nested.txt",
	}
	// Sum of the object sizes we planted, keyed for quick lookup.
	sizes := map[string]int64{
		"/test/file_a.txt":          10,
		"/test/file_b.txt":          20,
		"/test/sub/nested.txt":      40,
		"/test/sub/deeper/deep.txt": 80,
	}

	t.Run("Walk-visits-full-subtree-with-real-sizes", func(t *testing.T) {
		got := map[string]int64{}
		require.NoError(t, client.Walk(ft.Ctx, root, func(info client.FileInfo, err error) error {
			require.NoError(t, err, "no per-subtree failure expected on this fed")
			got[info.Name] = info.Size
			return nil
		}, client.WithRecursive(true)))

		for _, p := range wantEntries {
			assert.Contains(t, got, p, "Walk must visit %q", p)
		}
		for p, want := range sizes {
			assert.Equal(t, want, got[p], "Size for %q must match on-disk bytes", p)
		}
	})

	t.Run("WalkSeq-yields-same-set-and-honors-early-break", func(t *testing.T) {
		seen := map[string]bool{}
		for info, err := range client.WalkSeq(ft.Ctx, root, client.WithRecursive(true)) {
			require.NoError(t, err)
			seen[info.Name] = true
		}
		for _, p := range wantEntries {
			assert.True(t, seen[p], "WalkSeq must yield %q", p)
		}

		// Early break: consume only two entries and verify the loop actually
		// exits. A callback-based walker means there's no producer goroutine
		// to leak, but we still want confirmation the break unwinds cleanly.
		count := 0
		for range client.WalkSeq(ft.Ctx, root, client.WithRecursive(true)) {
			count++
			if count == 2 {
				break
			}
		}
		assert.Equal(t, 2, count)
	})

	t.Run("SkipSubtree-prunes-the-sub-tree-from-Walk", func(t *testing.T) {
		var got []string
		require.NoError(t, client.Walk(ft.Ctx, root, func(info client.FileInfo, err error) error {
			require.NoError(t, err)
			got = append(got, info.Name)
			if info.Name == "/test/sub" && info.IsCollection {
				return client.SkipSubtree
			}
			return nil
		}, client.WithRecursive(true)))
		assert.Contains(t, got, "/test/sub", "the collection we skipped must still be reported once")
		assert.Contains(t, got, "/test/file_a.txt")
		assert.NotContains(t, got, "/test/sub/nested.txt",
			"SkipSubtree on /test/sub must prune all descendants")
		assert.NotContains(t, got, "/test/sub/deeper")
		assert.NotContains(t, got, "/test/sub/deeper/deep.txt")
	})

	t.Run("SkipAll-ends-the-walk-cleanly", func(t *testing.T) {
		count := 0
		err := client.Walk(ft.Ctx, root, func(info client.FileInfo, err error) error {
			require.NoError(t, err)
			count++
			return client.SkipAll
		}, client.WithRecursive(true))
		require.NoError(t, err, "SkipAll must not surface as an error to callers")
		assert.Equal(t, 1, count)
	})

	t.Run("real-error-from-callback-propagates", func(t *testing.T) {
		want := errors.New("caller aborted")
		err := client.Walk(ft.Ctx, root, func(client.FileInfo, error) error {
			return want
		}, client.WithRecursive(true))
		require.Error(t, err)
		assert.ErrorIs(t, err, want,
			"a non-sentinel error from the callback must reach the caller intact")
	})
}
