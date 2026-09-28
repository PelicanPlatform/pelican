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

package xrootd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// TestDeleteTestFileConfined pins that the cache self-test cleanup only ever
// removes files strictly inside the self-test directory.  The prefix check
// has to run on the cleaned path: path.Join resolves "..", so checking the
// raw path and then joining would let "<selfTestDir>/../../x" escape.
func TestDeleteTestFileConfined(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	base := t.TempDir()
	require.NoError(t, param.Cache_NamespaceLocation.Set(base))

	selfTestPath := filepath.Join(base, selfTestDir)
	require.NoError(t, os.MkdirAll(selfTestPath, 0755))

	writePair := func(p string) {
		require.NoError(t, os.WriteFile(p, []byte("x"), 0644))
		require.NoError(t, os.WriteFile(p+".cinfo", []byte("x"), 0644))
	}
	exists := func(p string) bool {
		_, err := os.Lstat(p)
		return err == nil
	}

	t.Run("genuine self-test file is removed", func(t *testing.T) {
		okPath := filepath.Join(selfTestPath, "ok.txt")
		writePair(okPath)
		require.NoError(t, deleteTestFile("https://cache.example.org:8443"+selfTestDir+"/ok.txt"))
		assert.False(t, exists(okPath))
		assert.False(t, exists(okPath+".cinfo"))
	})

	t.Run("dot-dot traversal is refused", func(t *testing.T) {
		victim := filepath.Join(base, "victim.txt")
		writePair(victim)
		err := deleteTestFile("https://cache.example.org:8443" + selfTestDir + "/../../../victim.txt")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a valid self-test path")
		assert.True(t, exists(victim), "victim must survive")
		assert.True(t, exists(victim+".cinfo"), "victim cinfo must survive")
	})

	t.Run("sibling directory sharing the prefix is refused", func(t *testing.T) {
		siblingDir := filepath.Join(base, selfTestDir+"-other")
		require.NoError(t, os.MkdirAll(siblingDir, 0755))
		sibling := filepath.Join(siblingDir, "x.txt")
		writePair(sibling)
		err := deleteTestFile("https://cache.example.org:8443" + selfTestDir + "-other/x.txt")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a valid self-test path")
		assert.True(t, exists(sibling))
		assert.True(t, exists(sibling+".cinfo"))
	})

	t.Run("the self-test directory itself is refused", func(t *testing.T) {
		err := deleteTestFile("https://cache.example.org:8443" + selfTestDir)
		require.Error(t, err)
		assert.True(t, exists(selfTestPath))
	})
}
