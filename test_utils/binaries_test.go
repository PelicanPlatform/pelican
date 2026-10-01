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

package test_utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookupPrebuiltBinary(t *testing.T) {
	const envVar = "TEST_PELICAN_LOOKUP_PREBUILT_BINARY"

	t.Run("unset", func(t *testing.T) {
		// t.Setenv restores the variable when the test ends.
		t.Setenv(envVar, "")
		require.NoError(t, os.Unsetenv(envVar))
		path, ok, err := lookupPrebuiltBinary(envVar)
		assert.NoError(t, err)
		assert.False(t, ok)
		assert.Empty(t, path)
	})

	t.Run("existing", func(t *testing.T) {
		bin := filepath.Join(t.TempDir(), "pelican")
		require.NoError(t, os.WriteFile(bin, nil, 0755))
		t.Setenv(envVar, bin)
		path, ok, err := lookupPrebuiltBinary(envVar)
		assert.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, bin, path)
	})

	t.Run("missing", func(t *testing.T) {
		t.Setenv(envVar, filepath.Join(t.TempDir(), "pelican"))
		_, ok, err := lookupPrebuiltBinary(envVar)
		assert.Error(t, err)
		assert.True(t, ok)
	})

	t.Run("relative", func(t *testing.T) {
		t.Setenv(envVar, "pelican")
		_, ok, err := lookupPrebuiltBinary(envVar)
		assert.ErrorContains(t, err, "not an absolute path")
		assert.True(t, ok)
	})
}
