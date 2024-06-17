/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package cache

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

func TestCheckCacheSentinelLocation(t *testing.T) {
	t.Run("sentinel-not-set", func(t *testing.T) {
		viper.Reset()
		err := CheckCacheSentinelLocation()
		assert.NoError(t, err)
	})

	t.Run("sentinel-contains-dir", func(t *testing.T) {
		viper.Reset()
		viper.Set(param.Cache_SentinelLocation.GetName(), "/test.txt")
		err := CheckCacheSentinelLocation()
		require.Error(t, err)
		assert.Equal(t, "invalid Cache.SentinelLocation path. File must not contain a directory. Got /test.txt", err.Error())
	})

	t.Run("sentinel-dne", func(t *testing.T) {
		tmpDir := t.TempDir()
		viper.Reset()
		viper.Set(param.Cache_SentinelLocation.GetName(), "test.txt")
		viper.Set(param.Cache_LocalRoot.GetName(), tmpDir)
		err := CheckCacheSentinelLocation()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open Cache.SentinelLocation")
	})

	t.Run("sentinel-exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		viper.Reset()

		viper.Set(param.Cache_SentinelLocation.GetName(), "test.txt")
		viper.Set(param.Cache_LocalRoot.GetName(), tmpDir)

		file, err := os.Create(filepath.Join(tmpDir, "test.txt"))
		require.NoError(t, err)
		file.Close()

		err = CheckCacheSentinelLocation()
		require.NoError(t, err)
	})
}
