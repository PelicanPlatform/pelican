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

package local_cache

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseStorageDirsConfig(t *testing.T) {
	t.Run("Unset", func(t *testing.T) {
		viper.Reset()
		dirs, err := ParseStorageDirsConfig()
		require.NoError(t, err)
		assert.Nil(t, dirs)
	})

	t.Run("EmptyList", func(t *testing.T) {
		viper.Reset()
		viper.Set("LocalCache.StorageDirs", []interface{}{})
		dirs, err := ParseStorageDirsConfig()
		require.NoError(t, err)
		assert.Nil(t, dirs)
	})

	t.Run("StringList", func(t *testing.T) {
		viper.Reset()
		viper.Set("LocalCache.StorageDirs", []interface{}{"/mnt/cache1", "/mnt/cache2"})
		dirs, err := ParseStorageDirsConfig()
		require.NoError(t, err)
		require.Len(t, dirs, 2)
		assert.Equal(t, "/mnt/cache1", dirs[0].Path)
		assert.Equal(t, uint64(0), dirs[0].MaxSize)
		assert.Equal(t, "/mnt/cache2", dirs[1].Path)
	})

	t.Run("StringSliceNative", func(t *testing.T) {
		viper.Reset()
		viper.Set("LocalCache.StorageDirs", []string{"/a", "/b"})
		dirs, err := ParseStorageDirsConfig()
		require.NoError(t, err)
		require.Len(t, dirs, 2)
		assert.Equal(t, "/a", dirs[0].Path)
		assert.Equal(t, "/b", dirs[1].Path)
	})

	t.Run("StructuredEntries", func(t *testing.T) {
		viper.Reset()
		viper.Set("LocalCache.StorageDirs", []interface{}{
			map[string]interface{}{
				"Path":                    "/mnt/nvme",
				"MaxSize":                 "500GB",
				"HighWaterMarkPercentage": 95,
				"LowWaterMarkPercentage":  85,
			},
			map[string]interface{}{
				"Path":    "/mnt/hdd",
				"MaxSize": "2TB",
			},
		})
		dirs, err := ParseStorageDirsConfig()
		require.NoError(t, err)
		require.Len(t, dirs, 2)

		assert.Equal(t, "/mnt/nvme", dirs[0].Path)
		assert.Equal(t, uint64(500*1024*1024*1024), dirs[0].MaxSize)
		assert.Equal(t, 95, dirs[0].HighWaterMarkPercentage)
		assert.Equal(t, 85, dirs[0].LowWaterMarkPercentage)

		assert.Equal(t, "/mnt/hdd", dirs[1].Path)
		assert.Equal(t, uint64(2*1024*1024*1024*1024), dirs[1].MaxSize)
		assert.Equal(t, 0, dirs[1].HighWaterMarkPercentage)
	})

	t.Run("NumericMaxSize", func(t *testing.T) {
		viper.Reset()
		viper.Set("LocalCache.StorageDirs", []interface{}{
			map[string]interface{}{
				"Path":    "/data",
				"MaxSize": 1073741824, // 1 GiB as integer
			},
		})
		dirs, err := ParseStorageDirsConfig()
		require.NoError(t, err)
		require.Len(t, dirs, 1)
		assert.Equal(t, uint64(1073741824), dirs[0].MaxSize)
	})

	t.Run("LowercaseKeys", func(t *testing.T) {
		viper.Reset()
		viper.Set("LocalCache.StorageDirs", []interface{}{
			map[string]interface{}{
				"path":                    "/lower",
				"maxsize":                 "10GB",
				"highwatermarkpercentage": 90,
				"lowwatermarkpercentage":  80,
			},
		})
		dirs, err := ParseStorageDirsConfig()
		require.NoError(t, err)
		require.Len(t, dirs, 1)
		assert.Equal(t, "/lower", dirs[0].Path)
		assert.Equal(t, uint64(10*1024*1024*1024), dirs[0].MaxSize)
		assert.Equal(t, 90, dirs[0].HighWaterMarkPercentage)
		assert.Equal(t, 80, dirs[0].LowWaterMarkPercentage)
	})

	t.Run("MissingPath", func(t *testing.T) {
		viper.Reset()
		viper.Set("LocalCache.StorageDirs", []interface{}{
			map[string]interface{}{"MaxSize": "10GB"},
		})
		_, err := ParseStorageDirsConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing or empty Path")
	})

	t.Run("EmptyStringPath", func(t *testing.T) {
		viper.Reset()
		viper.Set("LocalCache.StorageDirs", []interface{}{""})
		_, err := ParseStorageDirsConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty path")
	})

	t.Run("InvalidMaxSize", func(t *testing.T) {
		viper.Reset()
		viper.Set("LocalCache.StorageDirs", []interface{}{
			map[string]interface{}{
				"Path":    "/data",
				"MaxSize": "notasize",
			},
		})
		_, err := ParseStorageDirsConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "MaxSize")
	})

	t.Run("YAMLMapInterfaceInterface", func(t *testing.T) {
		// Simulate the map[interface{}]interface{} that raw YAML sometimes produces
		viper.Reset()
		viper.Set("LocalCache.StorageDirs", []interface{}{
			map[interface{}]interface{}{
				"Path":    "/yaml-style",
				"MaxSize": "100GB",
			},
		})
		dirs, err := ParseStorageDirsConfig()
		require.NoError(t, err)
		require.Len(t, dirs, 1)
		assert.Equal(t, "/yaml-style", dirs[0].Path)
		assert.Equal(t, uint64(100*1024*1024*1024), dirs[0].MaxSize)
	})
}
