//go:build !windows

/***************************************************************
*
* Copyright (C) 2024, University of Nebraska-Lincoln
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

package common

import (
	_ "embed"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	//go:embed resources/env-var-mimic.yml
	envVarMimicConfig string

	//go:embed resources/multi-export-valid.yml
	multiExportValidConfig string

	//go:embed resources/single-export-block.yml
	singleExportBlockConfig string

	//go:embed resources/export-volumes-valid.yml
	exportVolumesValidConfig string

	//go:embed resources/single-export-volume.yml
	exportSingleVolumeConfig string
)

func setup(t *testing.T, config string) []OriginExports {
	viper.SetConfigType("yaml")
	// Use viper to read in the embedded config
	err := viper.ReadConfig(strings.NewReader(config))
	require.NoError(t, err, "error reading config")
	// Now call GetOriginExports and check the struct
	exports, err := GetOriginExports()
	require.NoError(t, err, "error getting origin exports")
	return exports
}

// Note that this test really doesn't actually test env var configuration. Rather, it
// tests an origin configuration that mimics what you could do with env vars due to the
// fact that we don't use a yaml list
func TestGetExports(t *testing.T) {
	viper.Reset()
	ResetOriginExports()

	t.Run("testSingleExportValid", func(t *testing.T) {
		defer viper.Reset()
		defer ResetOriginExports()
		// viper.SetConfigType("yaml")
		// // Use viper to read in the embedded config
		// err := viper.ReadConfig(strings.NewReader(singleExportValidConfig))
		// require.NoError(t, err, "error reading config")
		// // Now call GetOriginExports and check the struct
		// exports, err := GetOriginExports()
		// require.NoError(t, err, "error getting origin exports")
		exports := setup(t, envVarMimicConfig)

		assert.Len(t, exports, 1, "expected 1 export")
		assert.Equal(t, "/foo", exports[0].StoragePrefix, "expected /foo")

		assert.False(t, exports[0].Capabilities.Writes, "expected no writes")
		assert.True(t, exports[0].Capabilities.PublicReads, "expected public reads")
		assert.False(t, exports[0].Capabilities.Listings, "expected no listings")
		assert.True(t, exports[0].Capabilities.DirectReads, "expected direct reads")
	})

	t.Run("testMultiExportValid", func(t *testing.T) {
		defer viper.Reset()
		defer ResetOriginExports()
		exports := setup(t, multiExportValidConfig)
		assert.Len(t, exports, 2, "expected 2 exports")

		expectedExport1 := OriginExports{
			StoragePrefix:    "/test1",
			FederationPrefix: "/first/namespace",
			Capabilities: Capabilities{
				Writes:      true,
				PublicReads: true,
				Listings:    true,
				Reads:       true,
				DirectReads: true,
			},
		}
		assert.Equal(t, expectedExport1, exports[0])

		expectedExport2 := OriginExports{
			StoragePrefix:    "/test2",
			FederationPrefix: "/second/namespace",
			Capabilities: Capabilities{
				Writes:      true,
				PublicReads: false,
				Listings:    false,
				Reads:       false,
				DirectReads: false,
			},
		}
		assert.Equal(t, expectedExport2, exports[1])
	})

	t.Run("testExportVolumesValid", func(t *testing.T) {
		defer viper.Reset()
		defer ResetOriginExports()
		exports := setup(t, exportVolumesValidConfig)
		assert.Len(t, exports, 2, "expected 2 exports")

		expectedExport1 := OriginExports{
			StoragePrefix:    "/test1",
			FederationPrefix: "/first/namespace",
			Capabilities: Capabilities{
				Writes:      false,
				PublicReads: false,
				Listings:    true,
				Reads:       true,
				DirectReads: true,
			},
		}
		assert.Equal(t, expectedExport1, exports[0])

		expectedExport2 := OriginExports{
			StoragePrefix:    "/test2",
			FederationPrefix: "/second/namespace",
			Capabilities: Capabilities{
				Writes:      false,
				PublicReads: false,
				Listings:    true,
				Reads:       true,
				DirectReads: true,
			},
		}
		assert.Equal(t, expectedExport2, exports[1])
	})

	// When we have a single export volume, we also set a few viper variables that can be
	// used by sections of code that assume a single export. Test that those are set properly
	t.Run("testExportVolumesSingle", func(t *testing.T) {
		defer viper.Reset()
		defer ResetOriginExports()
		exports := setup(t, exportSingleVolumeConfig)
		assert.Len(t, exports, 1, "expected 1 export")

		expectedExport := OriginExports{
			StoragePrefix:    "/test1",
			FederationPrefix: "/first/namespace",
			Capabilities: Capabilities{
				Writes:      true,
				PublicReads: true,
				Listings:    false,
				Reads:       true,
				DirectReads: false,
			},
		}
		assert.Equal(t, expectedExport, exports[0])

		// Now check that we properly set the other viper vars we should have
		assert.Equal(t, "/test1", viper.GetString("Origin.StoragePrefix"))
		assert.Equal(t, "/first/namespace", viper.GetString("Origin.FederationPrefix"))
		assert.True(t, viper.GetBool("Origin.EnableReads"))
		assert.True(t, viper.GetBool("Origin.EnableWrites"))
		assert.True(t, viper.GetBool("Origin.EnablePublicReads"))
		assert.False(t, viper.GetBool("Origin.EnableListings"))
		assert.False(t, viper.GetBool("Origin.EnableDirectReads"))
	})

	t.Run("testSingleExportBlock", func(t *testing.T) {
		defer viper.Reset()
		defer ResetOriginExports()
		exports := setup(t, singleExportBlockConfig)
		assert.Len(t, exports, 1, "expected 1 export")

		expectedExport := OriginExports{
			StoragePrefix:    "/test1",
			FederationPrefix: "/first/namespace",
			Capabilities: Capabilities{
				Writes:      false,
				PublicReads: true,
				Listings:    false,
				Reads:       true,
				DirectReads: true,
			},
		}
		assert.Equal(t, expectedExport, exports[0])

		// Now check that we properly set the other viper vars we should have
		assert.Equal(t, "/test1", viper.GetString("Origin.StoragePrefix"))
		assert.Equal(t, "/first/namespace", viper.GetString("Origin.FederationPrefix"))
		assert.True(t, viper.GetBool("Origin.EnableReads"))
		assert.False(t, viper.GetBool("Origin.EnableWrites"))
		assert.True(t, viper.GetBool("Origin.EnablePublicReads"))
		assert.False(t, viper.GetBool("Origin.EnableListings"))
		assert.True(t, viper.GetBool("Origin.EnableDirectReads"))
	})

	t.Run("testInvalidExport", func(t *testing.T) {
		viper.Reset()
		defer ResetOriginExports()

		viper.Set("Origin.StorageType", "posix")
		viper.Set("Origin.ExportVolumes", "")
		_, err := GetOriginExports()
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidOriginConfig)

		viper.Reset()
		viper.Set("Origin.StorageType", "posix")
		viper.Set("Origin.ExportVolumes", "foo")
		_, err = GetOriginExports()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidOriginConfig)

		viper.Reset()
		viper.Set("Origin.StorageType", "blah")
		_, err = GetOriginExports()
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrUnknownOriginStorageType)
	})
}
