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

package server_utils

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/server_structs"
)

var (
	//go:embed resources/posix-origins/env-var-mimic.yml
	envVarMimicConfig string

	//go:embed resources/posix-origins/multi-export-valid.yml
	multiExportValidConfig string

	//go:embed resources/posix-origins/single-export-block.yml
	singleExportBlockConfig string

	//go:embed resources/posix-origins/export-volumes-valid.yml
	exportVolumesValidConfig string

	//go:embed resources/posix-origins/single-export-volume.yml
	exportSingleVolumeConfig string

	//go:embed resources/s3-origins/env-var-mimic.yml
	s3envVarMimicConfig string

	//go:embed resources/s3-origins/multi-export-valid.yml
	s3multiExportValidConfig string

	//go:embed resources/s3-origins/single-export-block.yml
	s3singleExportBlockConfig string

	//go:embed resources/s3-origins/export-volumes-valid.yml
	s3exportVolumesValidConfig string

	//go:embed resources/s3-origins/single-export-volume.yml
	s3exportSingleVolumeConfig string
)

func setup(t *testing.T, config string) []OriginExport {
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

	// Posix tests
	t.Run("testSingleExportValid", func(t *testing.T) {
		defer viper.Reset()
		defer ResetOriginExports()
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

		expectedExport1 := OriginExport{
			StoragePrefix:    "/test1",
			FederationPrefix: "/first/namespace",
			Capabilities: server_structs.Capabilities{
				Writes:      true,
				PublicReads: true,
				Listings:    true,
				Reads:       true,
				DirectReads: true,
			},
		}
		assert.Equal(t, expectedExport1, exports[0])

		expectedExport2 := OriginExport{
			StoragePrefix:    "/test2",
			FederationPrefix: "/second/namespace",
			Capabilities: server_structs.Capabilities{
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

		expectedExport1 := OriginExport{
			StoragePrefix:    "/test1",
			FederationPrefix: "/first/namespace",
			Capabilities: server_structs.Capabilities{
				Writes:      false,
				PublicReads: false,
				Listings:    true,
				Reads:       true,
				DirectReads: true,
			},
		}
		assert.Equal(t, expectedExport1, exports[0])

		expectedExport2 := OriginExport{
			StoragePrefix:    "/test2",
			FederationPrefix: "/second/namespace",
			Capabilities: server_structs.Capabilities{
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

		expectedExport := OriginExport{
			StoragePrefix:    "/test1",
			FederationPrefix: "/first/namespace",
			Capabilities: server_structs.Capabilities{
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

		expectedExport := OriginExport{
			StoragePrefix:    "/test1",
			FederationPrefix: "/first/namespace",
			Capabilities: server_structs.Capabilities{
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
		defer viper.Reset()
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

	// S3 tests
	t.Run("testSingleExportValidS3", func(t *testing.T) {
		defer viper.Reset()
		defer ResetOriginExports()

		exports := setup(t, s3envVarMimicConfig)

		assert.Len(t, exports, 1, "expected 1 export")
		assert.Equal(t, "/my/namespace", exports[0].FederationPrefix, "expected /my/namespace")
		assert.Equal(t, "my-bucket", exports[0].S3Bucket, "expected my-bucket")
		assert.Equal(t, "/path/to/access.key", exports[0].S3AccessKeyfile, "expected /path/to/access.key")
		assert.Equal(t, "/path/to/secret.key", exports[0].S3SecretKeyfile, "expected /path/to/secret.key")

		assert.False(t, exports[0].Capabilities.Writes, "expected no writes")
		assert.True(t, exports[0].Capabilities.PublicReads, "expected public reads")
		assert.False(t, exports[0].Capabilities.Listings, "expected no listings")
		assert.True(t, exports[0].Capabilities.DirectReads, "expected direct reads")
	})

	t.Run("testMultiExportValidS3", func(t *testing.T) {
		defer viper.Reset()
		defer ResetOriginExports()
		exports := setup(t, s3multiExportValidConfig)
		assert.Len(t, exports, 2, "expected 2 exports")

		expectedExport1 := OriginExport{
			S3Bucket:         "first-bucket",
			FederationPrefix: "/first/namespace",
			Capabilities: server_structs.Capabilities{
				Writes:      true,
				PublicReads: true,
				Listings:    true,
				Reads:       true,
				DirectReads: true,
			},
		}
		assert.Equal(t, expectedExport1, exports[0])

		expectedExport2 := OriginExport{
			S3Bucket:         "second-bucket",
			S3AccessKeyfile:  "/path/to/second/access.key",
			S3SecretKeyfile:  "/path/to/second/secret.key",
			FederationPrefix: "/second/namespace",
			Capabilities: server_structs.Capabilities{
				Writes:      true,
				PublicReads: false,
				Listings:    false,
				Reads:       false,
				DirectReads: false,
			},
		}
		assert.Equal(t, expectedExport2, exports[1])
	})

	t.Run("testExportVolumesValidS3", func(t *testing.T) {
		defer viper.Reset()
		defer ResetOriginExports()
		exports := setup(t, s3exportVolumesValidConfig)
		assert.Len(t, exports, 2, "expected 2 exports")

		expectedExport1 := OriginExport{
			StoragePrefix:    "/",
			S3Bucket:         "",
			FederationPrefix: "/first/namespace",
			Capabilities: server_structs.Capabilities{
				Writes:      false,
				PublicReads: false,
				Listings:    true,
				Reads:       true,
				DirectReads: true,
			},
		}
		assert.Equal(t, expectedExport1, exports[0])

		expectedExport2 := OriginExport{
			StoragePrefix:    "/",
			S3Bucket:         "my-bucket",
			FederationPrefix: "/second/namespace",
			Capabilities: server_structs.Capabilities{
				Writes:      false,
				PublicReads: false,
				Listings:    true,
				Reads:       true,
				DirectReads: true,
			},
		}
		assert.Equal(t, expectedExport2, exports[1])
	})

	t.Run("testExportVolumesSingleS3", func(t *testing.T) {
		defer viper.Reset()
		defer ResetOriginExports()
		exports := setup(t, s3exportSingleVolumeConfig)
		assert.Len(t, exports, 1, "expected 1 export")

		expectedExport := OriginExport{
			StoragePrefix:    "/",
			S3Bucket:         "my-bucket",
			S3AccessKeyfile:  "/path/to/access.key",
			S3SecretKeyfile:  "/path/to/secret.key",
			FederationPrefix: "/first/namespace",
			Capabilities: server_structs.Capabilities{
				Writes:      true,
				PublicReads: true,
				Listings:    false,
				Reads:       true,
				DirectReads: false,
			},
		}
		assert.Equal(t, expectedExport, exports[0])

		// Now check that we properly set the other viper vars we should have
		assert.Equal(t, "my-bucket", viper.GetString("Origin.S3Bucket"))
		assert.Equal(t, "/path/to/access.key", viper.GetString("Origin.S3AccessKeyfile"))
		assert.Equal(t, "/path/to/secret.key", viper.GetString("Origin.S3SecretKeyfile"))
		assert.Equal(t, "/first/namespace", viper.GetString("Origin.FederationPrefix"))
		assert.True(t, viper.GetBool("Origin.EnableReads"))
		assert.True(t, viper.GetBool("Origin.EnableWrites"))
		assert.True(t, viper.GetBool("Origin.EnablePublicReads"))
		assert.False(t, viper.GetBool("Origin.EnableListings"))
		assert.False(t, viper.GetBool("Origin.EnableDirectReads"))
	})

	t.Run("testSingleExportBlockS3", func(t *testing.T) {
		defer viper.Reset()
		defer ResetOriginExports()
		exports := setup(t, s3singleExportBlockConfig)
		assert.Len(t, exports, 1, "expected 1 export")

		expectedExport := OriginExport{
			S3Bucket:         "my-bucket",
			S3AccessKeyfile:  "/path/to/access.key",
			S3SecretKeyfile:  "/path/to/secret.key",
			FederationPrefix: "/first/namespace",
			Capabilities: server_structs.Capabilities{
				Writes:      false,
				PublicReads: true,
				Listings:    false,
				Reads:       true,
				DirectReads: true,
			},
		}
		assert.Equal(t, expectedExport, exports[0])

		// Now check that we properly set the other viper vars we should have
		assert.Equal(t, "my-bucket", viper.GetString("Origin.S3Bucket"))
		assert.Equal(t, "/path/to/access.key", viper.GetString("Origin.S3AccessKeyfile"))
		assert.Equal(t, "/path/to/secret.key", viper.GetString("Origin.S3SecretKeyfile"))
		assert.Equal(t, "/first/namespace", viper.GetString("Origin.FederationPrefix"))
		assert.True(t, viper.GetBool("Origin.EnableReads"))
		assert.False(t, viper.GetBool("Origin.EnableWrites"))
		assert.True(t, viper.GetBool("Origin.EnablePublicReads"))
		assert.False(t, viper.GetBool("Origin.EnableListings"))
		assert.True(t, viper.GetBool("Origin.EnableDirectReads"))
	})
}

func TestCheckOriginSentinelLocation(t *testing.T) {
	tmpDir := t.TempDir()
	tempStn := filepath.Join(tmpDir, "mock_sentinel")
	file, err := os.Create(tempStn)
	require.NoError(t, err)
	err = file.Close()
	require.NoError(t, err)

	mockExportNoStn := OriginExport{
		StoragePrefix:    "/foo/bar",
		FederationPrefix: "/demo/foo/bar",
		Capabilities:     server_structs.Capabilities{Reads: true},
	}
	mockExportValidStn := OriginExport{
		StoragePrefix:    tmpDir,
		FederationPrefix: "/demo/foo/bar",
		Capabilities:     server_structs.Capabilities{Reads: true},
		SentinelLocation: "mock_sentinel",
	}
	mockExportInvalidStn := OriginExport{
		StoragePrefix:    tmpDir,
		FederationPrefix: "/demo/foo/bar",
		Capabilities:     server_structs.Capabilities{Reads: true},
		SentinelLocation: "sentinel_dne",
	}

	t.Run("empty-sentinel-return-ok", func(t *testing.T) {
		exports := make([]OriginExport, 0)
		exports = append(exports, mockExportNoStn)
		exports = append(exports, mockExportNoStn)

		ok, err := CheckOriginSentinelLocations(exports)
		assert.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("valid-sentinel-return-ok", func(t *testing.T) {
		exports := make([]OriginExport, 0)
		exports = append(exports, mockExportNoStn)
		exports = append(exports, mockExportValidStn)

		ok, err := CheckOriginSentinelLocations(exports)
		assert.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("invalid-sentinel-return-error", func(t *testing.T) {
		exports := make([]OriginExport, 0)
		exports = append(exports, mockExportNoStn)
		exports = append(exports, mockExportValidStn)
		exports = append(exports, mockExportInvalidStn)

		ok, err := CheckOriginSentinelLocations(exports)
		assert.Error(t, err)
		assert.False(t, ok)
	})
}

func runBucketNameTest(t *testing.T, name string, valid bool) {
	t.Run(fmt.Sprintf("testBucketNameValidation-%s", name), func(t *testing.T) {
		err := validateBucketName(name)
		if valid {
			assert.NoError(t, err)
		} else {
			assert.Error(t, err)
		}
	})
}
func TestBucketNameValidation(t *testing.T) {
	// Valid bucket names
	valid := true
	runBucketNameTest(t, "my-bucket", valid)
	runBucketNameTest(t, "my-bucket-123", valid)
	runBucketNameTest(t, "my.bucket", valid)
	runBucketNameTest(t, "my-bucket-123.456", valid)

	// Invalid bucket names
	valid = false
	runBucketNameTest(t, "my_bucket", valid)
	runBucketNameTest(t, "my..bucket", valid)
	runBucketNameTest(t, "my-bucket-123-", valid)
	runBucketNameTest(t, "my-bucket-123.", valid)
	runBucketNameTest(t, "My-BUCKET", valid)
	runBucketNameTest(t, "sthree-bucket", valid)
	runBucketNameTest(t, "my-bucket-123456789012345678901234567890123456789012345678901234567890123412341234123412341234", valid)
	runBucketNameTest(t, "my-bucket-s3alias", valid)
	runBucketNameTest(t, "my-bucket--ol-s3", valid)
}

func runFedPrefixTest(t *testing.T, name string, valid bool) {
	t.Run(fmt.Sprintf("testFedPrefixValidation-%s", name), func(t *testing.T) {
		err := validateFederationPrefix(name)
		if valid {
			assert.NoError(t, err)
		} else {
			assert.Error(t, err)
		}
	})
}
func TestFederationPrefixValidation(t *testing.T) {
	runFedPrefixTest(t, "", false)                 // Test empty prefix
	runFedPrefixTest(t, "noSlashPrefix", false)    // Test prefix without leading '/'
	runFedPrefixTest(t, "/double//slash", false)   // Test prefix with '//'
	runFedPrefixTest(t, "/dotSlash./test", false)  // Test prefix with './'
	runFedPrefixTest(t, "/dotDot..test", false)    // Test prefix with '..'
	runFedPrefixTest(t, "~tilde/test", false)      // Test prefix with leading '~'
	runFedPrefixTest(t, "/dollar$test", false)     // Test prefix with '$'
	runFedPrefixTest(t, "/star*test", false)       // Test prefix with '*'
	runFedPrefixTest(t, "/backslash\\test", false) // Test prefix with '\'
	runFedPrefixTest(t, "/origins/foo/bar", false) // Test prefix for origins
	runFedPrefixTest(t, "/origins/example.org", false)
	runFedPrefixTest(t, "/caches/foo/bar", false) // Test prefix for caches
	runFedPrefixTest(t, "/caches/example.org", false)
	runFedPrefixTest(t, "/valid/prefix", true) // Test valid prefix
}
