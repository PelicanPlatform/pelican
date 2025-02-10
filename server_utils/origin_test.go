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

	//go:embed resources/https-origins/single-export.yml
	httpsSingleExport string

	//go:embed resources/https-origins/multi-export.yml
	httpsMultiExport string

	//go:embed resources/globus-origins/single-export-valid.yml
	globusSingleExportValid string

	//go:embed resources/globus-origins/single-export-invalid.yml
	globusSingleExportInvalid string

	//go:embed resources/globus-origins/multi-export-valid.yml
	globusMultiExport string

	//go:embed resources/xroot-origins/single-export-invalid.yml
	xrootSingleExportInvalid string

	//go:embed resources/xroot-origins/single-export-valid.yml
	xrootSingleExportValid string
)

func getTmpFile(t *testing.T) string {
	tmpFile := t.TempDir() + "/tmpfile"

	// Create the file
	file, err := os.Create(tmpFile)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	file.Close()

	// Set file permissions to 777
	err = os.Chmod(tmpFile, 0777)
	if err != nil {
		t.Fatalf("Failed to set file permissions: %v", err)
	}

	return tmpFile
}

func setup(t *testing.T, config string, shouldError bool) []OriginExport {
	viper.SetConfigType("yaml")
	// Use viper to read in the embedded config
	err := viper.ReadConfig(strings.NewReader(config))
	require.NoError(t, err, "error reading config")
	// Some keys need to be overridden because GetOriginExports validates things like filepaths by making
	// sure the file exists and is readable by the process.
	// Iterate through Origin.XXX keys and check for "SHOULD-OVERRIDE" in the value
	for _, key := range viper.AllKeys() {
		if strings.Contains(viper.GetString(key), "SHOULD-OVERRIDE-TEMPFILE") {
			tmpFile := getTmpFile(t)
			viper.Set(key, tmpFile)
		} else if key == "origin.exports" { // keys will be lowercased
			// We also need to override paths for any exports that define "SHOULD-OVERRIDE-TEMPFILE"
			exports := viper.Get(key).([]interface{})
			for _, export := range exports {
				exportMap := export.(map[string]interface{})
				for k, v := range exportMap {
					if v == "SHOULD-OVERRIDE-TEMPFILE" {
						tmpFile := getTmpFile(t)
						exportMap[k] = tmpFile
					}
				}
			}
			// Set the modified exports back to viper after all overrides
			viper.Set(key, exports)
		}
	}

	// Now call GetOriginExports and check the struct
	exports, err := GetOriginExports()
	if shouldError {
		require.Error(t, err, "expected error getting origin exports")
		require.ErrorIs(t, err, ErrInvalidOriginConfig, "expected invalid origin config error")
		return nil
	}
	require.NoError(t, err, "error getting origin exports")
	return exports
}

// Note that this test really doesn't actually test env var configuration. Rather, it
// tests an origin configuration that mimics what you could do with env vars due to the
// fact that we don't use a yaml list
func TestGetExports(t *testing.T) {
	ResetTestState()

	// Posix tests
	t.Run("testSingleExportValid", func(t *testing.T) {
		defer ResetTestState()
		exports := setup(t, envVarMimicConfig, false)

		assert.Len(t, exports, 1, "expected 1 export")
		assert.Equal(t, "/foo", exports[0].StoragePrefix, "expected /foo")

		assert.False(t, exports[0].Capabilities.Writes, "expected no writes")
		assert.True(t, exports[0].Capabilities.PublicReads, "expected public reads")
		assert.False(t, exports[0].Capabilities.Listings, "expected no listings")
		assert.True(t, exports[0].Capabilities.DirectReads, "expected direct reads")
	})

	t.Run("testMultiExportValid", func(t *testing.T) {
		defer ResetTestState()
		exports := setup(t, multiExportValidConfig, false)

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

		assert.Len(t, exports, 2, "expected 2 exports")
		assert.Equal(t, expectedExport1, exports[0])
		assert.Equal(t, expectedExport2, exports[1])
	})

	t.Run("testExportVolumesValid", func(t *testing.T) {
		defer ResetTestState()
		exports := setup(t, exportVolumesValidConfig, false)

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

		assert.Len(t, exports, 2, "expected 2 exports")
		assert.Equal(t, expectedExport1, exports[0])
		assert.Equal(t, expectedExport2, exports[1])
	})

	// When we have a single export volume, we also set a few viper variables that can be
	// used by sections of code that assume a single export. Test that those are set properly
	t.Run("testExportVolumesSingle", func(t *testing.T) {
		defer ResetTestState()
		exports := setup(t, exportSingleVolumeConfig, false)

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

		assert.Len(t, exports, 1, "expected 1 export")
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
		defer ResetTestState()
		exports := setup(t, singleExportBlockConfig, false)

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

		assert.Len(t, exports, 1, "expected 1 export")
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
		defer ResetTestState()

		viper.Set("Origin.StorageType", "posix")
		viper.Set("Origin.ExportVolumes", "")
		_, err := GetOriginExports()
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidOriginConfig)

		ResetTestState()
		viper.Set("Origin.StorageType", "posix")
		viper.Set("Origin.ExportVolumes", "foo")
		_, err = GetOriginExports()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidOriginConfig)

		ResetTestState()
		viper.Set("Origin.StorageType", "blah")
		_, err = GetOriginExports()
		assert.Error(t, err)
		assert.ErrorIs(t, err, server_structs.ErrUnknownOriginStorageType)
	})

	// S3 tests
	t.Run("testSingleExportValidS3", func(t *testing.T) {
		defer ResetTestState()

		exports := setup(t, s3envVarMimicConfig, false)

		assert.Len(t, exports, 1, "expected 1 export")
		assert.Equal(t, "/my/namespace", exports[0].FederationPrefix, "expected /my/namespace")
		assert.Equal(t, "my-bucket", exports[0].S3Bucket, "expected my-bucket")
		assert.NotEqual(t, "SHOULD-OVERRIDE-TEMPFILE", exports[0].S3AccessKeyfile, "S3AccessKeyfile was not overridden from config")
		assert.NotEmpty(t, exports[0].S3AccessKeyfile)
		assert.NotEqual(t, "SHOULD-OVERRIDE-TEMPFILE", exports[0].S3SecretKeyfile, "S3SecretKeyfile was not overridden from config")
		assert.NotEmpty(t, exports[0].S3SecretKeyfile)

		assert.False(t, exports[0].Capabilities.Writes, "expected no writes")
		assert.True(t, exports[0].Capabilities.PublicReads, "expected public reads")
		assert.False(t, exports[0].Capabilities.Listings, "expected no listings")
		assert.True(t, exports[0].Capabilities.DirectReads, "expected direct reads")
	})

	t.Run("testMultiExportValidS3", func(t *testing.T) {
		defer ResetTestState()
		exports := setup(t, s3multiExportValidConfig, false)

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

		expectedExport2 := OriginExport{
			S3Bucket:         "second-bucket",
			FederationPrefix: "/second/namespace",
			Capabilities: server_structs.Capabilities{
				Writes:      true,
				PublicReads: false,
				Listings:    false,
				Reads:       false,
				DirectReads: false,
			},
		}

		assert.Len(t, exports, 2, "expected 2 exports")
		assert.Equal(t, expectedExport1, exports[0])

		// Check that the S3AccessKeyfile and S3SecretKeyfile are not empty and not equal to "SHOULD-OVERRIDE-TEMPFILE"
		assert.NotEmpty(t, exports[1].S3AccessKeyfile)
		assert.NotEqual(t, "SHOULD-OVERRIDE-TEMPFILE", exports[1].S3AccessKeyfile)
		assert.NotEmpty(t, exports[1].S3SecretKeyfile)
		assert.NotEqual(t, "SHOULD-OVERRIDE-TEMPFILE", exports[1].S3SecretKeyfile)

		// Check the rest of the fields
		assert.Equal(t, expectedExport2.S3Bucket, exports[1].S3Bucket)
		assert.Equal(t, expectedExport2.FederationPrefix, exports[1].FederationPrefix)
		assert.Equal(t, expectedExport2.Capabilities, exports[1].Capabilities)
	})

	t.Run("testExportVolumesValidS3", func(t *testing.T) {
		defer ResetTestState()
		exports := setup(t, s3exportVolumesValidConfig, false)

		expectedExport1 := OriginExport{
			StoragePrefix:    "/first/namespace",
			S3Bucket:         "my-bucket",
			FederationPrefix: "/first/namespace",
			Capabilities: server_structs.Capabilities{
				Writes:      false,
				PublicReads: false,
				Listings:    true,
				Reads:       true,
				DirectReads: true,
			},
		}

		expectedExport2 := OriginExport{
			StoragePrefix:    "some-prefix",
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

		assert.Len(t, exports, 2, "expected 2 exports")
		assert.Equal(t, expectedExport1, exports[0])
		assert.Equal(t, expectedExport2, exports[1])
	})

	t.Run("testExportVolumesSingleS3", func(t *testing.T) {
		defer ResetTestState()
		exports := setup(t, s3exportSingleVolumeConfig, false)

		expectedExport := OriginExport{
			StoragePrefix:    "some-prefix",
			S3Bucket:         "",
			FederationPrefix: "/first/namespace",
			Capabilities: server_structs.Capabilities{
				Writes:      true,
				PublicReads: true,
				Listings:    false,
				Reads:       true,
				DirectReads: false,
			},
		}

		assert.Len(t, exports, 1, "expected 1 export")
		assert.Equal(t, expectedExport.StoragePrefix, exports[0].StoragePrefix)
		assert.Equal(t, expectedExport.FederationPrefix, exports[0].FederationPrefix)
		assert.Equal(t, expectedExport.S3Bucket, exports[0].S3Bucket)
		assert.Equal(t, expectedExport.Capabilities.Writes, exports[0].Capabilities.Writes)
		assert.Equal(t, expectedExport.Capabilities.PublicReads, exports[0].Capabilities.PublicReads)
		assert.Equal(t, expectedExport.Capabilities.Listings, exports[0].Capabilities.Listings)
		assert.Equal(t, expectedExport.Capabilities.Reads, exports[0].Capabilities.Reads)
		assert.Equal(t, expectedExport.Capabilities.DirectReads, exports[0].Capabilities.DirectReads)

		// Now check that we properly set the other viper vars we should have
		assert.Equal(t, "", viper.GetString("Origin.S3Bucket"))
		assert.NotEqual(t, "SHOULD-OVERRIDE-TEMPFILE", viper.GetString("Origin.S3AccessKeyfile"), "S3AccessKeyfile was not overridden from config")
		assert.NotEmpty(t, viper.GetString("Origin.S3AccessKeyfile"))
		assert.NotEqual(t, "SHOULD-OVERRIDE-TEMPFILE", viper.GetString("Origin.S3SecretKeyfile"), "S3SecretKeyfile was not overridden from config")
		assert.NotEmpty(t, viper.GetString("Origin.S3SecretKeyfile"))
		assert.Equal(t, "/first/namespace", viper.GetString("Origin.FederationPrefix"))
		assert.True(t, viper.GetBool("Origin.EnableReads"))
		assert.True(t, viper.GetBool("Origin.EnableWrites"))
		assert.True(t, viper.GetBool("Origin.EnablePublicReads"))
		assert.False(t, viper.GetBool("Origin.EnableListings"))
		assert.False(t, viper.GetBool("Origin.EnableDirectReads"))
	})

	t.Run("testSingleExportBlockS3", func(t *testing.T) {
		defer ResetTestState()
		exports := setup(t, s3singleExportBlockConfig, false)

		expectedExport := OriginExport{
			S3Bucket:         "my-bucket",
			FederationPrefix: "/first/namespace",
			StoragePrefix:    "/",
			Capabilities: server_structs.Capabilities{
				Writes:      false,
				PublicReads: true,
				Listings:    false,
				Reads:       true,
				DirectReads: true,
			},
		}

		assert.Len(t, exports, 1, "expected 1 export")
		assert.Equal(t, expectedExport.S3Bucket, exports[0].S3Bucket)
		assert.Equal(t, expectedExport.FederationPrefix, exports[0].FederationPrefix)
		assert.Equal(t, expectedExport.StoragePrefix, exports[0].StoragePrefix)
		assert.Equal(t, expectedExport.Capabilities.Writes, exports[0].Capabilities.Writes)
		assert.Equal(t, expectedExport.Capabilities.PublicReads, exports[0].Capabilities.PublicReads)
		assert.Equal(t, expectedExport.Capabilities.Listings, exports[0].Capabilities.Listings)
		assert.Equal(t, expectedExport.Capabilities.Reads, exports[0].Capabilities.Reads)
		assert.Equal(t, expectedExport.Capabilities.DirectReads, exports[0].Capabilities.DirectReads)

		// Now check that we properly set the other viper vars we should have
		assert.Equal(t, "my-bucket", viper.GetString("Origin.S3Bucket"))
		assert.NotEqual(t, "SHOULD-OVERRIDE-TEMPFILE", viper.GetString("Origin.S3AccessKeyfile"), "S3AccessKeyfile was not overridden from config")
		assert.NotEmpty(t, viper.GetString("Origin.S3AccessKeyfile"))
		assert.NotEqual(t, "SHOULD-OVERRIDE-TEMPFILE", viper.GetString("Origin.S3SecretKeyfile"), "S3SecretKeyfile was not overridden from config")
		assert.NotEmpty(t, viper.GetString("Origin.S3SecretKeyfile"))
		assert.Equal(t, "/first/namespace", viper.GetString("Origin.FederationPrefix"))
		assert.True(t, viper.GetBool("Origin.EnableReads"))
		assert.False(t, viper.GetBool("Origin.EnableWrites"))
		assert.True(t, viper.GetBool("Origin.EnablePublicReads"))
		assert.False(t, viper.GetBool("Origin.EnableListings"))
		assert.True(t, viper.GetBool("Origin.EnableDirectReads"))
	})

	t.Run("testSingleExportBlockHTTPS", func(t *testing.T) {
		defer ResetTestState()
		exports := setup(t, httpsSingleExport, false)

		expectedExport := OriginExport{
			FederationPrefix: "/first/namespace",
			StoragePrefix:    "/foo", // Notice lack of trailing /
			Capabilities: server_structs.Capabilities{
				Writes:      false,
				PublicReads: true,
				Listings:    true,
				Reads:       true,
				DirectReads: true,
			},
		}

		assert.Len(t, exports, 1, "expected 1 export")
		assert.Equal(t, viper.GetString("Origin.HTTPServiceUrl"), "https://example.com")
		assert.Equal(t, expectedExport, exports[0])
	})

	// Should currently fail -- HTTPS origins do not support multiple exports yet
	t.Run("testMultiExportBlockHTTPS", func(t *testing.T) {
		defer ResetTestState()
		_ = setup(t, httpsMultiExport, true)
	})

	t.Run("testSingleExportInvalidGlobus", func(t *testing.T) {
		defer ResetTestState()
		_ = setup(t, globusSingleExportInvalid, true)
	})

	t.Run("testSingleExportValidGlobus", func(t *testing.T) {
		defer ResetTestState()
		exports := setup(t, globusSingleExportValid, false)

		expectedExport := OriginExport{
			FederationPrefix:     "/first/namespace",
			StoragePrefix:        "/foo",
			GlobusCollectionID:   "abc123",
			GlobusCollectionName: "Pelican >> Globus!",
			Capabilities: server_structs.Capabilities{
				Writes:      true,
				PublicReads: true,
				Listings:    false,
				Reads:       true,
				DirectReads: true,
			},
		}

		assert.Len(t, exports, 1, "expected 1 export")
		assert.Equal(t, expectedExport, exports[0])
		assert.NotEqual(t, "SHOULD-OVERRIDE-TEMPFILE", viper.GetString("Origin.GlobusClientIDFile"), "GlobusClientIDFile was not overridden from config")
		assert.NotEmpty(t, viper.GetString("Origin.GlobusClientIDFile"))
		assert.NotEqual(t, "SHOULD-OVERRIDE-TEMPFILE", viper.GetString("Origin.GlobusClientSecretFile"), "GlobusClientSecretFile was not overridden from config")
		assert.NotEmpty(t, viper.GetString("Origin.GlobusClientSecretFile"))
		assert.Equal(t, "abc123", viper.GetString("Origin.GlobusCollectionID"))
		assert.Equal(t, "Pelican >> Globus!", viper.GetString("Origin.GlobusCollectionName"))
	})

	t.Run("testMultiExportValidGlobus", func(t *testing.T) {
		defer ResetTestState()
		exports := setup(t, globusMultiExport, false)

		expectedExport1 := OriginExport{
			FederationPrefix:     "/first/namespace",
			StoragePrefix:        "/foo",
			GlobusCollectionID:   "abc123",
			GlobusCollectionName: "Pelican >> Globus!",
			Capabilities: server_structs.Capabilities{
				Writes:      true,
				PublicReads: true,
				Listings:    false,
				Reads:       true,
				DirectReads: true,
			},
		}

		expectedExport2 := OriginExport{
			FederationPrefix:     "/second/namespace",
			StoragePrefix:        "/bar",
			GlobusCollectionID:   "123abc",
			GlobusCollectionName: "Globus << Pelican!",
			Capabilities: server_structs.Capabilities{
				Writes:      false,
				PublicReads: true,
				Listings:    false,
				Reads:       true,
				DirectReads: true,
			},
		}

		assert.Len(t, exports, 2, "expected 2 exports")
		assert.Equal(t, expectedExport1, exports[0])
		assert.Equal(t, expectedExport2, exports[1])
		assert.NotEqual(t, "SHOULD-OVERRIDE-TEMPFILE", viper.GetString("Origin.GlobusClientIDFile"), "GlobusClientIDFile was not overridden from config")
		assert.NotEmpty(t, viper.GetString("Origin.GlobusClientIDFile"))
		assert.NotEqual(t, "SHOULD-OVERRIDE-TEMPFILE", viper.GetString("Origin.GlobusClientSecretFile"), "GlobusClientSecretFile was not overridden from config")
		assert.NotEmpty(t, viper.GetString("Origin.GlobusClientSecretFile"))
	})

	// XRoot Origin tests
	t.Run("testSingleExportInvalidXRoot", func(t *testing.T) {
		defer ResetTestState()
		_ = setup(t, xrootSingleExportInvalid, true)
	})

	t.Run("testSingleExportValidXRoot", func(t *testing.T) {
		defer ResetTestState()
		exports := setup(t, xrootSingleExportValid, false)

		expectedExport := OriginExport{
			FederationPrefix: "/foo",
			StoragePrefix:    "/foo",
			Capabilities: server_structs.Capabilities{
				Writes:      true,
				PublicReads: true,
				Listings:    false,
				Reads:       true,
				DirectReads: true,
			},
		}

		assert.Len(t, exports, 1, "expected 1 export")
		assert.Equal(t, expectedExport, exports[0])
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
