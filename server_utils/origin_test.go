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

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
)

var (
	//go:embed resources/posix-origins/env-var-mimic.yml
	envVarMimicConfig string

	//go:embed resources/posix-origins/multi-export-valid.yml
	multiExportValidConfig string

	//go:embed resources/posix-origins/multi-export-trailing-slash.yml
	multiExportTrailingSlashConfig string

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

	defaultIssuerUrl = "https://foo-issuer.com"
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

	// Check if this is a POSIX origin (default is posix if not specified)
	storageType := viper.GetString("origin.storagetype")
	isPosix := storageType == "" || storageType == "posix"

	// Some keys need to be overridden because GetOriginExports validates things like filepaths by making
	// sure the file exists and is readable by the process.
	// Iterate through Origin.XXX keys and check for "SHOULD-OVERRIDE" in the value
	for _, key := range viper.AllKeys() {
		if strings.Contains(viper.GetString(key), "SHOULD-OVERRIDE-TEMPFILE") {
			tmpFile := getTmpFile(t)
			require.NoError(t, param.Set(key, tmpFile))
		} else if key == "origin.storageprefix" && isPosix {
			// For POSIX origins, replace the storage prefix with a temp directory
			// so the permission validation can succeed
			tmpDir := test_utils.GetTmpStoragePrefixDir(t)
			viper.Set(key, tmpDir)
		} else if key == "origin.exportvolumes" && isPosix {
			// For POSIX origins, replace export volumes paths with temp directories
			volumes := viper.GetStringSlice(key)
			newVolumes := make([]string, len(volumes))
			for i, vol := range volumes {
				// Parse the volume format "storagePrefix:federationPrefix"
				parts := strings.SplitN(vol, ":", 2)
				if len(parts) == 2 {
					tmpDir := test_utils.GetTmpStoragePrefixDir(t)
					newVolumes[i] = tmpDir + ":" + parts[1]
				} else {
					tmpDir := test_utils.GetTmpStoragePrefixDir(t)
					newVolumes[i] = tmpDir
				}
			}
			require.NoError(t, param.Set(key, newVolumes))
		} else if key == "origin.exports" { // keys will be lowercased
			// We also need to override paths for any exports that define "SHOULD-OVERRIDE-TEMPFILE"
			// and for POSIX origins, replace storage prefixes with temp directories
			exports := viper.Get(key).([]interface{})
			for _, export := range exports {
				exportMap := export.(map[string]interface{})
				for k, v := range exportMap {
					if v == "SHOULD-OVERRIDE-TEMPFILE" {
						tmpFile := getTmpFile(t)
						exportMap[k] = tmpFile
					} else if k == "storageprefix" && isPosix {
						// For POSIX origins, replace storage prefixes with temp directories
						// that have proper permissions for the daemon user
						exportMap[k] = test_utils.GetTmpStoragePrefixDir(t)
					}
				}
			}
			// Set the modified exports back to viper after all overrides
			require.NoError(t, param.Set(key, exports))
		}
	}

	// Provide an issuer URL that exports will use as a fallback
	require.NoError(t, param.Set(param.Server_IssuerUrl.GetName(), defaultIssuerUrl))

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
		// Storage prefix is replaced with a real temp dir for permission validation
		info, err := os.Stat(exports[0].StoragePrefix)
		assert.NoError(t, err, "storage prefix should exist")
		assert.True(t, info.IsDir(), "storage prefix should be a directory")

		assert.False(t, exports[0].Capabilities.Writes, "expected no writes")
		assert.True(t, exports[0].Capabilities.PublicReads, "expected public reads")
		assert.False(t, exports[0].Capabilities.Listings, "expected no listings")
		assert.True(t, exports[0].Capabilities.DirectReads, "expected direct reads")
	})

	t.Run("testMultiExportValid", func(t *testing.T) {
		defer ResetTestState()
		exports := setup(t, multiExportValidConfig, false)

		assert.Len(t, exports, 2, "expected 2 exports")

		// Check first export (storage prefix is a real temp dir)
		info, err := os.Stat(exports[0].StoragePrefix)
		assert.NoError(t, err, "first storage prefix should exist")
		assert.True(t, info.IsDir(), "first storage prefix should be a directory")
		assert.Equal(t, "/first/namespace", exports[0].FederationPrefix)
		assert.Equal(t, []string{defaultIssuerUrl}, exports[0].IssuerUrls)
		assert.True(t, exports[0].Capabilities.Writes)
		assert.True(t, exports[0].Capabilities.PublicReads)
		assert.True(t, exports[0].Capabilities.Listings)
		assert.True(t, exports[0].Capabilities.Reads)
		assert.True(t, exports[0].Capabilities.DirectReads)

		// Check second export (storage prefix is a real temp dir)
		info, err = os.Stat(exports[1].StoragePrefix)
		assert.NoError(t, err, "second storage prefix should exist")
		assert.True(t, info.IsDir(), "second storage prefix should be a directory")
		assert.Equal(t, "/second/namespace", exports[1].FederationPrefix)
		assert.Equal(t, []string{defaultIssuerUrl}, exports[1].IssuerUrls)
		assert.True(t, exports[1].Capabilities.Writes)
		assert.False(t, exports[1].Capabilities.PublicReads)
		assert.False(t, exports[1].Capabilities.Listings)
		assert.False(t, exports[1].Capabilities.Reads)
		assert.False(t, exports[1].Capabilities.DirectReads)
	})

	t.Run("testTrailingSlashRemovalPosix", func(t *testing.T) {
		defer ResetTestState()
		exports := setup(t, multiExportTrailingSlashConfig, false)

		// Both trailing-slash prefixes should have been trimmed
		assert.Len(t, exports, 2)
		assert.Equal(t, "/first/namespace", exports[0].FederationPrefix)
		assert.Equal(t, "/", exports[1].FederationPrefix)
	})

	t.Run("testExportVolumesValid", func(t *testing.T) {
		defer ResetTestState()
		exports := setup(t, exportVolumesValidConfig, false)

		assert.Len(t, exports, 2, "expected 2 exports")

		// Check first export (storage prefix is a real temp dir)
		info, err := os.Stat(exports[0].StoragePrefix)
		assert.NoError(t, err, "first storage prefix should exist")
		assert.True(t, info.IsDir(), "first storage prefix should be a directory")
		assert.Equal(t, "/first/namespace", exports[0].FederationPrefix)
		assert.Equal(t, []string{defaultIssuerUrl}, exports[0].IssuerUrls)
		assert.False(t, exports[0].Capabilities.Writes)
		assert.False(t, exports[0].Capabilities.PublicReads)
		assert.True(t, exports[0].Capabilities.Listings)
		assert.True(t, exports[0].Capabilities.Reads)
		assert.True(t, exports[0].Capabilities.DirectReads)

		// Check second export (storage prefix is a real temp dir)
		info, err = os.Stat(exports[1].StoragePrefix)
		assert.NoError(t, err, "second storage prefix should exist")
		assert.True(t, info.IsDir(), "second storage prefix should be a directory")
		assert.Equal(t, "/second/namespace", exports[1].FederationPrefix)
		assert.Equal(t, []string{defaultIssuerUrl}, exports[1].IssuerUrls)
		assert.False(t, exports[1].Capabilities.Writes)
		assert.False(t, exports[1].Capabilities.PublicReads)
		assert.True(t, exports[1].Capabilities.Listings)
		assert.True(t, exports[1].Capabilities.Reads)
		assert.True(t, exports[1].Capabilities.DirectReads)
	})

	// When we have a single export volume, we also set a few viper variables that can be
	// used by sections of code that assume a single export. Test that those are set properly
	t.Run("testExportVolumesSingle", func(t *testing.T) {
		defer ResetTestState()
		exports := setup(t, exportSingleVolumeConfig, false)

		assert.Len(t, exports, 1, "expected 1 export")

		// Check export (storage prefix is a real temp dir)
		info, err := os.Stat(exports[0].StoragePrefix)
		assert.NoError(t, err, "storage prefix should exist")
		assert.True(t, info.IsDir(), "storage prefix should be a directory")
		assert.Equal(t, "/first/namespace", exports[0].FederationPrefix)
		assert.Equal(t, []string{defaultIssuerUrl}, exports[0].IssuerUrls)
		assert.True(t, exports[0].Capabilities.Writes)
		assert.True(t, exports[0].Capabilities.PublicReads)
		assert.False(t, exports[0].Capabilities.Listings)
		assert.True(t, exports[0].Capabilities.Reads)
		assert.False(t, exports[0].Capabilities.DirectReads)

		// Now check that we properly set the other viper vars we should have
		viperSP := viper.GetString("Origin.StoragePrefix")
		info, err = os.Stat(viperSP)
		assert.NoError(t, err, "viper storage prefix should exist")
		assert.True(t, info.IsDir(), "viper storage prefix should be a directory")
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

		assert.Len(t, exports, 1, "expected 1 export")

		// Check export (storage prefix is a real temp dir)
		info, err := os.Stat(exports[0].StoragePrefix)
		assert.NoError(t, err, "storage prefix should exist")
		assert.True(t, info.IsDir(), "storage prefix should be a directory")
		assert.Equal(t, "/first/namespace", exports[0].FederationPrefix)
		// No issuer is populated because there are no namespaces requiring it
		assert.Nil(t, exports[0].IssuerUrls)
		assert.False(t, exports[0].Capabilities.Writes)
		assert.True(t, exports[0].Capabilities.PublicReads)
		assert.False(t, exports[0].Capabilities.Listings)
		assert.True(t, exports[0].Capabilities.Reads)
		assert.True(t, exports[0].Capabilities.DirectReads)

		// Now check that we properly set the other viper vars we should have
		viperSP := viper.GetString("Origin.StoragePrefix")
		info, err = os.Stat(viperSP)
		assert.NoError(t, err, "viper storage prefix should exist")
		assert.True(t, info.IsDir(), "viper storage prefix should be a directory")
		assert.Equal(t, "/first/namespace", viper.GetString("Origin.FederationPrefix"))
		assert.True(t, viper.GetBool("Origin.EnableReads"))
		assert.False(t, viper.GetBool("Origin.EnableWrites"))
		assert.True(t, viper.GetBool("Origin.EnablePublicReads"))
		assert.False(t, viper.GetBool("Origin.EnableListings"))
		assert.True(t, viper.GetBool("Origin.EnableDirectReads"))
	})

	t.Run("testInvalidExport", func(t *testing.T) {
		defer ResetTestState()

		require.NoError(t, param.Set("Origin.StorageType", "posix"))
		require.NoError(t, param.Set("Origin.ExportVolumes", ""))
		_, err := GetOriginExports()
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidOriginConfig)

		ResetTestState()
		require.NoError(t, param.Set("Origin.StorageType", "posix"))
		require.NoError(t, param.Set("Origin.ExportVolumes", "foo"))
		_, err = GetOriginExports()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidOriginConfig)

		ResetTestState()
		require.NoError(t, param.Set("Origin.StorageType", "blah"))
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
			IssuerUrls: []string{defaultIssuerUrl},
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
			IssuerUrls: []string{defaultIssuerUrl},
		}

		assert.Len(t, exports, 2, "expected 2 exports")
		assert.Equal(t, expectedExport1, exports[0])

		// Check that the S3AccessKeyfile and S3SecretKeyfile are not empty and not equal to "SHOULD-OVERRIDE-TEMPFILE"
		assert.NotEmpty(t, exports[1].S3AccessKeyfile)
		assert.NotEqual(t, "SHOULD-OVERRIDE-TEMPFILE", exports[1].S3AccessKeyfile)
		assert.NotEmpty(t, exports[1].S3SecretKeyfile)
		assert.NotEqual(t, "SHOULD-OVERRIDE-TEMPFILE", exports[1].S3SecretKeyfile)
		assert.Equal(t, expectedExport2.IssuerUrls, exports[1].IssuerUrls)

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
			IssuerUrls: []string{defaultIssuerUrl},
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
			IssuerUrls: []string{defaultIssuerUrl},
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
			IssuerUrls: []string{defaultIssuerUrl},
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
		assert.Equal(t, expectedExport.IssuerUrls, exports[0].IssuerUrls)

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
			// No issuer is populated because there are no namespaces requiring it
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
			// No issuer is populated because there are no namespaces requiring it
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
				Writes:      false,
				PublicReads: true,
				Listings:    false,
				Reads:       true,
				DirectReads: true,
			},
			IssuerUrls: []string{defaultIssuerUrl},
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
				Writes:      false,
				PublicReads: true,
				Listings:    false,
				Reads:       true,
				DirectReads: true,
			},
			IssuerUrls: []string{defaultIssuerUrl},
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
			// No issuer is populated because there are no namespaces requiring it
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
			IssuerUrls: []string{defaultIssuerUrl},
		}

		assert.Len(t, exports, 1, "expected 1 export")
		assert.Equal(t, expectedExport, exports[0])
	})

	t.Run("disabledDirectClientsPreventsDirectReads", func(t *testing.T) {
		defer ResetTestState()
		require.NoError(t, param.Set(param.Origin_DisableDirectClients.GetName(), true))
		// This export has DirectReads set to true, so expect failure
		_ = setup(t, singleExportBlockConfig, true)
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

// TestValidatePosixPermissions tests the filesystem permission validation for POSIX origins.
// These tests ensure that the origin correctly validates whether the XRootD daemon user has the
// necessary permissions to perform operations specified by the export's capabilities.
func TestValidatePosixPermissions(t *testing.T) {
	// Test with non-existent path
	t.Run("NonExistentPath", func(t *testing.T) {
		caps := server_structs.Capabilities{Reads: true}
		err := validatePosixPermissions("/nonexistent/path/that/does/not/exist", caps, "/test")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidOriginConfig)
		assert.Contains(t, err.Error(), "does not exist")
	})

	// Test with a file instead of directory
	t.Run("FileInsteadOfDirectory", func(t *testing.T) {
		tmpFile := t.TempDir() + "/testfile"
		file, err := os.Create(tmpFile)
		require.NoError(t, err)
		file.Close()

		caps := server_structs.Capabilities{Reads: true}
		err = validatePosixPermissions(tmpFile, caps, "/test")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidOriginConfig)
		assert.Contains(t, err.Error(), "is not a directory")
	})

	// Test with full permissions (rwx) - all capabilities should pass
	// Note: We use 0777 because tests run as root but the daemon user (xrootd) is different,
	// so we need "others" permissions to be rwx for the xrootd user to have access.
	t.Run("FullPermissions", func(t *testing.T) {
		tmpDir := t.TempDir()
		err := os.Chmod(tmpDir, 0777) // rwx for everyone including "others" (daemon user)
		require.NoError(t, err)

		// Test reads capability
		caps := server_structs.Capabilities{Reads: true}
		err = validatePosixPermissions(tmpDir, caps, "/test")
		assert.NoError(t, err)

		// Test public reads capability
		caps = server_structs.Capabilities{PublicReads: true}
		err = validatePosixPermissions(tmpDir, caps, "/test")
		assert.NoError(t, err)

		// Test writes capability
		caps = server_structs.Capabilities{Writes: true}
		err = validatePosixPermissions(tmpDir, caps, "/test")
		assert.NoError(t, err)

		// Test listings capability
		caps = server_structs.Capabilities{Listings: true}
		err = validatePosixPermissions(tmpDir, caps, "/test")
		assert.NoError(t, err)

		// Test all capabilities together
		caps = server_structs.Capabilities{
			Reads:       true,
			PublicReads: true,
			Writes:      true,
			Listings:    true,
		}
		err = validatePosixPermissions(tmpDir, caps, "/test")
		assert.NoError(t, err)
	})

	// Test with no capabilities - should always pass (nothing to validate)
	t.Run("NoCapabilities", func(t *testing.T) {
		tmpDir := t.TempDir()
		// Even with restrictive permissions, no capabilities means no validation needed
		err := os.Chmod(tmpDir, 0000)
		require.NoError(t, err)
		defer func() {
			// Restore permissions for cleanup
			err := os.Chmod(tmpDir, 0755)
			require.NoError(t, err)
		}()

		caps := server_structs.Capabilities{}
		err = validatePosixPermissions(tmpDir, caps, "/test")
		assert.NoError(t, err)
	})

	// Test with read-only permissions (r-x) - writes should fail
	t.Run("ReadOnlyPermissions", func(t *testing.T) {
		tmpDir := t.TempDir()
		err := os.Chmod(tmpDir, 0555) // r-x r-x r-x
		require.NoError(t, err)
		defer func() {
			err := os.Chmod(tmpDir, 0755)
			require.NoError(t, err)
		}()

		// Reads should pass
		caps := server_structs.Capabilities{Reads: true}
		err = validatePosixPermissions(tmpDir, caps, "/test")
		assert.NoError(t, err)

		// Listings should pass
		caps = server_structs.Capabilities{Listings: true}
		err = validatePosixPermissions(tmpDir, caps, "/test")
		assert.NoError(t, err)

		// Writes should fail
		caps = server_structs.Capabilities{Writes: true}
		err = validatePosixPermissions(tmpDir, caps, "/test")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidOriginConfig)
		assert.Contains(t, err.Error(), "Writes")
		assert.Contains(t, err.Error(), "write and execute")
	})

	// Test with write-only permissions (-wx) - reads and listings should fail
	t.Run("WriteOnlyPermissions", func(t *testing.T) {
		tmpDir := t.TempDir()
		err := os.Chmod(tmpDir, 0333) // -wx -wx -wx
		require.NoError(t, err)
		defer func() {
			err := os.Chmod(tmpDir, 0755)
			require.NoError(t, err)
		}()

		// Writes should pass
		caps := server_structs.Capabilities{Writes: true}
		err = validatePosixPermissions(tmpDir, caps, "/test")
		assert.NoError(t, err)

		// Reads should fail
		caps = server_structs.Capabilities{Reads: true}
		err = validatePosixPermissions(tmpDir, caps, "/test")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidOriginConfig)
		assert.Contains(t, err.Error(), "Reads")

		// Listings should fail
		caps = server_structs.Capabilities{Listings: true}
		err = validatePosixPermissions(tmpDir, caps, "/test")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidOriginConfig)
		assert.Contains(t, err.Error(), "Listings")
	})

	// Test with no execute permission - all capabilities requiring traversal should fail
	t.Run("NoExecutePermission", func(t *testing.T) {
		tmpDir := t.TempDir()
		err := os.Chmod(tmpDir, 0666) // rw- rw- rw-
		require.NoError(t, err)
		defer func() {
			err := os.Chmod(tmpDir, 0755)
			require.NoError(t, err)
		}()

		// Reads should fail (needs execute for directory traversal)
		caps := server_structs.Capabilities{Reads: true}
		err = validatePosixPermissions(tmpDir, caps, "/test")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidOriginConfig)

		// Writes should fail (needs execute for directory traversal)
		caps = server_structs.Capabilities{Writes: true}
		err = validatePosixPermissions(tmpDir, caps, "/test")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidOriginConfig)

		// Listings should fail (needs execute for directory traversal)
		caps = server_structs.Capabilities{Listings: true}
		err = validatePosixPermissions(tmpDir, caps, "/test")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidOriginConfig)
	})

	// Test error message contains useful information
	t.Run("ErrorMessageContent", func(t *testing.T) {
		tmpDir := t.TempDir()
		err := os.Chmod(tmpDir, 0000) // --- --- ---
		require.NoError(t, err)
		defer func() {
			err := os.Chmod(tmpDir, 0755)
			require.NoError(t, err)
		}()

		caps := server_structs.Capabilities{Reads: true}
		err = validatePosixPermissions(tmpDir, caps, "/my/federation/prefix")
		require.Error(t, err)

		errStr := err.Error()
		// Check that the error message contains useful debugging information
		assert.Contains(t, errStr, tmpDir, "error should contain the storage path")
		assert.Contains(t, errStr, "/my/federation/prefix", "error should contain the federation prefix")
		assert.Contains(t, errStr, "uid=", "error should contain UID info")
		assert.Contains(t, errStr, "gid=", "error should contain GID info")
		assert.Contains(t, errStr, "permissions", "error should mention permissions")
	})
}
