//go:build linux

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

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/common"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestFedServeCache(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	viper.Reset()
	common.ResetOriginExports()
	defer viper.Reset()
	defer common.ResetOriginExports()

	modules := config.ServerType(0)
	modules.Set(config.CacheType)
	modules.Set(config.OriginType)
	modules.Set(config.DirectorType)
	modules.Set(config.RegistryType)

	// Create our own temp directory (for some reason t.TempDir() does not play well with xrootd)
	tmpPathPattern := "XRootD-Test_Whole_Fed*"
	tmpPath, err := os.MkdirTemp("", tmpPathPattern)
	require.NoError(t, err)

	// Need to set permissions or the xrootd process we spawn won't be able to write PID/UID files
	permissions := os.FileMode(0755)
	err = os.Chmod(tmpPath, permissions)
	require.NoError(t, err)

	nsTmpPattern := "Orig_NS*"
	origPath, err := os.MkdirTemp("", nsTmpPattern)
	require.NoError(t, err)

	err = os.Chmod(origPath, permissions)
	require.NoError(t, err)

	err = os.Mkdir(filepath.Join(origPath, "ns"), 0755)
	require.NoError(t, err)

	viper.Set("ConfigDir", tmpPath)
	viper.Set("Origin.RunLocation", filepath.Join(tmpPath, "xOrigin"))
	viper.Set("Cache.RunLocation", filepath.Join(tmpPath, "xCache"))
	viper.Set("Origin.StoragePrefix", filepath.Join(origPath, "ns"))
	viper.Set("Origin.FederationPrefix", "/test")
	testFilePath := filepath.Join(origPath, "ns", "test-file.txt")
	content := []byte("This is the content of the test file.")
	err = os.WriteFile(testFilePath, content, 0755)
	t.Cleanup(func() {
		if err := os.RemoveAll(tmpPath); err != nil {
			t.Fatal("Failed to clean up temp path")
		}
		if err := os.RemoveAll(origPath); err != nil {
			t.Fatal("Failed to clean up temp origin path")
		}
	})

	// Increase the log level; otherwise, its difficult to debug failures
	viper.Set("Logging.Level", "Debug")
	config.InitConfig()

	viper.Set("Origin.StorageType", "posix")
	// Disable functionality we're not using (and is difficult to make work on Mac)
	viper.Set("Origin.EnableCmsd", false)
	viper.Set("Origin.EnableMacaroons", false)
	viper.Set("Origin.EnableVoms", false)
	viper.Set("TLSSkipVerify", true)
	viper.Set("Server.EnableUI", false)
	viper.Set("Registry.DbLocation", filepath.Join(t.TempDir(), "ns-registry.sqlite"))
	viper.Set("Registry.RequireOriginApproval", false)
	viper.Set("Registry.RequireCacheApproval", false)
	viper.Set("Origin.EnablePublicReads", false)

	require.NoError(t, err)

	fedCancel, err := launchers.LaunchModules(ctx, modules)
	defer fedCancel()
	if err != nil {
		log.Errorln("Failure in fedServeInternal:", err)
		require.NoError(t, err)
	}

	// In this case 403 means the cache is running
	err = server_utils.WaitUntilWorking(ctx, "GET", param.Cache_Url.GetString(), "xrootd", 403)
	require.NoError(t, err)

	fileTests := server_utils.TestFileTransferImpl{}
	issuerUrl, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	ok, err := fileTests.RunTestsCache(ctx, param.Cache_Url.GetString(), issuerUrl, "/test/test-file.txt", "This is the content of the test file.")
	require.NoError(t, err)
	require.True(t, ok)

	cancel()
	fedCancel()
	assert.NoError(t, egrp.Wait())
}
