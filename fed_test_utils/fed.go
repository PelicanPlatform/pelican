//go:build !windows

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

package fed_test_utils

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

type (
	FedTest struct {
		Exports []server_utils.OriginExport
		Token   string
		Ctx     context.Context
		Egrp    *errgroup.Group
		Pids    []int
	}
)

func NewFedTest(t *testing.T, originConfig string) (ft *FedTest) {
	ft = &FedTest{}

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	ft.Ctx = ctx
	ft.Egrp = egrp

	modules := config.ServerType(0)
	modules.Set(config.CacheType)
	modules.Set(config.OriginType)
	modules.Set(config.DirectorType)
	modules.Set(config.RegistryType)
	// TODO: the cache startup routines not sequenced correctly for the downloads
	// to immediately work through the cache.  For now, unit tests will just use the origin.
	modules.Set(config.LocalCacheType)

	tmpPathPattern := "Pelican-FedTest*"
	tmpPath, err := os.MkdirTemp("", tmpPathPattern)
	require.NoError(t, err)

	permissions := os.FileMode(0755)
	err = os.Chmod(tmpPath, permissions)
	require.NoError(t, err)

	viper.Set("ConfigDir", tmpPath)
	viper.Set("Logging.Level", "debug")

	config.InitConfig()

	// Read in any config we may have set
	if originConfig != "" {
		viper.SetConfigType("yaml")
		err = viper.MergeConfig(strings.NewReader(originConfig))
		require.NoError(t, err, "error reading config")
	}
	// Now call GetOriginExports and check the struct
	exports, err := server_utils.GetOriginExports()
	require.NoError(t, err, "error getting origin exports")
	ft.Exports = exports

	// Override the test directory from the config file with our temp directory
	for i := 0; i < len(ft.Exports); i++ {
		originDir, err := os.MkdirTemp("", fmt.Sprintf("Export%d", i))
		assert.NoError(t, err)
		t.Cleanup(func() {
			err := os.RemoveAll(originDir)
			require.NoError(t, err)
		})

		// Set the storage prefix to the temporary origin directory
		ft.Exports[i].StoragePrefix = originDir
		// Our exports object becomes global -- we must reset in between each fed test
		t.Cleanup(func() {
			server_utils.ResetOriginExports()
		})

		// Change the permissions of the temporary origin directory
		permissions = os.FileMode(0755)
		err = os.Chmod(originDir, permissions)
		require.NoError(t, err)

		// Change ownership on the temporary origin directory so files can be uploaded
		uinfo, err := config.GetDaemonUserInfo()
		require.NoError(t, err)
		require.NoError(t, os.Chown(originDir, uinfo.Uid, uinfo.Gid))

		// Start off with a Hello World file we can use for testing in each of our exports
		err = os.WriteFile(filepath.Join(originDir, "hello_world.txt"), []byte("Hello, World!"), os.FileMode(0644))
		require.NoError(t, err)
	}

	// Disable functionality we're not using (and is difficult to make work on Mac)
	viper.Set("Origin.EnableCmsd", false)
	viper.Set("Origin.EnableMacaroons", false)
	viper.Set("Origin.EnableVoms", false)
	viper.Set("Server.EnableUI", false)
	viper.Set("Registry.DbLocation", filepath.Join(t.TempDir(), "ns-registry.sqlite"))
	viper.Set("Origin.Port", 0)
	viper.Set("Cache.Port", 0)
	viper.Set("Server.WebPort", 0)
	viper.Set("Origin.RunLocation", filepath.Join(tmpPath, "origin"))
	viper.Set("Cache.RunLocation", filepath.Join(tmpPath, "cache"))
	viper.Set("Cache.DataLocation", filepath.Join(tmpPath, "xcache-data"))
	viper.Set("Registry.RequireOriginApproval", false)
	viper.Set("Registry.RequireCacheApproval", false)

	err = config.InitServer(ctx, modules)
	require.NoError(t, err)

	servers, _, err := launchers.LaunchModules(ctx, modules)
	require.NoError(t, err)

	ft.Pids = make([]int, 0, 2)
	for _, server := range servers {
		ft.Pids = append(ft.Pids, server.GetPids()...)
	}

	desiredURL := param.Server_ExternalWebUrl.GetString() + "/api/v1.0/health"
	err = server_utils.WaitUntilWorking(ctx, "GET", desiredURL, "director", 200, false)
	require.NoError(t, err)

	httpc := http.Client{
		Transport: config.GetTransport(),
	}
	resp, err := httpc.Get(desiredURL)
	require.NoError(t, err)

	assert.Equal(t, resp.StatusCode, http.StatusOK)

	responseBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	expectedResponse := struct {
		Msg string `json:"message"`
	}{}
	err = json.Unmarshal(responseBody, &expectedResponse)
	require.NoError(t, err)
	assert.NotEmpty(t, expectedResponse.Msg)

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)
	tokConf := token.NewWLCGToken()
	tokConf.Lifetime = time.Duration(time.Minute)
	tokConf.Issuer = issuer
	tokConf.Subject = "test"
	tokConf.AddAudienceAny()
	tokConf.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Storage_Read, "/hello_world.txt"))

	token, err := tokConf.CreateToken()
	require.NoError(t, err)

	ft.Token = token

	// Explicitly run tmpPath cleanup AFTER cancel and egrp are done -- otherwise we end up
	// with a race condition where removing tmpPath might happen while the server is still
	// using it, resulting in "error: unlinkat <tmpPath>: directory not empty"
	t.Cleanup(func() {
		cancel()
		if err := egrp.Wait(); err != nil && err != context.Canceled && err != http.ErrServerClosed {
			require.NoError(t, err)
		}
		err := os.RemoveAll(tmpPath)
		require.NoError(t, err)
		// Throw in a viper.Reset for good measure. Keeps our env squeaky clean!
		viper.Reset()
	})

	return
}
