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
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

type (
	FedTest struct {
		OriginDir string
		Token     string
		Ctx       context.Context
		Egrp      *errgroup.Group
	}
)

func NewFedTest(t *testing.T) (ft *FedTest) {
	ft = &FedTest{}

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	t.Cleanup(func() {
		cancel()
		if err := egrp.Wait(); err != nil && err != context.Canceled && err != http.ErrServerClosed {
			require.NoError(t, err)
		}
	})

	ft.Ctx = ctx
	ft.Egrp = egrp

	modules := config.ServerType(0)
	modules.Set(config.OriginType)
	modules.Set(config.DirectorType)
	modules.Set(config.RegistryType)
	// TODO: the cache startup routines not sequenced correctly for the downloads
	// to immediately work through the cache.  For now, unit tests will just use the origin.
	viper.Set("Origin.EnableFallbackRead", true)
	modules.Set(config.LocalCacheType)

	tmpPathPattern := "PelicanOrigin-FedTest*"
	tmpPath, err := os.MkdirTemp("", tmpPathPattern)
	require.NoError(t, err)

	permissions := os.FileMode(0755)
	err = os.Chmod(tmpPath, permissions)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := os.RemoveAll(tmpPath)
		require.NoError(t, err)
	})

	viper.Set("ConfigDir", tmpPath)

	config.InitConfig()

	originDir, err := os.MkdirTemp("", "Origin")
	assert.NoError(t, err)
	t.Cleanup(func() {
		err := os.RemoveAll(originDir)
		require.NoError(t, err)
	})

	// Change the permissions of the temporary origin directory
	permissions = os.FileMode(0755)
	err = os.Chmod(originDir, permissions)
	require.NoError(t, err)

	viper.Set("Origin.ExportVolume", originDir+":/test")
	viper.Set("Origin.Mode", "posix")
	viper.Set("Origin.EnableFallbackRead", true)
	// Disable functionality we're not using (and is difficult to make work on Mac)
	viper.Set("Origin.EnableCmsd", false)
	viper.Set("Origin.EnableMacaroons", false)
	viper.Set("Origin.EnableVoms", false)
	viper.Set("Server.EnableUI", false)
	viper.Set("Registry.DbLocation", filepath.Join(t.TempDir(), "ns-registry.sqlite"))
	viper.Set("Origin.Port", 0)
	viper.Set("Server.WebPort", 0)
	viper.Set("Origin.RunLocation", tmpPath)
	viper.Set("Registry.RequireOriginApproval", false)
	viper.Set("Registry.RequireCacheApproval", false)

	err = config.InitServer(ctx, modules)
	require.NoError(t, err)

	_, err = launchers.LaunchModules(ctx, modules)
	require.NoError(t, err)

	desiredURL := param.Server_ExternalWebUrl.GetString() + "/api/v1.0/health"
	err = server_utils.WaitUntilWorking(ctx, "GET", desiredURL, "director", 200)
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

	err = os.WriteFile(filepath.Join(originDir, "hello_world.txt"), []byte("Hello, World!"), os.FileMode(0644))
	require.NoError(t, err)

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

	ft.OriginDir = originDir
	ft.Token = token

	return
}
