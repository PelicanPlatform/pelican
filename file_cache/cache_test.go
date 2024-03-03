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

package simple_cache_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	simple_cache "github.com/pelicanplatform/pelican/file_cache"
	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func spinup(t *testing.T, ctx context.Context, egrp *errgroup.Group) (token string) {

	modules := config.ServerType(0)
	modules.Set(config.OriginType)
	modules.Set(config.DirectorType)
	modules.Set(config.RegistryType)
	if runtime.GOOS == "darwin" {
		viper.Set("Origin.EnableFallbackRead", true)
	} else {
		modules.Set(config.CacheType)
	}
	modules.Set(config.LocalCacheType)

	tmpPathPattern := "XRootD-Test_Origin*"
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
	permissions = os.FileMode(0777)
	err = os.Chmod(originDir, permissions)
	require.NoError(t, err)

	viper.Set("Origin.ExportVolume", originDir+":/test")
	viper.Set("Origin.Mode", "posix")
	// Disable functionality we're not using (and is difficult to make work on Mac)
	viper.Set("Origin.EnableCmsd", false)
	viper.Set("Origin.EnableMacaroons", false)
	viper.Set("Origin.EnableVoms", false)
	viper.Set("Server.EnableUI", false)
	viper.Set("Registry.DbLocation", filepath.Join(t.TempDir(), "ns-registry.sqlite"))
	viper.Set("Origin.Port", 0)
	viper.Set("Server.WebPort", 0)
	viper.Set("Origin.RunLocation", tmpPath)
	viper.Set("Cache.RunLocation", tmpPath)
	viper.Set("Registry.RequireOriginApproval", false)
	viper.Set("Registry.RequireCacheApproval", false)

	err = config.InitServer(ctx, modules)
	require.NoError(t, err)

	cancel, err := launchers.LaunchModules(ctx, modules)
	require.NoError(t, err)
	t.Cleanup(func() {
		cancel()
		if err = egrp.Wait(); err != nil && err != context.Canceled && err != http.ErrServerClosed {
			require.NoError(t, err)
		}
	})

	err = os.WriteFile(filepath.Join(originDir, "hello_world.txt"), []byte("Hello, World!"), os.FileMode(0644))
	require.NoError(t, err)

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)
	tokConf := utils.TokenConfig{
		TokenProfile: utils.WLCG,
		Lifetime:     time.Duration(time.Minute),
		Issuer:       issuer,
		Subject:      "test",
		Audience:     []string{utils.WLCGAny},
	}
	tokConf.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Storage_Read, "/hello_world.txt"))

	token, err = tokConf.CreateToken()
	require.NoError(t, err)

	return
}

// Setup a federation, invoke "get" through the local cache module
//
// The download is done twice -- once to verify functionality and once
// as a cache hit.
func TestFedPublicGet(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer cancel()

	viper.Set("Origin.EnablePublicReads", true)
	spinup(t, ctx, egrp)

	sc, err := simple_cache.NewSimpleCache(ctx, egrp)
	require.NoError(t, err)

	reader, err := sc.Get("/test/hello_world.txt", "")
	require.NoError(t, err)

	byteBuff, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, "Hello, World!", string(byteBuff))

	// Query again -- cache hit case
	reader, err = sc.Get("/test/hello_world.txt", "")
	require.NoError(t, err)

	assert.Equal(t, "*os.File", fmt.Sprintf("%T", reader))
	byteBuff, err = io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, "Hello, World!", string(byteBuff))
}

func TestFedAuthGet(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer cancel()

	viper.Set("Origin.EnablePublicReads", false)
	token := spinup(t, ctx, egrp)

	lc, err := simple_cache.NewSimpleCache(ctx, egrp)
	require.NoError(t, err)

	reader, err := lc.Get("/test/hello_world.txt", token)
	require.NoError(t, err)

	byteBuff, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, "Hello, World!", string(byteBuff))

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)
	tokConf := utils.TokenConfig{
		TokenProfile: utils.WLCG,
		Lifetime:     time.Duration(time.Minute),
		Issuer:       issuer,
		Subject:      "test",
		Audience:     []string{utils.WLCGAny},
	}
	tokConf.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Storage_Read, "/not_correct"))

	token, err = tokConf.CreateToken()
	require.NoError(t, err)

	_, err = lc.Get("/test/hello_world.txt", token)
	assert.Error(t, err)
	assert.Equal(t, "authorization denied", err.Error())
}

func TestHttpReq(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer cancel()

	viper.Set("Origin.EnablePublicReads", false)
	token := spinup(t, ctx, egrp)

	transport := config.GetTransport().Clone()
	transport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", param.FileCache_Socket.GetString())
	}

	client := &http.Client{Transport: transport}
	req, err := http.NewRequest("GET", "http://localhost/test/hello_world.txt", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, "Hello, World!", string(body))
}

func TestClient(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer cancel()
	tmpDir := t.TempDir()

	viper.Set("Origin.EnablePublicReads", false)
	token := spinup(t, ctx, egrp)

	cacheUrl := &url.URL{
		Scheme: "unix",
		Path:   param.FileCache_Socket.GetString(),
	}

	discoveryHost := param.Federation_DiscoveryUrl.GetString()
	discoveryUrl, err := url.Parse(discoveryHost)
	require.NoError(t, err)
	tr, err := client.DoGet(ctx, "pelican://"+discoveryUrl.Host+"/test/hello_world.txt", filepath.Join(tmpDir, "hello_world.txt"), false, client.WithToken(token), client.WithCaches(cacheUrl), client.WithAcquireToken(false))
	assert.NoError(t, err)
	require.Equal(t, 1, len(tr))
	assert.Equal(t, int64(13), tr[0].TransferredBytes)
	assert.NoError(t, tr[0].Error)

	byteBuff, err := os.ReadFile(filepath.Join(tmpDir, "hello_world.txt"))
	assert.NoError(t, err)
	assert.Equal(t, "Hello, World!", string(byteBuff))
}
