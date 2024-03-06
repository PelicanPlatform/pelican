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

package local_cache_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/launchers"
	local_cache "github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

type (
	fedTest struct {
		originDir string
		token     string
	}
)

func (ft *fedTest) spinup(t *testing.T, ctx context.Context, egrp *errgroup.Group) {

	modules := config.ServerType(0)
	modules.Set(config.OriginType)
	modules.Set(config.DirectorType)
	modules.Set(config.RegistryType)
	// TODO: the cache startup routines not sequenced correctly for the downloads
	// to immediately work through the cache.  For now, unit tests will just use the origin.
	viper.Set("Origin.EnableFallbackRead", true)
	/*
		if runtime.GOOS == "darwin" {
			viper.Set("Origin.EnableFallbackRead", true)
		} else {
			modules.Set(config.CacheType)
		}
	*/
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
	tokConf := token.TokenConfig{
		TokenProfile: token.WLCG,
		Lifetime:     time.Duration(time.Minute),
		Issuer:       issuer,
		Subject:      "test",
		Audience:     []string{token.WLCGAny},
	}
	tokConf.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Storage_Read, "/hello_world.txt"))

	token, err := tokConf.CreateToken()
	require.NoError(t, err)

	ft.originDir = originDir
	ft.token = token
}

// Setup a federation, invoke "get" through the local cache module
//
// The download is done twice -- once to verify functionality and once
// as a cache hit.
func TestFedPublicGet(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer cancel()

	viper.Reset()
	viper.Set("Origin.EnablePublicReads", true)
	ft := fedTest{}
	ft.spinup(t, ctx, egrp)

	lc, err := local_cache.NewLocalCache(ctx, egrp)
	require.NoError(t, err)

	reader, err := lc.Get("/test/hello_world.txt", "")
	require.NoError(t, err)

	byteBuff, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, "Hello, World!", string(byteBuff))

	// Query again -- cache hit case
	reader, err = lc.Get("/test/hello_world.txt", "")
	require.NoError(t, err)

	assert.Equal(t, "*os.File", fmt.Sprintf("%T", reader))
	byteBuff, err = io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, "Hello, World!", string(byteBuff))
}

// Test the local cache library on an authenticated GET.
func TestFedAuthGet(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer cancel()

	viper.Reset()
	viper.Set("Origin.EnablePublicReads", false)
	ft := fedTest{}
	ft.spinup(t, ctx, egrp)

	lc, err := local_cache.NewLocalCache(ctx, egrp)
	require.NoError(t, err)

	reader, err := lc.Get("/test/hello_world.txt", ft.token)
	require.NoError(t, err)

	byteBuff, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, "Hello, World!", string(byteBuff))

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)
	tokConf := token.TokenConfig{
		TokenProfile: token.WLCG,
		Lifetime:     time.Duration(time.Minute),
		Issuer:       issuer,
		Subject:      "test",
		Audience:     []string{token.WLCGAny},
	}
	tokConf.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Storage_Read, "/not_correct"))

	token, err := tokConf.CreateToken()
	require.NoError(t, err)

	_, err = lc.Get("/test/hello_world.txt", token)
	assert.Error(t, err)
	assert.Equal(t, "authorization denied", err.Error())
}

// Test a raw HTTP request (no Pelican client) works with the local cache
func TestHttpReq(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer cancel()

	viper.Reset()
	viper.Set("Origin.EnablePublicReads", false)
	ft := fedTest{}
	ft.spinup(t, ctx, egrp)

	transport := config.GetTransport().Clone()
	transport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", param.LocalCache_Socket.GetString())
	}

	client := &http.Client{Transport: transport}
	req, err := http.NewRequest("GET", "http://localhost/test/hello_world.txt", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+ft.token)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, "Hello, World!", string(body))
}

// Test that the client library (with authentication) works with the local cache
func TestClient(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer cancel()
	tmpDir := t.TempDir()

	viper.Reset()
	viper.Set("Origin.EnablePublicReads", false)
	ft := fedTest{}
	ft.spinup(t, ctx, egrp)

	cacheUrl := &url.URL{
		Scheme: "unix",
		Path:   param.LocalCache_Socket.GetString(),
	}

	t.Run("correct-auth", func(t *testing.T) {
		discoveryHost := param.Federation_DiscoveryUrl.GetString()
		discoveryUrl, err := url.Parse(discoveryHost)
		require.NoError(t, err)
		tr, err := client.DoGet(ctx, "pelican://"+discoveryUrl.Host+"/test/hello_world.txt", filepath.Join(tmpDir, "hello_world.txt"), false,
			client.WithToken(ft.token), client.WithCaches(cacheUrl), client.WithAcquireToken(false))
		assert.NoError(t, err)
		require.Equal(t, 1, len(tr))
		assert.Equal(t, int64(13), tr[0].TransferredBytes)
		assert.NoError(t, tr[0].Error)

		byteBuff, err := os.ReadFile(filepath.Join(tmpDir, "hello_world.txt"))
		assert.NoError(t, err)
		assert.Equal(t, "Hello, World!", string(byteBuff))
	})
	t.Run("incorrect-auth", func(t *testing.T) {
		_, err := client.DoGet(ctx, "pelican:///test/hello_world.txt", filepath.Join(tmpDir, "hello_world.txt"), false,
			client.WithToken("badtoken"), client.WithCaches(cacheUrl), client.WithAcquireToken(false))
		assert.Error(t, err)
		assert.ErrorIs(t, err, &client.ConnectionSetupError{})
		var cse *client.ConnectionSetupError
		assert.True(t, errors.As(err, &cse))
		assert.Equal(t, "failed connection setup: server returned 403 Forbidden", cse.Error())
	})

	t.Run("file-not-found", func(t *testing.T) {
		issuer, err := config.GetServerIssuerURL()
		require.NoError(t, err)
		tokConf := token.TokenConfig{
			TokenProfile: token.WLCG,
			Lifetime:     time.Duration(time.Minute),
			Issuer:       issuer,
			Subject:      "test",
			Audience:     []string{token.WLCGAny},
		}
		tokConf.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Storage_Read, "/hello_world.txt.1"))

		token, err := tokConf.CreateToken()
		require.NoError(t, err)

		_, err = client.DoGet(ctx, "pelican:///test/hello_world.txt.1", filepath.Join(tmpDir, "hello_world.txt.1"), false,
			client.WithToken(token), client.WithCaches(cacheUrl), client.WithAcquireToken(false))
		assert.Error(t, err)
		assert.Equal(t, "failed to download file: transfer error: failed connection setup: server returned 404 Not Found", err.Error())
	})
}

// Test that HEAD requests to the local cache return the correct result
func TestStat(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer cancel()

	viper.Reset()
	viper.Set("Origin.EnablePublicReads", true)
	ft := fedTest{}
	ft.spinup(t, ctx, egrp)

	lc, err := local_cache.NewLocalCache(ctx, egrp)
	require.NoError(t, err)

	size, err := lc.Stat("/test/hello_world.txt", "")
	require.NoError(t, err)
	assert.Equal(t, uint64(13), size)

	reader, err := lc.Get("/test/hello_world.txt", "")
	require.NoError(t, err)
	byteBuff, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, 13, len(byteBuff))

	size, err = lc.Stat("/test/hello_world.txt", "")
	assert.NoError(t, err)
	assert.Equal(t, uint64(13), size)
}

// Creates a buffer of at least 1MB
func makeBigBuffer() []byte {
	byteBuff := []byte("Hello, World!")
	for {
		byteBuff = append(byteBuff, []byte("Hello, World!")...)
		if len(byteBuff) > 1024*1024 {
			break
		}
	}
	return byteBuff
}

// Writes a file at least the specified size in MB
func writeBigBuffer(t *testing.T, fp io.WriteCloser, sizeMB int) (size int) {
	defer fp.Close()
	byteBuff := makeBigBuffer()
	size = 0
	for {
		n, err := fp.Write(byteBuff)
		require.NoError(t, err)
		size += n
		if size > sizeMB*1024*1024 {
			break
		}
	}
	return
}

// Create a 100MB file in the origin.  Download it (slowly) via the local cache.
//
// This triggers multiple internal requests to wait on the slow download
func TestLargeFile(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer cancel()
	tmpDir := t.TempDir()

	viper.Reset()
	viper.Set("Origin.EnablePublicReads", true)
	viper.Set("Client.MaximumDownloadSpeed", 40*1024*1024)
	ft := fedTest{}
	ft.spinup(t, ctx, egrp)

	cacheUrl := &url.URL{
		Scheme: "unix",
		Path:   param.LocalCache_Socket.GetString(),
	}

	fp, err := os.OpenFile(filepath.Join(ft.originDir, "hello_world.txt"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	require.NoError(t, err)
	size := writeBigBuffer(t, fp, 100)

	discoveryHost := param.Federation_DiscoveryUrl.GetString()
	discoveryUrl, err := url.Parse(discoveryHost)
	require.NoError(t, err)
	tr, err := client.DoGet(ctx, "pelican://"+discoveryUrl.Host+"/test/hello_world.txt", filepath.Join(tmpDir, "hello_world.txt"), false,
		client.WithCaches(cacheUrl))
	assert.NoError(t, err)
	require.Equal(t, 1, len(tr))
	assert.Equal(t, int64(size), tr[0].TransferredBytes)
	assert.NoError(t, tr[0].Error)

}

// Create five 1MB files.  Trigger a purge, ensuring that the cleanup is
// done according to LRU
func TestPurge(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer cancel()
	tmpDir := t.TempDir()

	viper.Reset()
	viper.Set("Origin.EnablePublicReads", true)
	viper.Set("LocalCache.Size", "5MB")
	ft := fedTest{}
	ft.spinup(t, ctx, egrp)

	cacheUrl := &url.URL{
		Scheme: "unix",
		Path:   param.LocalCache_Socket.GetString(),
	}

	size := 0
	for idx := 0; idx < 5; idx++ {
		log.Debugln("Will write origin file", filepath.Join(ft.originDir, fmt.Sprintf("hello_world.txt.%d", idx)))
		fp, err := os.OpenFile(filepath.Join(ft.originDir, fmt.Sprintf("hello_world.txt.%d", idx)), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		require.NoError(t, err)
		size = writeBigBuffer(t, fp, 1)
	}
	require.NotEqual(t, 0, size)

	for idx := 0; idx < 5; idx++ {
		tr, err := client.DoGet(ctx, fmt.Sprintf("pelican:///test/hello_world.txt.%d", idx), filepath.Join(tmpDir, fmt.Sprintf("hello_world.txt.%d", idx)), false,
			client.WithCaches(cacheUrl))
		assert.NoError(t, err)
		require.Equal(t, 1, len(tr))
		assert.Equal(t, int64(size), tr[0].TransferredBytes)
		assert.NoError(t, tr[0].Error)
	}

	// Size of the cache should be just small enough that the 5th file triggers LRU deletion of the first.
	for idx := 0; idx < 5; idx++ {
		func() {
			fp, err := os.Open(filepath.Join(param.LocalCache_DataLocation.GetString(), "test", fmt.Sprintf("hello_world.txt.%d.DONE", idx)))
			if idx == 0 {
				log.Errorln("Error:", err)
				assert.ErrorIs(t, err, os.ErrNotExist)
			} else {
				assert.NoError(t, err)
			}
			defer fp.Close()
		}()
	}
}

// Create four 1MB files (above low-water mark).  Force a purge, ensuring that the cleanup is
// done according to LRU
func TestForcePurge(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer cancel()
	tmpDir := t.TempDir()

	viper.Reset()
	viper.Set("Origin.EnablePublicReads", true)
	viper.Set("LocalCache.Size", "5MB")
	// Decrease the low water mark so invoking purge will result in 3 files in the cache.
	viper.Set("LocalCache.LowWaterMarkPercentage", "80")
	ft := fedTest{}
	ft.spinup(t, ctx, egrp)

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)
	tokConf := token.TokenConfig{
		TokenProfile: token.WLCG,
		Lifetime:     time.Duration(time.Minute),
		Issuer:       issuer,
		Subject:      "test",
		Audience:     []string{token.WLCGAny},
	}
	tokConf.AddScopes(token_scopes.Localcache_Purge)

	token, err := tokConf.CreateToken()
	require.NoError(t, err)

	cacheUrl := &url.URL{
		Scheme: "unix",
		Path:   param.LocalCache_Socket.GetString(),
	}

	// Populate the cache with our test files
	size := 0
	for idx := 0; idx < 4; idx++ {
		log.Debugln("Will write origin file", filepath.Join(ft.originDir, fmt.Sprintf("hello_world.txt.%d", idx)))
		fp, err := os.OpenFile(filepath.Join(ft.originDir, fmt.Sprintf("hello_world.txt.%d", idx)), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		require.NoError(t, err)
		size = writeBigBuffer(t, fp, 1)
	}
	require.NotEqual(t, 0, size)

	for idx := 0; idx < 4; idx++ {
		tr, err := client.DoGet(ctx, fmt.Sprintf("pelican:///test/hello_world.txt.%d", idx), filepath.Join(tmpDir, fmt.Sprintf("hello_world.txt.%d", idx)), false,
			client.WithCaches(cacheUrl))
		assert.NoError(t, err)
		require.Equal(t, 1, len(tr))
		assert.Equal(t, int64(size), tr[0].TransferredBytes)
		assert.NoError(t, tr[0].Error)
	}

	// Size of the cache should be large enough that purge hasn't fired yet.
	for idx := 0; idx < 4; idx++ {
		func() {
			fp, err := os.Open(filepath.Join(param.LocalCache_DataLocation.GetString(), "test", fmt.Sprintf("hello_world.txt.%d.DONE", idx)))
			assert.NoError(t, err)
			defer fp.Close()
		}()
	}

	_, err = utils.MakeRequest(ctx, param.Server_ExternalWebUrl.GetString()+"/api/v1.0/localcache/purge", "POST", nil, map[string]string{"Authorization": "Bearer " + token})
	require.NoError(t, err)

	// Low water mark is small enough that a force purge will delete a file.
	for idx := 0; idx < 4; idx++ {
		func() {
			fp, err := os.Open(filepath.Join(param.LocalCache_DataLocation.GetString(), "test", fmt.Sprintf("hello_world.txt.%d.DONE", idx)))
			if idx == 0 {
				assert.ErrorIs(t, err, os.ErrNotExist)
			} else {
				assert.NoError(t, err)
			}
			defer fp.Close()
		}()
	}
}
