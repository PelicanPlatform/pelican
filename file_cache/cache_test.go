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
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/pelicanplatform/pelican/config"
	simple_cache "github.com/pelicanplatform/pelican/file_cache"
	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func spinup(t *testing.T, ctx context.Context, egrp *errgroup.Group) string {

	modules := config.ServerType(0)
	modules.Set(config.OriginType)
	modules.Set(config.DirectorType)
	modules.Set(config.RegistryType)
	modules.Set(config.CacheType)
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
		egrp.Wait()
	})

	return originDir
}

func TestFileCacheSimpleGet(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer cancel()

	originDir := spinup(t, ctx, egrp)

	err := os.WriteFile(filepath.Join(originDir, "hello_world.txt"), []byte("Hello, World!"), os.FileMode(0644))
	require.NoError(t, err)

	sc, err := simple_cache.NewSimpleCache(ctx, egrp)
	require.NoError(t, err)

	reader, err := sc.Get("/test/hello_world.txt", "")
	require.NoError(t, err)

	byteBuff, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, "Hello, World!", string(byteBuff))
}
