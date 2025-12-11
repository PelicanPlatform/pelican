/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

func TestServeFlagsRefreshParamCache(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Avoid leaking args into other cmd tests (Cobra will prefer SetArgs over os.Args).
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	// ResetTestState() resets the global viper instance; re-bind the serve flags to viper
	// so flag values are visible through viper.Get() and therefore through param.Refresh().
	require.NoError(t, viper.BindPFlag(param.Server_Modules.GetName(), serveCmd.Flags().Lookup("module")))
	require.NoError(t, viper.BindPFlag(param.Server_WebPort.GetName(), serveCmd.Flags().Lookup("port")))

	oldRunE := serveCmd.RunE
	serveCmd.RunE = func(cmd *cobra.Command, args []string) error {
		require.ElementsMatch(t, []string{"director", "registry", "origin"}, param.Server_Modules.GetStringSlice())
		require.Equal(t, 60451, param.Server_WebPort.GetInt())
		return nil
	}
	t.Cleanup(func() { serveCmd.RunE = oldRunE })

	cfgPath := filepath.Join(t.TempDir(), "empty.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(""), 0644))

	rootCmd.SetArgs([]string{
		"--config", cfgPath,
		"serve",
		"--module", "director",
		"--module", "registry",
		"--module", "origin",
		"--port", "60451",
	})
	require.NoError(t, rootCmd.Execute())
}
