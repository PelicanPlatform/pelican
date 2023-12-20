/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/pelicanplatform/pelican/config"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFedServePosixOrigin(t *testing.T) {
	viper.Reset()
	moduleMap := map[string]uint16{"registry": 8446, "director": 8445, "origin": 8443}

	// Create our own temp directory (for some reason t.TempDir() does not play well with xrootd)
	tmpPathPattern := "XRootD-Test_Origin*"
	tmpPath, err := os.MkdirTemp("", tmpPathPattern)
	require.NoError(t, err)

	// Need to set permissions or the xrootd process we spawn won't be able to write PID/UID files
	permissions := os.FileMode(0777)
	err = os.Chmod(tmpPath, permissions)
	require.NoError(t, err)

	viper.Set("ConfigDir", tmpPath)
	viper.Set("Xrootd.RunLocation", filepath.Join(tmpPath, "xrootd"))
	t.Cleanup(func() {
		os.RemoveAll(tmpPath)
	})

	// Increase the log level; otherwise, its difficult to debug failures
	viper.Set("Logging.Level", "Debug")
	config.InitConfig()

	viper.Set("Origin.ExportVolume", t.TempDir()+":/test")
	viper.Set("Origin.Mode", "posix")
	// Disable functionality we're not using (and is difficult to make work on Mac)
	viper.Set("Origin.EnableCmsd", false)
	viper.Set("Origin.EnableMacaroons", false)
	viper.Set("Origin.EnableVoms", false)
	viper.Set("TLSSkipVerify", true)
	viper.Set("Server.EnableUI", false)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		err = fedServeInternal(ctx, moduleMap)
		require.NoError(t, err)
	}()
	defer cancel()

	time.Sleep(2 * time.Second)
	hostname, err := os.Hostname()
	require.NoError(t, err)

	curlString := "https://" + hostname + ":8445/.well-known/openid-configuration"

	curl := exec.Command("curl", "-v", "-k", curlString)
	out, err := curl.Output()
	require.NoError(t, err)

	assert.Contains(t, string(out), "jwks_uri")

	viper.Reset()
}
