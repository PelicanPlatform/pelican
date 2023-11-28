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

package xrootd

import (
	"context"
	"crypto/elliptic"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/origin_ui"
	"github.com/pelicanplatform/pelican/param"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestOrigin(t *testing.T) {
	viper.Reset()

	viper.Set("Origin.ExportVolume", t.TempDir()+":/test")
	// Disable functionality we're not using (and is difficult to make work on Mac)
	viper.Set("Origin.EnableCmsd", false)
	viper.Set("Origin.EnableMacaroons", false)
	viper.Set("Origin.EnableVoms", false)
	viper.Set("TLSSkipVerify", true)

	// Create our own temp directory (for some reason t.TempDir() does not play well with xrootd)
	tmpPath := "/tmp/XRootD-Test_Origin"
	viper.Set("ConfigDir", tmpPath)
	viper.Set("Xrootd.RunLocation", filepath.Join(tmpPath, "xrootd"))
	t.Cleanup(func() {
		os.RemoveAll(tmpPath)
	})
	// Increase the log level; otherwise, its difficult to debug failures
	viper.Set("Logging.Level", "Debug")
	config.InitConfig()
	err := config.InitServer()

	require.NoError(t, err)

	err = config.GeneratePrivateKey(param.Server_TLSKey.GetString(), elliptic.P256())
	require.NoError(t, err)
	err = config.GenerateCert()
	require.NoError(t, err)

	err = CheckXrootdEnv(true, nil)
	require.NoError(t, err)

	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	defer shutdownCancel()
	var wg sync.WaitGroup
	wg.Add(1)
	err = SetUpMonitoring(shutdownCtx, &wg)
	require.NoError(t, err)

	configPath, err := ConfigXrootd(true)
	require.NoError(t, err)

	launchers, err := ConfigureLaunchers(false, configPath, false)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = daemon.LaunchDaemons(ctx, launchers)
	}()
	defer cancel()

	testExpiry := time.Now().Add(10 * time.Second)
	testSuccess := false
	for !(testSuccess || time.Now().After(testExpiry)) {
		time.Sleep(50 * time.Millisecond)
		req, err := http.NewRequest("GET", param.Origin_Url.GetString(), nil)
		require.NoError(t, err)
		httpClient := http.Client{
			Transport: config.GetTransport(),
			Timeout:   50 * time.Millisecond,
		}
		_, err = httpClient.Do(req)
		if err != nil {
			log.Infoln("Failed to send request to XRootD; likely, server is not up (will retry in 50ms):", err)
		} else {
			testSuccess = true
			log.Debugln("XRootD server appears to be functioning; will proceed with test")
		}
	}

	if testSuccess {
		url, err := origin_ui.UploadTestfile()
		require.NoError(t, err)
		err = origin_ui.DownloadTestfile(url)
		require.NoError(t, err)
		err = origin_ui.DeleteTestfile(url)
		require.NoError(t, err)
	} else {
		t.Fatalf("Unsucessful test: timeout when trying to send request to xrootd")
	}
}
