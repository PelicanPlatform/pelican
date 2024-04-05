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

package xrootd

import (
	"context"
	"crypto/elliptic"
	_ "embed"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/origin"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/web_ui"
)

var (
	//go:embed resources/multi-export-origin.yml
	multiExportOriginConfig string
)

func originMockup(ctx context.Context, egrp *errgroup.Group, t *testing.T) context.CancelFunc {
	originServer := &origin.OriginServer{}

	// Create our own temp directory (for some reason t.TempDir() does not play well with xrootd)
	tmpPathPattern := "XRD-Tst_Orgn*"
	tmpPath, err := os.MkdirTemp("", tmpPathPattern)
	require.NoError(t, err)

	// Need to set permissions or the xrootd process we spawn won't be able to write PID/UID files
	permissions := os.FileMode(0755)
	err = os.Chmod(tmpPath, permissions)
	require.NoError(t, err)

	viper.Set("ConfigDir", tmpPath)
	viper.Set("Origin.RunLocation", filepath.Join(tmpPath, "xorigin"))
	t.Cleanup(func() {
		os.RemoveAll(tmpPath)
	})

	// Increase the log level; otherwise, its difficult to debug failures
	viper.Set("Logging.Level", "Debug")
	config.InitConfig()
	err = config.InitServer(ctx, config.OriginType)
	require.NoError(t, err)

	err = config.GeneratePrivateKey(param.Server_TLSKey.GetString(), elliptic.P256(), false)
	require.NoError(t, err)
	err = config.GenerateCert()
	require.NoError(t, err)

	engine, err := web_ui.GetEngine()
	require.NoError(t, err)

	server_utils.RegisterOIDCAPI(engine)

	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	defer func() {
		if err != nil {
			shutdownCancel()
		}
	}()

	addr := fmt.Sprintf("%v:%v", param.Server_WebHost.GetString(), param.Server_WebPort.GetInt())
	ln, err := net.Listen("tcp", addr)
	require.NoError(t, err)
	lnReference := ln
	defer func() {
		if lnReference != nil {
			lnReference.Close()
		}
	}()
	config.UpdateConfigFromListener(ln)

	err = CheckXrootdEnv(originServer)
	require.NoError(t, err)

	err = SetUpMonitoring(shutdownCtx, egrp)
	require.NoError(t, err)

	configPath, err := ConfigXrootd(shutdownCtx, true)
	require.NoError(t, err)

	launchers, err := ConfigureLaunchers(false, configPath, false, false)
	require.NoError(t, err)

	_, err = LaunchOriginDaemons(shutdownCtx, launchers, egrp)
	require.NoError(t, err)

	log.Info("Starting web engine...")
	lnReference = nil
	egrp.Go(func() error {
		if err := web_ui.RunEngineRoutineWithListener(ctx, engine, egrp, true, ln); err != nil {
			log.Errorln("Failure when running the web engine:", err)
			return err
		}
		log.Info("Web engine has shutdown")
		shutdownCancel()
		return nil
	})

	return shutdownCancel
}

func TestOrigin(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	viper.Reset()
	server_utils.ResetOriginExports()
	defer viper.Reset()
	defer server_utils.ResetOriginExports()

	viper.Set("Origin.StoragePrefix", t.TempDir())
	viper.Set("Origin.FederationPrefix", "/test")
	viper.Set("Origin.StorageType", "posix")
	// Disable functionality we're not using (and is difficult to make work on Mac)
	viper.Set("Origin.EnableCmsd", false)
	viper.Set("Origin.EnableMacaroons", false)
	viper.Set("Origin.EnableVoms", false)
	viper.Set("Origin.Port", 0)
	viper.Set("Server.WebPort", 0)
	viper.Set("TLSSkipVerify", true)
	viper.Set("Logging.Origin.Scitokens", "debug")

	mockupCancel := originMockup(ctx, egrp, t)
	defer mockupCancel()

	// In this case a 403 means its running
	err := server_utils.WaitUntilWorking(ctx, "GET", param.Origin_Url.GetString(), "xrootd", 403, false)
	if err != nil {
		t.Fatalf("Unsuccessful test: Server encountered an error: %v", err)
	}
	fileTests := server_utils.TestFileTransferImpl{}
	issuerUrl, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	ok, err := fileTests.RunTests(ctx, param.Origin_Url.GetString(), config.GetServerAudience(), issuerUrl, server_utils.OriginSelfFileTest)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestMultiExportOrigin(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	viper.Reset()
	defer viper.Reset()
	server_utils.ResetOriginExports()
	defer server_utils.ResetOriginExports()

	viper.SetConfigType("yaml")
	// Use viper to read in the embedded config
	err := viper.ReadConfig(strings.NewReader(multiExportOriginConfig))
	require.NoError(t, err, "error reading config")

	exports, err := server_utils.GetOriginExports()
	require.NoError(t, err)
	require.Len(t, *exports, 2)
	// Override the object store prefix to a temp directory
	(*exports)[0].StoragePrefix = t.TempDir()
	(*exports)[1].StoragePrefix = t.TempDir()

	// Disable functionality we're not using (and is difficult to make work on Mac)
	viper.Set("Origin.EnableCmsd", false)
	viper.Set("Origin.EnableMacaroons", false)
	viper.Set("Origin.EnableVoms", false)
	viper.Set("Origin.Port", 0)
	viper.Set("Server.WebPort", 0)
	viper.Set("TLSSkipVerify", true)
	viper.Set("Logging.Origin.Scitokens", "debug")

	mockupCancel := originMockup(ctx, egrp, t)
	defer mockupCancel()

	// In this case a 403 means its running
	err = server_utils.WaitUntilWorking(ctx, "GET", param.Origin_Url.GetString(), "xrootd", 403, true)
	if err != nil {
		t.Fatalf("Unsuccessful test: Server encountered an error: %v", err)
	}
	fileTests := server_utils.TestFileTransferImpl{}
	issuerUrl, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	ok, err := fileTests.RunTests(ctx, param.Origin_Url.GetString(), config.GetServerAudience(), issuerUrl, server_utils.OriginSelfFileTest)
	require.NoError(t, err)
	require.True(t, ok)
}

func runS3Test(t *testing.T, ctx context.Context, egrp *errgroup.Group, bucketName, urlStyle, objectName string) {
	viper.Reset()
	server_utils.ResetOriginExports()
	defer viper.Reset()
	defer server_utils.ResetOriginExports()
	federationPrefix := "/test"
	regionName := "us-east-1"
	serviceUrl := "https://s3.amazonaws.com"
	viper.Set("Origin.FederationPrefix", federationPrefix)
	viper.Set("Origin.S3Bucket", bucketName)
	viper.Set("Origin.S3Region", regionName)
	viper.Set("Origin.S3ServiceUrl", serviceUrl)
	viper.Set("Origin.S3UrlStyle", urlStyle)
	viper.Set("Origin.StorageType", "s3")
	viper.Set("Origin.EnablePublicReads", true)

	// Disable functionality we're not using (and is difficult to make work on Mac)
	viper.Set("Origin.EnableCmsd", false)
	viper.Set("Origin.EnableMacaroons", false)
	viper.Set("Origin.EnableVoms", false)
	viper.Set("Origin.SelfTest", false)
	viper.Set("Origin.Port", 0)
	viper.Set("Server.WebPort", 0)
	viper.Set("TLSSkipVerify", true)

	mockupCancel := originMockup(ctx, egrp, t)
	defer mockupCancel()

	originEndpoint := fmt.Sprintf("%s/%s", param.Origin_Url.GetString(), federationPrefix)
	// At this point, a 404 means the server is running, which means its ready to grab objects from
	err := server_utils.WaitUntilWorking(ctx, "GET", originEndpoint, "xrootd", 404, true)
	if err != nil {
		t.Fatalf("Unsucessful test: Server encountered an error: %v", err)
	}

	// Now try to get the object
	originEndpoint = fmt.Sprintf("%s%s/%s", param.Origin_Url.GetString(), federationPrefix, objectName)
	// Set up an HTTP client to request the object from originEndpoint
	transport := config.GetTransport()
	client := &http.Client{Transport: transport}
	req, err := http.NewRequest("GET", originEndpoint, nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)

	// Luckily, this is historic data and there's no reason to believe it will change, so we can
	// grab the body and check for a known value indicating the file correctly downloaded (there is a
	// time travel paradox baked into this -- if someone goes back to 1800 and alters the measurement,
	// will this code be updated automatically?)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(body), "36e5f1edfe5d403b2da163bd50669f66  1800/wod_osd_1800.nc")
}

func TestS3OriginConfig(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	t.Run("S3OriginPathBucket", func(t *testing.T) {
		runS3Test(t, ctx, egrp, "noaa-wod-pds", "path", "MD5SUMS")
	})

	t.Run("S3OriginVirtualBucket", func(t *testing.T) {
		runS3Test(t, ctx, egrp, "noaa-wod-pds", "virtual", "MD5SUMS")
	})

	t.Run("S3OriginNoBucket", func(t *testing.T) {
		runS3Test(t, ctx, egrp, "", "path", "noaa-wod-pds/MD5SUMS")
	})
}
