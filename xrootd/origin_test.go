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
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/origin"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/web_ui"
)

var (
	//go:embed resources/multi-export-origin.yml
	multiExportOriginConfig string
)

func ensureXrdS3PluginAvailable(t *testing.T) {
	searchPaths := []string{
		"/usr/lib",
		"/usr/lib64",
		"/usr/local/lib",
		"/opt/homebrew/lib",
	}

	appendEnvPaths := func(env string) {
		for _, path := range strings.Split(os.Getenv(env), ":") {
			if path != "" {
				searchPaths = append(searchPaths, path)
			}
		}
	}

	appendEnvPaths("XRD_PLUGINPATH")
	appendEnvPaths("LD_LIBRARY_PATH")
	appendEnvPaths("DYLD_LIBRARY_PATH")

	pluginNames := []string{"libXrdS3.so", "libXrdS3-5.so", "libXrdS3-6.so", "libXrdS3.dylib", "libXrdS3-5.dylib", "libXrdS3-6.dylib"}
	for _, dir := range searchPaths {
		for _, name := range pluginNames {
			if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
				return
			}
		}
	}

	t.Skip("Skipping: XRootD S3 plugin not found on this system")
}

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

	require.NoError(t, param.Set("ConfigDir", tmpPath))
	require.NoError(t, param.Set(param.Origin_RunLocation.GetName(), filepath.Join(tmpPath, "xorigin")))
	t.Cleanup(func() {
		os.RemoveAll(tmpPath)
	})

	test_utils.MockFederationRoot(t, nil, nil)

	// Increase the log level; otherwise, its difficult to debug failures
	require.NoError(t, param.Set(param.Logging_Level.GetName(), "Debug"))
	err = config.InitServer(ctx, server_structs.OriginType)
	require.NoError(t, err)

	err = config.GeneratePrivateKey(param.Server_TLSKey.GetString(), elliptic.P256(), false)
	require.NoError(t, err)
	err = config.GenerateCert()
	require.NoError(t, err)

	engine, err := web_ui.GetEngine()
	require.NoError(t, err)

	server_utils.RegisterOIDCAPI(engine.Group("/"), false)

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
	// Clear cached issuer URL so it gets recalculated with the actual port
	require.NoError(t, param.Set(param.Server_IssuerUrl.GetName(), ""))

	err = CheckXrootdEnv(originServer)
	require.NoError(t, err)

	err = SetUpMonitoring(shutdownCtx, egrp)
	require.NoError(t, err)

	configPath, err := ConfigXrootd(shutdownCtx, true)
	require.NoError(t, err)

	launchers, err := ConfigureLaunchers(false, configPath, false, false)
	require.NoError(t, err)

	portStartCallback := func(port int) {
		require.NoError(t, param.Set(param.Origin_Port.GetName(), port))
		if originUrl, err := url.Parse(param.Origin_Url.GetString()); err == nil {
			originUrl.Host = originUrl.Hostname() + ":" + strconv.Itoa(port)
			require.NoError(t, param.Set("Origin.Url", originUrl.String()))
			log.Debugln("Resetting Origin.Url to", originUrl.String())
		}
		log.Infoln("Origin startup complete on port", port)
	}

	_, err = LaunchDaemons(shutdownCtx, launchers, egrp, portStartCallback)
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
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	server_utils.ResetTestState()

	defer server_utils.ResetTestState()

	// Create temp dir with 0777 permissions so XRootD daemon user can write
	viper.Set(param.Origin_StoragePrefix.GetName(), test_utils.GetTmpStoragePrefixDir(t))
	viper.Set(param.Origin_FederationPrefix.GetName(), "/test")
	viper.Set(param.Origin_StorageType.GetName(), "posix")
	// Disable functionality we're not using (and is difficult to make work on Mac)
	require.NoError(t, param.Set(param.Origin_EnableCmsd.GetName(), false))
	require.NoError(t, param.Set(param.Origin_EnableMacaroons.GetName(), false))
	require.NoError(t, param.Set(param.Origin_EnableVoms.GetName(), false))
	require.NoError(t, param.Set(param.Origin_Port.GetName(), 0))
	require.NoError(t, param.Set(param.Server_WebPort.GetName(), 0))
	require.NoError(t, param.Set(param.TLSSkipVerify.GetName(), true))
	require.NoError(t, param.Set(param.Logging_Origin_Scitokens.GetName(), "debug"))

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

	ok, err := fileTests.RunTests(ctx, param.Origin_Url.GetString(), param.Origin_TokenAudience.GetString(), issuerUrl, server_utils.ServerSelfTest)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestMultiExportOrigin(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	viper.SetConfigType("yaml")
	// Use viper to read in the embedded config
	err := viper.ReadConfig(strings.NewReader(multiExportOriginConfig))
	require.NoError(t, err, "error reading config")

	// Replace storage prefixes with temp directories that have proper permissions
	// for the daemon user (xrootd) before calling GetOriginExports()
	exports := viper.Get("origin.exports").([]interface{})
	for _, export := range exports {
		exportMap := export.(map[string]interface{})
		for k, v := range exportMap {
			if v == "/<WILL BE REPLACED IN TEST>" {
				exportMap[k] = test_utils.GetTmpStoragePrefixDir(t)
			}
		}
	}
	viper.Set("origin.exports", exports)

	// Get available, unique ports and pre-allocate for xrootd startup.
	ports, err := test_utils.GetUniqueAvailablePorts(2)
	require.NoError(t, err)
	require.Len(t, ports, 2)

	// Disable functionality we're not using for the tests
	require.NoError(t, param.Set(param.Origin_EnableCmsd.GetName(), false))
	require.NoError(t, param.Set(param.Origin_EnableVoms.GetName(), false))
	require.NoError(t, param.Set(param.Origin_Port.GetName(), 0))
	require.NoError(t, param.Set(param.Server_WebPort.GetName(), 0))
	require.NoError(t, param.Set(param.TLSSkipVerify.GetName(), true))
	require.NoError(t, param.Set(param.Logging_Origin_Scitokens.GetName(), "debug"))

	test_utils.MockFederationRoot(t, nil, nil)

	// Initialize the origin before getting origin exports
	require.NoError(t, param.Set("ConfigDir", t.TempDir()))
	err = config.InitServer(ctx, server_structs.OriginType)
	require.NoError(t, err)

	originExports, err := server_utils.GetOriginExports()
	require.NoError(t, err)
	require.Len(t, originExports, 2)

	// No need to override StoragePrefix directly; object store prefix was set via exportMap update above

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

	ok, err := fileTests.RunTests(ctx, param.Origin_Url.GetString(), param.Origin_TokenAudience.GetString(), issuerUrl, server_utils.ServerSelfTest)
	require.NoError(t, err)
	require.True(t, ok)
}

func mockupS3Origin(ctx context.Context, egrp *errgroup.Group, t *testing.T, federationPrefix, bucketName, urlStyle string) context.CancelFunc {
	regionName := "us-east-1"
	serviceUrl := "https://s3.amazonaws.com"
	require.NoError(t, param.Set(param.Origin_FederationPrefix.GetName(), federationPrefix))
	require.NoError(t, param.Set(param.Origin_S3Bucket.GetName(), bucketName))
	require.NoError(t, param.Set(param.Origin_S3Region.GetName(), regionName))
	require.NoError(t, param.Set(param.Origin_S3ServiceUrl.GetName(), serviceUrl))
	require.NoError(t, param.Set(param.Origin_S3UrlStyle.GetName(), urlStyle))
	require.NoError(t, param.Set(param.Origin_StorageType.GetName(), "s3"))
	require.NoError(t, param.Set(param.Origin_EnablePublicReads.GetName(), true))

	// Disable functionality we're not using (and is difficult to make work on Mac)
	require.NoError(t, param.Set(param.Origin_EnableCmsd.GetName(), false))
	require.NoError(t, param.Set(param.Origin_EnableMacaroons.GetName(), false))
	require.NoError(t, param.Set(param.Origin_EnableVoms.GetName(), false))
	require.NoError(t, param.Set(param.Origin_SelfTest.GetName(), false))
	require.NoError(t, param.Set(param.Origin_Port.GetName(), 0))
	require.NoError(t, param.Set(param.Server_WebPort.GetName(), 0))
	require.NoError(t, param.Set(param.TLSSkipVerify.GetName(), true))

	return originMockup(ctx, egrp, t)
}

func runS3Test(t *testing.T, bucketName, urlStyle, objectName string) {
	ensureXrdS3PluginAvailable(t)

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	federationPrefix := "/test"

	mockupCancel := mockupS3Origin(ctx, egrp, t, federationPrefix, bucketName, urlStyle)
	defer mockupCancel()

	originEndpoint := param.Origin_Url.GetString()
	// At this point, a 403 means the server is running, which means its ready to grab objects from
	err := server_utils.WaitUntilWorking(ctx, "GET", originEndpoint, "xrootd", 403, true)
	if err != nil {
		t.Fatalf("Unsuccessful test: Server encountered an error: %v", err)
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
	t.Cleanup(test_utils.SetupTestLogging(t))
	t.Run("S3OriginPathBucket", func(t *testing.T) {
		runS3Test(t, "noaa-wod-pds", "path", "MD5SUMS")
	})

	t.Run("S3OriginVirtualBucket", func(t *testing.T) {
		runS3Test(t, "noaa-wod-pds", "virtual", "MD5SUMS")
	})

	t.Run("S3OriginNoBucket", func(t *testing.T) {
		runS3Test(t, "", "path", "noaa-wod-pds/MD5SUMS")
	})
}

func TestS3OriginWithSentinel(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ensureXrdS3PluginAvailable(t)
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	federationPrefix := "/test"
	bucketName := "noaa-wod-pds"

	mockupCancel := mockupS3Origin(ctx, egrp, t, federationPrefix, bucketName, "path")
	defer mockupCancel()

	mockExportValidStn := server_utils.OriginExport{
		StoragePrefix:    viper.GetString(param.Origin_StoragePrefix.GetName()),
		FederationPrefix: viper.GetString(param.Origin_FederationPrefix.GetName()),
		Capabilities:     server_structs.Capabilities{Reads: true},
		SentinelLocation: "MD5SUMS",
	}

	originEndpoint := param.Origin_Url.GetString()
	// At this point, a 403 means the server is running, which means its ready to grab objects from
	err := server_utils.WaitUntilWorking(ctx, "GET", originEndpoint, "xrootd", 403, true)
	if err != nil {
		t.Fatalf("Unsuccessful test: Server encountered an error: %v", err)
	}

	// mock export with no sentinel
	mockExportNoStn := server_utils.OriginExport{
		StoragePrefix:    viper.GetString(param.Origin_StoragePrefix.GetName()),
		FederationPrefix: viper.GetString(param.Origin_FederationPrefix.GetName()),
		Capabilities:     server_structs.Capabilities{Reads: true},
	}

	// mock export with an invalid sentinel
	mockExportInvalidStn := server_utils.OriginExport{
		StoragePrefix:    viper.GetString(param.Origin_StoragePrefix.GetName()),
		FederationPrefix: viper.GetString(param.Origin_FederationPrefix.GetName()),
		Capabilities:     server_structs.Capabilities{Reads: true},
		SentinelLocation: "MD5SUMS_dne",
	}

	t.Run("valid-sentinel-return-ok", func(t *testing.T) {
		ok, err := server_utils.CheckOriginSentinelLocations([]server_utils.OriginExport{mockExportValidStn})
		require.NoError(t, err)
		require.True(t, ok)
	})
	t.Run("empty-sentinel-return-ok", func(t *testing.T) {
		ok, err := server_utils.CheckOriginSentinelLocations([]server_utils.OriginExport{mockExportNoStn})
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("invalid-sentinel-return-error", func(t *testing.T) {
		ok, err := server_utils.CheckOriginSentinelLocations([]server_utils.OriginExport{mockExportInvalidStn})
		require.Error(t, err)
		require.False(t, ok)
	})
}

func TestPosixOriginWithSentinel(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	server_utils.ResetTestState()

	defer server_utils.ResetTestState()

	// Create a test temp dir, ensure it's readable and writable by XRootD daemon user
	tmpPathPattern := "XRD-Tst_Orgn*"
	tmpPath, err := os.MkdirTemp("", tmpPathPattern)
	require.NoError(t, err)
	err = os.Chmod(tmpPath, 0777) // 0777 to allow XRootD daemon user access
	require.NoError(t, err)

	require.NoError(t, param.Set(param.Origin_StoragePrefix.GetName(), tmpPath))
	require.NoError(t, param.Set(param.Origin_FederationPrefix.GetName(), "/test"))
	require.NoError(t, param.Set(param.Origin_StorageType.GetName(), "posix"))
	// Disable functionality we're not using (and is difficult to make work on Mac)
	require.NoError(t, param.Set(param.Origin_EnableCmsd.GetName(), false))
	require.NoError(t, param.Set(param.Origin_EnableMacaroons.GetName(), false))
	require.NoError(t, param.Set(param.Origin_EnableVoms.GetName(), false))
	require.NoError(t, param.Set(param.Origin_Port.GetName(), 0))
	require.NoError(t, param.Set(param.Server_WebPort.GetName(), 0))
	require.NoError(t, param.Set(param.TLSSkipVerify.GetName(), true))
	require.NoError(t, param.Set(param.Logging_Origin_Scitokens.GetName(), "trace"))

	mockupCancel := originMockup(ctx, egrp, t)
	defer mockupCancel()

	// mock export with a valid sentinel
	mockExportValidStn := server_utils.OriginExport{
		StoragePrefix:    viper.GetString("Origin.StoragePrefix"),
		FederationPrefix: viper.GetString("Origin.FederationPrefix"),
		Capabilities:     server_structs.Capabilities{Reads: true},
		SentinelLocation: "mock_sentinel",
	}
	// mock export with no sentinel
	mockExportNoStn := server_utils.OriginExport{
		StoragePrefix:    viper.GetString("Origin.StoragePrefix"),
		FederationPrefix: viper.GetString("Origin.FederationPrefix"),
		Capabilities:     server_structs.Capabilities{Reads: true},
	}
	// mock export with an invalid sentinel
	mockExportInvalidStn := server_utils.OriginExport{
		StoragePrefix:    viper.GetString("Origin.StoragePrefix"),
		FederationPrefix: viper.GetString("Origin.FederationPrefix"),
		Capabilities:     server_structs.Capabilities{Reads: true},
		SentinelLocation: "sentinel_dne",
	}

	// Create a sentinel file, ensure it's readable by XRootD
	tempStn := filepath.Join(mockExportValidStn.StoragePrefix, mockExportValidStn.SentinelLocation)
	file, err := os.Create(tempStn)
	require.NoError(t, err)
	err = file.Close()
	require.NoError(t, err)
	err = os.Chmod(tempStn, 0755)
	require.NoError(t, err)

	err = server_utils.WaitUntilWorking(ctx, "GET", param.Origin_Url.GetString(), "xrootd", 403, false)
	if err != nil {
		t.Fatalf("Unsuccessful test: Server encountered an error: %v", err)
	}
	require.NoError(t, err)

	t.Run("valid-sentinel-return-ok", func(t *testing.T) {
		ok, err := server_utils.CheckOriginSentinelLocations([]server_utils.OriginExport{mockExportValidStn})
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("empty-sentinel-return-ok", func(t *testing.T) {
		ok, err := server_utils.CheckOriginSentinelLocations([]server_utils.OriginExport{mockExportNoStn})
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("invalid-sentinel-return-error", func(t *testing.T) {
		ok, err := server_utils.CheckOriginSentinelLocations([]server_utils.OriginExport{mockExportInvalidStn})
		require.Error(t, err)
		require.False(t, ok)
	})
}
