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
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

type (
	FedTest struct {
		AdvertiseCancel context.CancelFunc
		Exports         []server_utils.OriginExport
		Token           string
		Ctx             context.Context
		Egrp            *errgroup.Group
		Pids            []int
	}
)

var (
	//go:embed resources/default.yaml
	fedTestDefaultConfig string
)

// Start up a new Pelican federation for unit testing
func NewFedTest(t *testing.T, originConfig string) (ft *FedTest) {
	ft = &FedTest{}
	director.ResetState()

	if originConfig == "" {
		originConfig = fedTestDefaultConfig
	}

	// Allow quick switching between POSIX backends for tests.
	// If TEST_POSIXV2=1, replace occurrences of "posix" with "posixv2" in the origin config.
	if os.Getenv("TEST_POSIXV2") == "1" {
		// Since "posixv2" contains "posix", we need to do the replacement in two steps
		// to avoid ending up with "posixv2v2".
		originConfig = strings.ReplaceAll(originConfig, "posixv2", "posix")
		originConfig = strings.ReplaceAll(originConfig, "posix", "posixv2")
	}

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	shutdownCtx, shutdownCancel := context.WithCancel(ctx)
	ctx = context.WithValue(ctx, director.AdvertiseShutdownKey, shutdownCtx)
	ctx = context.WithValue(ctx, server_utils.DirectorDiscoveryShutdownKey, shutdownCtx)
	ft.Ctx = ctx
	ft.AdvertiseCancel = shutdownCancel
	ft.Egrp = egrp

	tmpPathPattern := "Pelican-FedTest*"
	tmpPath, err := os.MkdirTemp("", tmpPathPattern)
	require.NoError(t, err)

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
		// Throw in a config.Reset for good measure. Keeps our env squeaky clean!
		server_utils.ResetTestState()
	})

	modules := server_structs.ServerType(0)
	modules.Set(server_structs.BrokerType)
	modules.Set(server_structs.CacheType)
	modules.Set(server_structs.OriginType)
	modules.Set(server_structs.DirectorType)
	modules.Set(server_structs.RegistryType)
	// TODO: the cache startup routines not sequenced correctly for the downloads
	// to immediately work through the cache.  For now, unit tests will just use the origin.
	modules.Set(server_structs.LocalCacheType)

	permissions := os.FileMode(0755)
	err = os.Chmod(tmpPath, permissions)
	require.NoError(t, err)

	require.NoError(t, param.Set("ConfigDir", tmpPath))
	// Set RuntimeDir to a per-test location to avoid race conditions in parallel tests
	require.NoError(t, param.Set(param.RuntimeDir.GetName(), tmpPath))
	// Configure all relevant logging levels. We don't let the XRootD
	// log levels inherit from the global log level, because the many
	// fed tests we run back-to-back would otherwise generate a lot of
	// log output.
	require.NoError(t, param.Set(param.Logging_Level.GetName(), "debug"))
	require.NoError(t, param.Set(param.Logging_Origin_Cms.GetName(), "error"))
	require.NoError(t, param.Set(param.Logging_Origin_Xrd.GetName(), "error"))
	require.NoError(t, param.Set(param.Logging_Origin_Ofs.GetName(), "error"))
	require.NoError(t, param.Set(param.Logging_Origin_Oss.GetName(), "error"))
	require.NoError(t, param.Set(param.Logging_Origin_Http.GetName(), "error"))
	require.NoError(t, param.Set(param.Logging_Origin_Scitokens.GetName(), "fatal"))
	require.NoError(t, param.Set(param.Logging_Origin_Xrootd.GetName(), "info"))
	require.NoError(t, param.Set(param.Logging_Cache_Ofs.GetName(), "error"))
	require.NoError(t, param.Set(param.Logging_Cache_Pss.GetName(), "error"))
	require.NoError(t, param.Set(param.Logging_Cache_PssSetOpt.GetName(), "error"))
	require.NoError(t, param.Set(param.Logging_Cache_Http.GetName(), "error"))
	require.NoError(t, param.Set(param.Logging_Cache_Xrd.GetName(), "error"))
	require.NoError(t, param.Set(param.Logging_Cache_Xrootd.GetName(), "error"))
	require.NoError(t, param.Set(param.Logging_Cache_Scitokens.GetName(), "fatal"))
	require.NoError(t, param.Set(param.Logging_Cache_Pfc.GetName(), "info"))

	// Do NOT skip TLS verification in tests.  This has hidden *real bugs* in the past
	// and there should be no need since we generate CA certs when needed.  If you think
	// this should be changed, talk to the rest of the dev team first.
	require.NoError(t, param.Set(param.TLSSkipVerify.GetName(), false))

	// Disable functionality we're not using (and is difficult to make work on Mac)
	require.NoError(t, param.Set(param.Registry_DbLocation.GetName(), filepath.Join(t.TempDir(), "ns-registry.sqlite")))
	require.NoError(t, param.Set(param.Registry_RequireOriginApproval.GetName(), false))
	require.NoError(t, param.Set(param.Registry_RequireCacheApproval.GetName(), false))
	require.NoError(t, param.Set(param.Director_CacheSortMethod.GetName(), "distance"))
	require.NoError(t, param.Set(param.Director_DbLocation.GetName(), filepath.Join(t.TempDir(), "director.sqlite")))
	require.NoError(t, param.Set(param.Director_FilterCachesInErrorState.GetName(), false))
	require.NoError(t, param.Set(param.Origin_EnableCmsd.GetName(), false))
	require.NoError(t, param.Set(param.Origin_EnableVoms.GetName(), false))
	require.NoError(t, param.Set(param.Origin_Port.GetName(), 0))
	require.NoError(t, param.Set(param.Origin_RunLocation.GetName(), filepath.Join(tmpPath, "origin")))
	require.NoError(t, param.Set(param.Origin_DbLocation.GetName(), filepath.Join(t.TempDir(), "origin.sqlite")))
	require.NoError(t, param.Set(param.Origin_TokenAudience.GetName(), ""))
	require.NoError(t, param.Set(param.Cache_Port.GetName(), 0))
	require.NoError(t, param.Set(param.Cache_RunLocation.GetName(), filepath.Join(tmpPath, "cache")))
	require.NoError(t, param.Set(param.Cache_EnableEvictionMonitoring.GetName(), false))
	require.NoError(t, param.Set(param.Cache_StorageLocation.GetName(), filepath.Join(tmpPath, "xcache-data")))
	require.NoError(t, param.Set(param.Cache_DbLocation.GetName(), filepath.Join(t.TempDir(), "cache.sqlite")))
	require.NoError(t, param.Set(param.Server_EnableUI.GetName(), false))
	require.NoError(t, param.Set(param.Server_WebPort.GetName(), 0))
	require.NoError(t, param.Set(param.Server_DbLocation.GetName(), filepath.Join(t.TempDir(), "server.sqlite")))
	// Set up OIDC client configuration for registry OAuth functionality
	oidcClientIDFile := filepath.Join(tmpPath, "oidc-client-id")
	oidcClientSecretFile := filepath.Join(tmpPath, "oidc-client-secret")
	require.NoError(t, os.WriteFile(oidcClientIDFile, []byte("test-client-id"), 0644))
	require.NoError(t, os.WriteFile(oidcClientSecretFile, []byte("test-client-secret"), 0644))
	require.NoError(t, param.Set(param.OIDC_ClientIDFile.GetName(), oidcClientIDFile))
	require.NoError(t, param.Set(param.OIDC_ClientSecretFile.GetName(), oidcClientSecretFile))
	// Unix domain sockets have a maximum length of 108 bytes, so we need to make sure our
	// socket path is short enough to fit within that limit. Mac OS X has long temporary path
	// names, so we need to make sure our socket path is short enough to fit within that limit.
	require.NoError(t, param.Set(param.LocalCache_RunLocation.GetName(), filepath.Join(tmpPath, "lc")))

	// Set the Director's start time to 6 minutes ago. This prevents it from sending an HTTP 429 for
	// unknown prefixes.
	directorStartTime := time.Now().Add(-6 * time.Minute)
	director.SetStartupTime(directorStartTime)

	err = config.InitServer(ctx, modules)
	require.NoError(t, err)

	// Read in any config we may have set
	var importedConf any
	viper.SetConfigType("yaml")
	err = viper.MergeConfig(strings.NewReader(originConfig))
	require.NoError(t, err, "error reading config")

	err = yaml.Unmarshal([]byte(originConfig), &importedConf)
	require.NoError(t, err, "error unmarshalling into interface")

	confMap := importedConf.(map[string]any)

	if originRaw, exists := confMap["Origin"]; exists {
		originMap := originRaw.(map[string]any)

		overrideTemp := func(storageDir string, exportMap map[string]any) {
			exportMap["StoragePrefix"] = storageDir

			// Change the permissions of the temporary origin directory
			permissions = os.FileMode(0755)
			err = os.Chmod(storageDir, permissions)
			require.NoError(t, err)

			// Change ownership on the temporary origin directory so files can be uploaded
			uinfo, err := config.GetDaemonUserInfo()
			require.NoError(t, err)
			require.NoError(t, os.Chown(storageDir, uinfo.Uid, uinfo.Gid))

			// Start off with a Hello World file we can use for testing in each of our exports
			err = os.WriteFile(filepath.Join(storageDir, "hello_world.txt"), []byte("Hello, World!"), os.FileMode(0644))
			require.NoError(t, err)
		}

		// Override the test directory from the config file with our temp directory
		if exportsRaw, exists := originMap["Exports"]; exists {
			for i, item := range exportsRaw.([]any) {
				originDir, err := os.MkdirTemp("", fmt.Sprintf("Export%d", i))
				assert.NoError(t, err)
				t.Cleanup(func() {
					err := os.RemoveAll(originDir)
					require.NoError(t, err)
				})

				exportMap := item.(map[string]any)
				overrideTemp(originDir, exportMap)
			}
		} else {
			originDir, err := os.MkdirTemp("", fmt.Sprintf("Export%s", "test"))
			assert.NoError(t, err)
			t.Cleanup(func() {
				err := os.RemoveAll(originDir)
				require.NoError(t, err)
			})

			overrideTemp(originDir, originMap)
		}
	}

	confDir := t.TempDir()
	outputPath := filepath.Join(confDir, "tempfile_*.yaml")

	outputData, err := yaml.Marshal(&importedConf)
	require.NoError(t, err, "error marshalling struct into yaml format")

	err = os.WriteFile(outputPath, outputData, 0644)
	require.NoError(t, err, "error writing out temporary config file for fed test")

	require.NoError(t, param.Set("config", outputPath))

	servers, _, err := launchers.LaunchModules(ctx, modules)
	require.NoError(t, err)

	ft.Pids = make([]int, 0, 2)
	for _, server := range servers {
		ft.Pids = append(ft.Pids, server.GetPids()...)
	}

	var discoveryServer *httptest.Server
	// Set up discovery for federation metadata hosting. This needs to be done AFTER launching
	// servers, because they populate the param values we use to set the metadata.
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/pelican-configuration" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			discoveryMetadata := pelican_url.FederationDiscovery{
				DiscoveryEndpoint:          discoveryServer.URL,
				DirectorEndpoint:           param.Server_ExternalWebUrl.GetString(),
				RegistryEndpoint:           param.Server_ExternalWebUrl.GetString(),
				BrokerEndpoint:             param.Server_ExternalWebUrl.GetString(),
				JwksUri:                    param.Server_ExternalWebUrl.GetString() + "/.well-known/issuer.jwks",
				DirectorAdvertiseEndpoints: param.Server_DirectorUrls.GetStringSlice(),
			}

			discoveryJSONBytes, err := json.Marshal(discoveryMetadata)
			require.NoError(t, err, "Failed to marshal discovery metadata")
			_, err = w.Write(discoveryJSONBytes)
			require.NoError(t, err)
		} else {
			http.NotFound(w, r)
		}
	}
	// Use the generated server certificate instead of httptest's self-signed cert
	discoveryServer = httptest.NewUnstartedServer(http.HandlerFunc(handler))
	cert, err := config.LoadCertificate(param.Server_TLSCertificateChain.GetString())
	require.NoError(t, err, "Failed to load server certificate")

	// Get the server hostname that matches the certificate
	serverHostname := param.Server_Hostname.GetString()

	// Create a listener on the server hostname instead of 127.0.0.1
	// This ensures the certificate's DNS name matches the connection
	listener, err := net.Listen("tcp", serverHostname+":0")
	require.NoError(t, err, "Failed to create listener on server hostname")
	discoveryServer.Listener = listener

	discoveryServer.TLS = config.GetTransport().TLSClientConfig.Clone()
	discoveryServer.TLS.Certificates = make([]tls.Certificate, 1)
	discoveryServer.TLS.Certificates[0], err = tls.LoadX509KeyPair(
		param.Server_TLSCertificateChain.GetString(),
		param.Server_TLSKey.GetString(),
	)
	require.NoError(t, err, "Failed to load X509 key pair")
	_ = cert // We loaded the cert just to verify it exists, but we use the keypair for TLS
	discoveryServer.StartTLS()

	// Override the URL to use the hostname instead of the IP address
	// httptest might set URL to https://127.0.0.1:<port>, but our cert is for the hostname
	// Extract the port from the listener address and construct the URL with the hostname
	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err, "Failed to parse listener address")
	discoveryServer.URL = "https://" + net.JoinHostPort(serverHostname, port)

	t.Cleanup(discoveryServer.Close)

	// Set the discovery URL in both viper and the global fed info object
	require.NoError(t, param.Set(param.Federation_DiscoveryUrl.GetName(), discoveryServer.URL))
	fedInfo, err := config.GetFederation(ctx)
	require.NoError(t, err, "error getting federation info")
	fedInfo.DiscoveryEndpoint = discoveryServer.URL
	config.SetFederation(fedInfo)

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
	tokConf.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/hello_world.txt"))

	token, err := tokConf.CreateToken()
	require.NoError(t, err)

	ft.Token = token

	ft.Exports, err = server_utils.GetOriginExports()
	require.NoError(t, err)

	return
}
