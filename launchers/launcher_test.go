//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

package launchers

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// This test uses Server.TrustedProxies to verify configs are read before the gin engine build.
// Regression test for https://github.com/PelicanPlatform/pelican/issues/3678
func TestServerTrustedProxiesFromConfigFile(t *testing.T) {
	server_utils.ResetTestState()

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)

	tmpPath, err := os.MkdirTemp("", "Pelican-TrustedProxies*")
	require.NoError(t, err)
	t.Cleanup(func() {
		cancel()
		if err := egrp.Wait(); err != nil && err != context.Canceled && err != http.ErrServerClosed {
			require.NoError(t, err)
		}
		require.NoError(t, os.RemoveAll(tmpPath))
		server_utils.ResetTestState()
	})

	// Trust all sources so the test is independent of which interface the
	// probe request arrives on (loopback, container NIC, ...). The regression
	// still flips the assertion: an unapplied list means "trust nothing", so
	// the logged client would be the TCP peer instead of the forwarded IP.
	configFile := filepath.Join(tmpPath, "pelican.yaml")
	require.NoError(t, os.WriteFile(configFile,
		[]byte("Server:\n  TrustedProxies: [\"0.0.0.0/0\", \"::/0\"]\n"), 0644))
	viper.Set("config", configFile)

	require.NoError(t, param.ConfigBase.Set(tmpPath))
	require.NoError(t, param.RuntimeDir.Set(tmpPath))
	require.NoError(t, param.Logging_Level.Set("debug"))
	require.NoError(t, param.TLSSkipVerify.Set(false))
	require.NoError(t, param.Server_EnableUI.Set(false))
	require.NoError(t, param.Server_WebPort.Set(0))
	require.NoError(t, param.Server_DbLocation.Set(filepath.Join(t.TempDir(), "server.sqlite")))
	require.NoError(t, param.Registry_DbLocation.Set(filepath.Join(t.TempDir(), "ns-registry.sqlite")))
	require.NoError(t, param.Director_DbLocation.Set(filepath.Join(t.TempDir(), "director.sqlite")))

	// Registry alone cannot resolve federation metadata without an external
	// discovery endpoint; including the director makes discovery self-hosted
	// so LaunchModules runs without any prior config/InitServer call in the
	// test body (a prior InitServer would load the config file early and mask
	// the ordering regression this test exists to catch).
	modules := server_structs.ServerType(0)
	modules.Set(server_structs.DirectorType)
	modules.Set(server_structs.RegistryType)

	_, shutdownCancel, err := LaunchModules(ctx, modules)
	require.NoError(t, err)
	t.Cleanup(shutdownCancel)

	// The config file must have been loaded by the time the server is up
	require.Equal(t, []string{"0.0.0.0/0", "::/0"}, param.Server_TrustedProxies.GetStringSlice())

	// Install the log hook only after LaunchModules: Pelican's logging setup
	// replaces the standard logger's hooks during InitServer, which would
	// silently discard a hook installed earlier. Adding (not replacing) keeps
	// Pelican's own hooks intact.
	logHook := new(logrustest.Hook)
	log.AddHook(logHook)

	healthUrl := param.Server_ExternalWebUrl.GetString() + "/api/v1.0/health"
	require.NoError(t, server_utils.WaitUntilWorking(ctx, "GET", healthUrl, "registry", 200, false))

	// Request over loopback with a spoofed X-Forwarded-For. Since 127.0.0.0/8
	// is in the trusted-proxy list, gin must report the forwarded address as
	// the client rather than the TCP peer.
	const forwardedIP = "203.0.113.7"
	const probePath = "/trusted-proxy-probe"
	req, err := http.NewRequestWithContext(ctx, "GET", param.Server_ExternalWebUrl.GetString()+probePath, nil)
	require.NoError(t, err)
	req.Header.Set("X-Forwarded-For", forwardedIP)

	httpc := http.Client{Transport: config.GetTransport()}
	resp, err := httpc.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	// The gin access-log middleware records the resolved client IP for every
	// request; find our probe's entry and check which address it saw. Match
	// the path by suffix: the director module rewrites unrecognized paths
	// into its object API (e.g. /api/v1.0/director/object<probePath>), so the
	// logged resource may not equal the request path verbatim.
	var loggedClient any
	require.Eventually(t, func() bool {
		for _, entry := range logHook.AllEntries() {
			resource, ok := entry.Data["resource"].(string)
			if ok && entry.Message == "Served Request" && strings.HasSuffix(resource, probePath) {
				loggedClient = entry.Data["client"]
				return true
			}
		}
		return false
	}, 5*time.Second, 50*time.Millisecond, "gin access-log entry for %s never appeared", probePath)

	assert.Equal(t, forwardedIP, loggedClient,
		"engine did not honor X-Forwarded-For from a trusted proxy; Server.TrustedProxies from the config file was not applied to the gin engine")
}
