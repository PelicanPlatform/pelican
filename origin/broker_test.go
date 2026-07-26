//go:build !windows

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

package origin_test

import (
	_ "embed"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

var (
	//go:embed resources/broker-config.yaml
	brokerConfig string

	//go:embed resources/broker-posixv2-config.yaml
	brokerPosixv2Config string
)

// A test that spins up a federation and verifies we can
// perform API calls to the origin via the broker.
func TestBrokerApi(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	fed := fed_test_utils.NewFedTest(t, brokerConfig)

	collector, err := metrics.PelicanBrokerConnections.GetMetricWithLabelValues("origin")
	require.NoError(t, err, "Failed to get metric collector")

	startVal := testutil.ToFloat64(collector)

	desiredURL := param.Server_ExternalWebUrl.GetString() + "/api/v1.0/health"
	err = server_utils.WaitUntilWorking(fed.Ctx, "GET", desiredURL, "director", 200, false)
	require.NoError(t, err)

	// Wait for the director to register the origin's broker endpoint
	// We need to extract the host:port from the external web URL since that's what the HTTP client will dial
	externalWebUrl, err := url.Parse(param.Server_ExternalWebUrl.GetString())
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return director.HasBrokerForAddr(externalWebUrl.Host)
	}, 5*time.Second, 50*time.Millisecond, "Director did not register origin broker endpoint for "+externalWebUrl.Host)

	httpc := http.Client{
		Transport: config.GetTransport().Clone(),
	}
	resp, err := httpc.Get(desiredURL)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "Expected HTTP status code 200")

	// Verify the metric collector has been incremented
	require.Greater(t, testutil.ToFloat64(collector), startVal, "Expected broker connections metric to be incremented")
}

// TestBrokerObjectGet verifies the "firewalled origin" data path for a native
// (posixv2) origin: an object request arriving at the origin over the broker
// must be served by the pelican web engine, not proxied to a local XRootD port.
// A posixv2 origin has no XRootD (Origin.Port is 0), so the pre-existing broker
// proxy — which forwarded object requests to localhost:Origin.Port — sent them
// to localhost:0 and failed. This exercises the fix that routes v2-origin object
// requests to the engine. (This is the origin half of WS1's cache -> broker ->
// origin chain; here we dial the origin's broker endpoint directly, which is
// what the cache does in production.)
func TestBrokerObjectGet(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	fed := fed_test_utils.NewFedTest(t, brokerPosixv2Config)
	require.Greater(t, len(fed.Exports), 0, "Federation should have at least one export")

	// Seed an object directly into the origin's backing store. A successful
	// fetch can only come from the origin, over the broker.
	testContent := "object served by a posixv2 origin over the broker"
	require.NoError(t, os.WriteFile(
		filepath.Join(fed.Exports[0].StoragePrefix, "broker_object.txt"),
		[]byte(testContent), 0644))

	// Wait for the origin to come up and for the director to register its broker
	// endpoint (so the broker-aware transport reverse-dials the origin).
	externalWebUrl, err := url.Parse(param.Server_ExternalWebUrl.GetString())
	require.NoError(t, err)
	require.NoError(t, server_utils.WaitUntilWorking(fed.Ctx, "GET",
		param.Server_ExternalWebUrl.GetString()+"/api/v1.0/health", "director", 200, false))
	require.Eventually(t, func() bool {
		return director.HasBrokerForAddr(externalWebUrl.Host)
	}, 5*time.Second, 50*time.Millisecond, "Director did not register origin broker endpoint for "+externalWebUrl.Host)

	// GET the object at its federation path. config.GetTransport() is broker-aware,
	// so the request reverse-dials the origin; the origin-side proxy must route it
	// to the web engine (not localhost:0) and serve the file. PublicReads is set,
	// so no token is required.
	httpc := http.Client{Transport: config.GetTransport().Clone()}
	resp, err := httpc.Get(param.Server_ExternalWebUrl.GetString() + "/test/broker_object.txt")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "object GET over the broker should succeed")
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(body), "object bytes served over the broker must match")
}
