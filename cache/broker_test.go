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

package cache_test

import (
	_ "embed"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

var (
	//go:embed resources/broker-config.yaml
	brokerConfig string
)

// Spin up a federation and verify that the cache advertises with BrokerURL when broker is enabled
// and the director registers it.
func TestBrokerApi(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(func() {
		server_utils.ResetTestState()
	})

	fed := fed_test_utils.NewFedTest(t, brokerConfig)

	// Wait for the server to be ready
	desiredURL := param.Server_ExternalWebUrl.GetString() + "/api/v1.0/health"
	err := server_utils.WaitUntilWorking(fed.Ctx, "GET", desiredURL, "director", 200, false)
	require.NoError(t, err)

	require.True(t, param.Cache_EnableBroker.GetBool(), "Cache broker should be enabled")

	// Verify the broker connection metric collector exists for cache (incremented in broker_client on reverse connection)
	collector, err := metrics.PelicanBrokerConnections.GetMetricWithLabelValues("cache")
	require.NoError(t, err, "Failed to get metric collector for cache broker connections")
	require.NotNil(t, collector)

	// Wait for the director to register the cache's broker endpoint.
	// This proves the cache advertised with BrokerURL and the director received it.
	externalWebUrl, err := url.Parse(param.Server_ExternalWebUrl.GetString())
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return director.HasBrokerForAddr(externalWebUrl.Host)
	}, 5*time.Second, 50*time.Millisecond, "Director did not register cache broker endpoint for "+externalWebUrl.Host)
}
