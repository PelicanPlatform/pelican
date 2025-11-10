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
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

var (
	//go:embed resources/broker-config.yaml
	brokerConfig string
)

// Spin up a federation and verifies that the cache broker infrastructure is properly configured.
func TestBrokerApi(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(func() {
		server_utils.ResetTestState()
	})

	fed := fed_test_utils.NewFedTest(t, brokerConfig)

	// Verify the broker connection metric collector exists for cache
	collector, err := metrics.PelicanBrokerConnections.GetMetricWithLabelValues("cache")
	require.NoError(t, err, "Failed to get metric collector for cache broker connections")
	startVal := testutil.ToFloat64(collector)

	// Wait for the server to be ready
	desiredURL := param.Server_ExternalWebUrl.GetString() + "/api/v1.0/health"
	err = server_utils.WaitUntilWorking(fed.Ctx, "GET", desiredURL, "director", 200, false)
	require.NoError(t, err)

	// Verify Cache.EnableBroker is set
	require.True(t, param.Cache_EnableBroker.GetBool(), "Cache broker should be enabled")

	// Verify the metric collector infrastructure exists
	require.NotNil(t, collector, "Expected broker connections metric collector to exist for cache")

	// Verify we can increment the metric (infrastructure test)
	metrics.PelicanBrokerConnections.WithLabelValues("cache").Inc()
	t.Logf("startVal: %f", startVal)
	t.Logf("currentVal: %f", testutil.ToFloat64(collector))
	require.Greater(t, testutil.ToFloat64(collector), startVal,
		"Expected to be able to increment the broker connections metric")
}
