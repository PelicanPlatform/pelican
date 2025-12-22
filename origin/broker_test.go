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
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/origin"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

var (
	//go:embed resources/broker-config.yaml
	brokerConfig string
)

// A test that spins up a federation and verifies we can
// perform API calls to the origin via the broker.
func TestBrokerApi(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	fed := fed_test_utils.NewFedTest(t, brokerConfig)

	collector, err := origin.PelicanBrokerConnections.GetMetricWithLabelValues("origin")
	require.NoError(t, err, "Failed to get metric collector")

	startVal := testutil.ToFloat64(collector)

	desiredURL := param.Server_ExternalWebUrl.GetString() + "/api/v1.0/health"
	err = server_utils.WaitUntilWorking(fed.Ctx, "GET", desiredURL, "director", 200, false)
	require.NoError(t, err)

	// Wait for the director to register the origin's broker endpoint
	originAddr := param.Server_Hostname.GetString() + ":" + strconv.Itoa(param.Origin_Port.GetInt())
	require.Eventually(t, func() bool {
		return director.HasBrokerForAddr(originAddr)
	}, 5*time.Second, 50*time.Millisecond, "Director did not register origin broker endpoint")

	httpc := http.Client{
		Transport: config.GetTransport().Clone(),
	}
	resp, err := httpc.Get(desiredURL)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "Expected HTTP status code 200")

	// Verify the metric collector has been incremented
	require.Greater(t, testutil.ToFloat64(collector), startVal, "Expected broker connections metric to be incremented")
}
