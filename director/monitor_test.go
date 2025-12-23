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

package director_test

/*
import (
	_ "embed"
)

type (
	componentStatus struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}

	healthComponents map[string]componentStatus

	healthResults struct {
		Status     string           `json:"status"`
		Components healthComponents `json:"components"`
	}
)

var (
	//go:embed resources/fed_test.yaml
	fedTestCfg string
)


func TestDirector(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	fed := fed_test_utils.NewFedTest(t, fedTestCfg)

	fedInfo, err := config.GetFederation(fed.Ctx)
	require.NoError(t, err)

	client := &http.Client{Transport: config.GetTransport()}
	loc := fedInfo.DirectorEndpoint + "/api/v1.0/metrics/health"
	fmt.Println("Location to test: ", loc)

	statusOK := false
	var results healthResults
	for idx := 1; idx < 10; idx += 1 {
		req, err := http.NewRequestWithContext(fed.Ctx, "GET", loc, nil)
		require.NoError(t, err)
		res, err := client.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		fmt.Println(string(body))

		require.NoError(t, json.Unmarshal(body, &results))

		if results.Status == "ok" {
			statusOK = true
			break
		} else if results.Status == "critical" {
			break
		}
		time.Sleep(400 * time.Millisecond)
	}
	assert.True(t, statusOK)
	comp, ok := results.Components["director"]
	require.True(t, ok)
	assert.Equal(t, "ok", comp.Status)
}
*/
