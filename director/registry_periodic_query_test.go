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

package director

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestLaunchRegistryPeriodicQuery(t *testing.T) {
	config.ResetConfig()
	defer config.ResetConfig()

	mockDataChan := make(chan map[string][]string, 2)
	mockData := map[string][]string{
		"cacheHostname1": {"/ns1/ns2", "/ns3/ns4"},
	}
	mockDataChan <- mockData

	var lastData map[string][]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		select {
		case currentData := <-mockDataChan:
			lastData = currentData
		default:
		}
		if lastData == nil {
			lastData = make(map[string][]string)
		}
		if err := json.NewEncoder(w).Encode(lastData); err != nil {
			log.Errorf("Failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	// Set the registry URL to the mock server.
	viper.Set("Federation.Registryurl", server.URL)
	viper.Set("Director.RegistryQueryInterval", "200ms")

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	LaunchRegistryPeriodicQuery(ctx, egrp)

	require.Eventually(t, func() bool {
		currentMapPtr := allowedPrefixesForCaches.Load()
		return reflect.DeepEqual(*currentMapPtr, convertMapOfListToMapOfSet(mockData))
	}, 5*time.Second, 100*time.Millisecond, "allowedPrefixesForCaches was not updated with the initial mock data")

	mockData = map[string][]string{
		"cacheHostname2": {"/ns5/ns6", "/ns7/ns8"},
	}
	mockDataChan <- mockData

	require.Eventually(t, func() bool {
		currentMapPtr := allowedPrefixesForCaches.Load()
		return reflect.DeepEqual(*currentMapPtr, convertMapOfListToMapOfSet(mockData))
	}, 5*time.Second, 100*time.Millisecond, "allowedPrefixesForCaches was not updated with the new mock data")

}
