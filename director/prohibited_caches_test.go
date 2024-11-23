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
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
)

// TestLaunchPeriodicProhibitedCachesFetch tests whether the prohibited caches data is periodically updated from the registry.
func TestLaunchPeriodicProhibitedCachesFetch(t *testing.T) {
	config.ResetConfig()
	defer config.ResetConfig()

	mockDataChan := make(chan map[string][]string, 2)
	mockDataChan <- map[string][]string{
		"/foo/bar": {"hostname1", "hostname2"},
	}

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
	viper.Set("Director.ProhibitedCachesRefreshInterval", "200ms")

	ctx, cancel := context.WithCancel(context.Background())
	egrp := &errgroup.Group{}

	LaunchPeriodicProhibitedCachesFetch(ctx, egrp)

	time.Sleep(500 * time.Millisecond)

	prohibitedCachesMutex.RLock()
	assert.Equal(t, map[string][]string{
		"/foo/bar": {"hostname1", "hostname2"},
	}, prohibitedCaches)
	prohibitedCachesMutex.RUnlock()

	mockDataChan <- map[string][]string{
		"/foo/bar": {"hostname3", "hostname4"},
	}

	time.Sleep(500 * time.Millisecond)

	prohibitedCachesMutex.RLock()
	assert.Equal(t, map[string][]string{
		"/foo/bar": {"hostname3", "hostname4"},
	}, prohibitedCaches)
	prohibitedCachesMutex.RUnlock()

	cancel()

	require.NoError(t, egrp.Wait(), "Periodic fetch goroutine did not terminate properly")
}
