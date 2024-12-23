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
	"fmt"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

var (
	// allowedPrefixesForCaches maps cahce hostnames to a list of prefixes the caches are allowed to serve.
	allowedPrefixesForCaches atomic.Pointer[map[string][]string]
	// allowedPrefixesForCachesLastSetTimestamp tracks when allowedPrefixesForCaches was last explicitly set.
	allowedPrefixesForCachesLastSetTimestamp atomic.Int64
)

func init() {
	emptyMap := make(map[string][]string)
	allowedPrefixesForCaches.Store(&emptyMap)

	// Initialize allowedPrefixesForCachesLastSetTimestamp to 0 (indicating never set)
	allowedPrefixesForCachesLastSetTimestamp.Store(0)
}

// fetchAllowedPrefixesForCaches makes a request to the registry endpoint to retrieve
// information about allowed prefixes for caches and returns the result.
func fetchAllowedPrefixesForCaches(ctx context.Context) (map[string][]string, error) {
	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return nil, err
	}
	registryUrlStr := fedInfo.RegistryEndpoint
	registryUrl, err := url.Parse(registryUrlStr)
	if err != nil {
		return nil, err
	}
	reqUrl := registryUrl.JoinPath("/api/v1.0/registry/caches/allowedPrefixes")

	client := http.Client{Transport: config.GetTransport()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqUrl.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch allowed prefixes for caches from the registry: unexpected status code %d", resp.StatusCode)
	}

	var result map[string][]string
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// LaunchRegistryPeriodicQuery starts a new goroutine that periodically refreshes
// the allowed prefixes for cache data maintained by the director in memory.
// This can later be extended to include any registry data the director wants to maintain in memory.
func LaunchRegistryPeriodicQuery(ctx context.Context, egrp *errgroup.Group) {
	refreshInterval := param.Director_RegistryQueryInterval.GetDuration()

	if refreshInterval < 1*time.Millisecond {
		log.Warnf("Director.RegistryQueryInterval is set to: %v, which is too low. Falling back to default: 1m", refreshInterval)

		viper.Set("Director.RegistryQueryInterval", "1m")
		refreshInterval = 1 * time.Minute
	}

	ticker := time.NewTicker(refreshInterval)

	data, err := fetchAllowedPrefixesForCaches(ctx)
	if err != nil {
		ticker.Reset(1 * time.Second) // Higher frequency (10s)
		log.Warningf("Error fetching allowed prefixes for caches data on first attempt: %v", err)
		log.Debug("Switching to higher frequency (1s) for allowed prefixes for caches data fetch")
	} else {
		allowedPrefixesForCaches.Store(&data)
		allowedPrefixesForCachesLastSetTimestamp.Store(time.Now().Unix())
		log.Debug("Allowed prefixes for caches data updated successfully on first attempt")
	}

	egrp.Go(func() error {
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				data, err := fetchAllowedPrefixesForCaches(ctx)
				if err != nil {
					log.Warningf("Error fetching allowed prefixes for caches data: %v", err)
					lastSet := allowedPrefixesForCachesLastSetTimestamp.Load()
					if time.Since(time.Unix(lastSet, 0)) >= 15*time.Minute {
						log.Debug("Allowed prefixes for caches data last updated over 15 minutes ago, switching to higher frequency")
						ticker.Reset(1 * time.Second) // Higher frequency (1s)
					}
					continue
				}
				ticker.Reset(refreshInterval) // Normal frequency
				allowedPrefixesForCaches.Store(&data)
				allowedPrefixesForCachesLastSetTimestamp.Store(time.Now().Unix())
				log.Debug("Allowed prefixes for caches data updated successfully")
			case <-ctx.Done():
				log.Debug("Periodic fetch terminated")
				return nil
			}
		}
	})
}
