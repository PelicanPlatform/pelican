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
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

var (
	// prohibitedCaches maps federation prefixes to a list of cache hostnames where data should not propagate.
	prohibitedCaches      map[string][]string
	prohibitedCachesMutex sync.RWMutex
)

// fetchProhibitedCaches makes a request to the registry endpoint to retrieve
// information about prohibited caches and returns the result.
func fetchProhibitedCaches(ctx context.Context) (map[string][]string, error) {
	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return nil, err
	}
	registryUrlStr := fedInfo.RegistryEndpoint
	registryUrl, err := url.Parse(registryUrlStr)
	if err != nil {
		return nil, err
	}
	reqUrl := registryUrl.JoinPath("/api/v1.0/registry/namespaces/prohibitedCaches")

	client := http.Client{Transport: config.GetTransport()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqUrl.String(), nil)

	req.Header.Add("Content-Type", "application/json")
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch prohibited caches from the registry: unexpected status code %d", resp.StatusCode)
	}

	var result map[string][]string
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// LaunchPeriodicProhibitedCachesFetch starts a new goroutine that periodically
// refreshes the prohibited cache data maintained by the director in memory.
func LaunchPeriodicProhibitedCachesFetch(ctx context.Context, egrp *errgroup.Group) {
	ticker := time.NewTicker(param.Director_ProhibitedCachesRefreshInterval.GetDuration())

	data, err := fetchProhibitedCaches(ctx)
	if err != nil {
		log.Warningf("Error fetching prohibited caches on first attempt: %v", err)
	} else {
		prohibitedCachesMutex.Lock()
		prohibitedCaches = data
		prohibitedCachesMutex.Unlock()
		log.Debug("Prohibited caches updated successfully on first attempt")
	}

	egrp.Go(func() error {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				data, err := fetchProhibitedCaches(ctx)
				if err != nil {
					log.Warningf("Error fetching prohibited caches: %v", err)
					continue
				}
				prohibitedCachesMutex.Lock()
				prohibitedCaches = data
				prohibitedCachesMutex.Unlock()
				log.Debug("Prohibited caches updated successfully")
			case <-ctx.Done():
				log.Debug("Periodic fetch terminated")
				return nil
			}
		}
	})
}
