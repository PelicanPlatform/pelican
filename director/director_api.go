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
	"fmt"
	"strconv"
	"time"

	"github.com/jellydator/ttlcache/v3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
)

// List all namespaces from origins registered at the director
func listNamespacesFromOrigins() []server_structs.NamespaceAdV2 {
	serverAdItems := serverAds.Items()
	namespaces := make([]server_structs.NamespaceAdV2, 0, len(serverAdItems))
	for _, item := range serverAdItems {
		ad := item.Value()
		if ad.Type == server_structs.OriginType {
			namespaces = append(namespaces, ad.NamespaceAds...)
		}
	}
	return namespaces
}

// List all serverAds in the cache that matches the serverType array
func listServerAds(serverTypes []server_structs.ServerType) []server_structs.ServerAd {
	ads := make([]server_structs.ServerAd, 0)
	for _, item := range serverAds.Items() {
		ad := item.Value()
		for _, serverType := range serverTypes {
			if ad.Type == serverType {
				ads = append(ads, ad.ServerAd)
			}
		}
	}
	return ads
}

// Check if a server is filtered from "production" servers by
// checking if a serverName is in the filteredServers map
func checkFilter(serverName string) (bool, filterType) {
	filteredServersMutex.RLock()
	defer filteredServersMutex.RUnlock()

	status, exists := filteredServers[serverName]
	// No filter entry
	if !exists {
		return false, ""
	} else {
		// Has filter entry
		switch status {
		case permFiltered:
			return true, permFiltered
		case tempFiltered:
			return true, tempFiltered
		case tempAllowed:
			return false, tempAllowed
		default:
			log.Error("Unknown filterType: ", status)
			return false, ""
		}
	}
}

// Configure TTL caches to enable cache eviction and other additional cache events handling logic
//
// The `ctx` is the context for listening to server shutdown event in order to cleanup internal cache eviction
// goroutine and `wg` is the wait group to notify when the clean up goroutine finishes
func ConfigTTLCache(ctx context.Context, egrp *errgroup.Group) {
	// Start automatic expired item deletion
	go serverAds.Start()
	go namespaceKeys.Start()

	serverAds.OnEviction(func(ctx context.Context, er ttlcache.EvictionReason, i *ttlcache.Item[string, *server_structs.Advertisement]) {
		healthTestUtilsMutex.RLock()
		defer healthTestUtilsMutex.RUnlock()
		serverAd := i.Value().ServerAd
		serverUrl := i.Key()

		if util, exists := healthTestUtils[serverAd]; exists {
			util.Cancel()
			if util.ErrGrp != nil {
				err := util.ErrGrp.Wait()
				if err != nil {
					log.Debugf("Error from errgroup when evict the registration from TTL cache for %s %s %s", string(serverAd.Type), serverAd.Name, err.Error())
				} else {
					log.Debugf("Errgroup successfully emptied at TTL cache eviction for %s %s", string(serverAd.Type), serverAd.Name)
				}
			} else {
				log.Debugf("errgroup is nil when evict the registration from TTL cache for %s %s", string(serverAd.Type), serverAd.Name)
			}
		} else {
			log.Debugf("healthTestUtil not found for %s when evicting TTL cache item", serverAd.Name)
		}

		if serverAd.Type == server_structs.OriginType {
			originStatUtilsMutex.Lock()
			defer originStatUtilsMutex.Unlock()
			statUtil, ok := originStatUtils[serverUrl]
			if ok {
				statUtil.Cancel()
				if err := statUtil.Errgroup.Wait(); err != nil {
					log.Info(fmt.Sprintf("Error happened when stopping origin %q stat goroutine group: %v", serverAd.Name, err))
				}
				delete(originStatUtils, serverUrl)
			}
		}
	})

	// Put stop logic in a separate goroutine so that parent function is not blocking
	egrp.Go(func() error {
		<-ctx.Done()
		log.Info("Gracefully stopping director TTL cache eviction...")
		serverAds.DeleteAll()
		serverAds.Stop()
		namespaceKeys.DeleteAll()
		namespaceKeys.Stop()
		log.Info("Director TTL cache eviction has been stopped")
		return nil
	})
}

// Populate internal filteredServers map by Director.FilteredServers
func ConfigFilterdServers() {
	filteredServersMutex.Lock()
	defer filteredServersMutex.Unlock()

	if !param.Director_FilteredServers.IsSet() {
		return
	}

	for _, sn := range param.Director_FilteredServers.GetStringSlice() {
		filteredServers[sn] = permFiltered
	}
}

// Start a goroutine to query director's Prometheus endpoint for origin/cache server I/O stats
// and save the value to the corresponding serverAd
func ConfigServerIOQuery(ctx context.Context, egrp *errgroup.Group) {
	egrp.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(1 * time.Minute):
				items := serverAds.Items()
				for _, item := range items {
					if item.IsExpired() {
						continue
					}
					serverUrl := item.Key()
					serverAd := item.Value()
					if serverAd.FromTopology {
						// Topology servers have no Prometheus metrics
						continue
					}
					query := fmt.Sprintf(`deriv(xrootd_server_io{job="origin_cache_servers", type="total", server_auth_url="%s"}[5m])`, serverUrl)
					queryResult, err := queryPromtheus(query, true)
					if err != nil {
						log.Debugf("Failed to update IO stat for server %s: %v", serverUrl, err)
						continue
					}
					if queryResult.ResultType != "vector" {
						log.Debugf("Failed to update IO stat for server %s: Prometheus response returns type %s not vector", serverUrl, queryResult.ResultType)
						continue
					}
					if len(queryResult.Result) != 1 {
						log.Debugf("Failed to update IO stat for server %s: Prometheus response contains more or less than 1 result: %d", serverUrl, len(queryResult.Result))
						continue
					}
					ioDerivStr := queryResult.Result[0].Values[0].Value
					if ioDerivStr == "" {
						continue
					} else {
						ioDeriv, err := strconv.ParseFloat(ioDerivStr, 64)
						if err != nil {
							log.Debugf("Failed to update IO stat for server %s: failed to convert Prometheus response to a float number: %s", serverUrl, ioDerivStr)
							continue
						}
						// Here we use a sigmoid function
						sigmoidIO := utils.Sigmoid(ioDeriv)
						serverAd.IOLoad = sigmoidIO
					}
				}
				log.Debug("Successfully updated server IO stat")
			}
		}
	})
}
