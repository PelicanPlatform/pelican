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
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
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

// List all advertisements in the TTL cache that match the serverType array
func listAdvertisement(serverTypes []server_structs.ServerType) []*server_structs.Advertisement {
	ads := make([]*server_structs.Advertisement, 0)
	for _, item := range serverAds.Items() {
		ad := item.Value()
		for _, serverType := range serverTypes {
			if ad.Type == serverType {
				ads = append(ads, ad)
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
		case topoFiltered:
			return true, topoFiltered
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
// The `ctx` is the context for listening to server shutdown event in order to cleanup internal cache eviction goroutine
func LaunchTTLCache(ctx context.Context, egrp *errgroup.Group) {
	// Start automatic expired item deletion
	go serverAds.Start()
	go namespaceKeys.Start()

	serverAds.OnEviction(func(ctx context.Context, er ttlcache.EvictionReason, i *ttlcache.Item[string, *server_structs.Advertisement]) {
		healthTestUtilsMutex.RLock()
		defer healthTestUtilsMutex.RUnlock()
		serverAd := i.Value().ServerAd
		serverUrl := i.Key()

		if util, exists := healthTestUtils[serverUrl]; exists {
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
			statUtilsMutex.Lock()
			defer statUtilsMutex.Unlock()
			statUtil, ok := statUtils[serverUrl]
			if ok {
				statUtil.Cancel()
				if err := statUtil.Errgroup.Wait(); err != nil {
					log.Info(fmt.Sprintf("Error happened when stopping origin %q stat goroutine group: %v", serverAd.Name, err))
				}
				delete(statUtils, serverUrl)
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

// Launch a goroutine to scrape metrics from various TTL caches and maps in the director
func LaunchMapMetrics(ctx context.Context, egrp *errgroup.Group) {
	// Scrape TTL cache and map metrics for Prometheus
	egrp.Go(func() error {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				// serverAds
				sAdMetrics := serverAds.Metrics()
				metrics.PelicanDirectorTTLCache.With(prometheus.Labels{"name": "serverAds", "type": "insersions"}).Set(float64(sAdMetrics.Insertions))
				metrics.PelicanDirectorTTLCache.With(prometheus.Labels{"name": "serverAds", "type": "evictions"}).Set(float64(sAdMetrics.Evictions))
				metrics.PelicanDirectorTTLCache.With(prometheus.Labels{"name": "serverAds", "type": "hits"}).Set(float64(sAdMetrics.Hits))
				metrics.PelicanDirectorTTLCache.With(prometheus.Labels{"name": "serverAds", "type": "misses"}).Set(float64(sAdMetrics.Misses))
				metrics.PelicanDirectorTTLCache.With(prometheus.Labels{"name": "serverAds", "type": "total"}).Set(float64(serverAds.Len()))

				// JWKS
				jwksMetrics := namespaceKeys.Metrics()
				metrics.PelicanDirectorTTLCache.With(prometheus.Labels{"name": "jwks", "type": "insersions"}).Set(float64(jwksMetrics.Insertions))
				metrics.PelicanDirectorTTLCache.With(prometheus.Labels{"name": "jwks", "type": "evictions"}).Set(float64(jwksMetrics.Evictions))
				metrics.PelicanDirectorTTLCache.With(prometheus.Labels{"name": "jwks", "type": "hits"}).Set(float64(jwksMetrics.Hits))
				metrics.PelicanDirectorTTLCache.With(prometheus.Labels{"name": "jwks", "type": "misses"}).Set(float64(jwksMetrics.Misses))
				metrics.PelicanDirectorTTLCache.With(prometheus.Labels{"name": "jwks", "type": "total"}).Set(float64(namespaceKeys.Len()))

				// Maps
				metrics.PelicanDirectorMapItemsTotal.WithLabelValues("filteredServers").Set(float64(len(filteredServers)))
				metrics.PelicanDirectorMapItemsTotal.WithLabelValues("healthTestUtils").Set(float64(len(healthTestUtils)))
				metrics.PelicanDirectorMapItemsTotal.WithLabelValues("originStatUtils").Set(float64(len(statUtils)))
			}
		}
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
func LaunchServerIOQuery(ctx context.Context, egrp *errgroup.Group) {
	serverIOQueryLoop := func(ctx context.Context) error {
		tick := time.NewTicker(15 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-tick.C:
				// Requests expires before the next round starts
				ddlCtx, cancel := context.WithDeadline(ctx, time.Now().Add(10*time.Second))
				defer cancel()

				// Query all the servers and filter them out later
				// We are interested in the derivative/rate of the total server IO over the past 5min
				query := `rate(xrootd_server_io_total{job="origin_cache_servers"}[5m])`
				queryResult, err := queryPromtheus(ddlCtx, query, true)
				if err != nil {
					log.Debugf("Failed to update IO stat: querying Prometheus responded with an error: %v", err)
					continue
				}
				if queryResult.ResultType != "vector" {
					log.Debugf("Failed to update IO stat: Prometheus response returns %s type, expected a vector", queryResult.ResultType)
					continue
				}
				for _, result := range queryResult.Result {
					serverUrlRaw, ok := result.Metric["server_url"]
					if !ok {
						log.Debugf("Failed to update IO stat: Prometheus query response does not contain server_url metric: %#v", result)
						continue
					}
					serverUrl, ok := serverUrlRaw.(string)
					if !ok {
						log.Debugf("Failed to update IO stat: Prometheus query response contains invalid server_url: %#v", result)
						continue
					}
					ioDerivStr := result.Values[0].Value
					if ioDerivStr == "" {
						log.Debugf("Skipped updating IO stat for server %s: Prometheus query responded with empty I/O value: %#v", serverUrl, result)
						continue
					} else {
						ioDeriv, err := strconv.ParseFloat(ioDerivStr, 64)
						if err != nil {
							log.Debugf("Failed to update IO stat for server %s: failed to convert Prometheus response to a float number: %s", serverUrl, ioDerivStr)
							continue
						}
						serverAd := serverAds.Get(serverUrl)
						if serverAd == nil {
							log.Debugf("Failed to update IO stat for server %s: server does not exist in the director", serverUrl)
							continue
						}
						serverAd.Value().SetIOLoad(ioDeriv)
					}
				}
				log.Debugf("Successfully updated server IO stat. Received %d updates.", len(queryResult.Result))
			}
		}
	}

	egrp.Go(func() error {
		return serverIOQueryLoop(ctx)
	})
}
