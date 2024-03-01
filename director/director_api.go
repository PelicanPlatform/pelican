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

	"github.com/jellydator/ttlcache/v3"
	"github.com/pelicanplatform/pelican/common"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// List all namespaces from origins registered at the director
func listNamespacesFromOrigins() []common.NamespaceAdV2 {

	serverAdMutex.RLock()
	defer serverAdMutex.RUnlock()

	serverAdItems := serverAds.Items()
	namespaces := make([]common.NamespaceAdV2, 0, len(serverAdItems))
	for _, item := range serverAdItems {
		if item.Key().Type == common.OriginType {
			namespaces = append(namespaces, item.Value()...)
		}
	}
	return namespaces
}

// List all serverAds in the cache that matches the serverType array
func listServerAds(serverTypes []common.ServerType) []common.ServerAd {
	serverAdMutex.RLock()
	defer serverAdMutex.RUnlock()
	ads := make([]common.ServerAd, 0)
	for _, ad := range serverAds.Keys() {
		for _, serverType := range serverTypes {
			if ad.Type == serverType {
				ads = append(ads, ad)
			}
		}
	}
	return ads
}

// Configure TTL caches to enable cache eviction and other additional cache events handling logic
//
// The `ctx` is the context for listening to server shutdown event in order to cleanup internal cache eviction
// goroutine and `wg` is the wait group to notify when the clean up goroutine finishes
func ConfigTTLCache(ctx context.Context, egrp *errgroup.Group) {
	// Start automatic expired item deletion
	go serverAds.Start()
	go namespaceKeys.Start()

	serverAds.OnEviction(func(ctx context.Context, er ttlcache.EvictionReason, i *ttlcache.Item[common.ServerAd, []common.NamespaceAdV2]) {
		healthTestUtilsMutex.RLock()
		defer healthTestUtilsMutex.RUnlock()
		if util, exists := healthTestUtils[i.Key()]; exists {
			util.Cancel()
			if util.ErrGrp != nil {
				err := util.ErrGrp.Wait()
				if err != nil {
					log.Debugf("Error from errgroup when evict the registration from TTL cache for %s %s %s", string(i.Key().Type), i.Key().Name, err.Error())
				} else {
					log.Debugf("Errgroup successfully emptied at TTL cache eviction for %s %s", string(i.Key().Type), i.Key().Name)
				}
			} else {
				log.Debugf("errgroup is nil when evict the registration from TTL cache for %s %s", string(i.Key().Type), i.Key().Name)
			}
		} else {
			log.Debugf("healthTestUtil not found for %s when evicting TTL cache item", i.Key().Name)
		}

		if i.Key().Type == common.OriginType {
			originStatUtilsMutex.Lock()
			defer originStatUtilsMutex.Unlock()
			statUtil, ok := originStatUtils[i.Key().URL]
			if ok {
				statUtil.Cancel()
				if err := statUtil.Errgroup.Wait(); err != nil {
					log.Info(fmt.Sprintf("Error happened when stopping origin %q stat goroutine group: %v", i.Key().Name, err))
				}
				delete(originStatUtils, i.Key().URL)
			}
		}
	})

	// Put stop logic in a separate goroutine so that parent function is not blocking
	egrp.Go(func() error {
		<-ctx.Done()
		log.Info("Gracefully stopping director TTL cache eviction...")
		serverAdMutex.Lock()
		defer serverAdMutex.Unlock()
		namespaceKeysMutex.Lock()
		defer namespaceKeysMutex.Unlock()
		serverAds.DeleteAll()
		serverAds.Stop()
		namespaceKeys.DeleteAll()
		namespaceKeys.Stop()
		log.Info("Director TTL cache eviction has been stopped")
		return nil
	})
}
