/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/pelicanplatform/pelican/common"
	"github.com/pelicanplatform/pelican/param"
	log "github.com/sirupsen/logrus"
)

var (
	serverAds     = ttlcache.New[common.ServerAd, []common.NamespaceAdV2](ttlcache.WithTTL[common.ServerAd, []common.NamespaceAdV2](15 * time.Minute))
	serverAdMutex = sync.RWMutex{}
)

func recordAd(ad common.ServerAd, namespaceAds *[]common.NamespaceAdV2) {
	if err := updateLatLong(&ad); err != nil {
		log.Debugln("Failed to lookup GeoIP coordinates for host", ad.URL.Host)
	}
	serverAdMutex.Lock()
	defer serverAdMutex.Unlock()

	customTTL := param.Director_AdvertisementTTL.GetDuration()
	if customTTL == 0 {
		serverAds.Set(ad, *namespaceAds, ttlcache.DefaultTTL)
	} else {
		serverAds.Set(ad, *namespaceAds, customTTL)
	}
}

func updateLatLong(ad *common.ServerAd) error {
	if ad == nil {
		return errors.New("Cannot provide a nil ad to UpdateLatLong")
	}
	hostname := strings.Split(ad.URL.Host, ":")[0]
	ip, err := net.LookupIP(hostname)
	if err != nil {
		return err
	}
	if len(ip) == 0 {
		return fmt.Errorf("Unable to find an IP address for hostname %s", hostname)
	}
	addr, ok := netip.AddrFromSlice(ip[0])
	if !ok {
		return errors.New("Failed to create address object from IP")
	}
	lat, long, err := getLatLong(addr)
	if err != nil {
		return err
	}
	ad.Latitude = lat
	ad.Longitude = long
	return nil
}

func matchesPrefix(reqPath string, namespaceAds []common.NamespaceAdV2) *common.NamespaceAdV2 {
	var best *common.NamespaceAdV2

	for _, namespace := range namespaceAds {
		serverPath := namespace.Path
		if strings.Compare(serverPath, reqPath) == 0 {
			return &namespace
		}

		// Some namespaces in Topology already have the trailing /, some don't
		// Perhaps this should be standardized, but in case it isn't we need to
		// handle it throughout this function. Note that reqPath already has the
		// tail from being called by GetAdsForPath
		if serverPath[len(serverPath)-1:] != "/" {
			serverPath += "/"
		}

		// The assignment of best doesn't account for the trailing / that we need to consider
		// Account for that by setting up a tmpBest string that adds the / if needed
		var tmpBest string
		if best != nil {
			tmpBest = best.Path
			if tmpBest[len(tmpBest)-1:] != "/" {
				tmpBest += "/"
			}
		}

		// Make the len comparison with tmpBest, because serverPath is one char longer now
		if strings.HasPrefix(reqPath, serverPath) && len(serverPath) > len(tmpBest) {
			if best == nil {
				best = new(common.NamespaceAdV2)
			}
			*best = namespace
		}
	}
	return best
}

func getAdsForPath(reqPath string) (originNamespace common.NamespaceAdV2, originAds []common.ServerAd, cacheAds []common.ServerAd) {
	serverAdMutex.RLock()
	defer serverAdMutex.RUnlock()

	// Clean the path, but re-append a trailing / to deal with some namespaces
	// from topo that have a trailing /
	reqPath = path.Clean(reqPath)
	reqPath += "/"

	// Iterate through all of the server ads. For each "item", the key
	// is the server ad itself (either cache or origin), and the value
	// is a slice of namespace prefixes are supported by that server
	var best *common.NamespaceAdV2
	for _, item := range serverAds.Items() {
		if item == nil {
			continue
		}
		serverAd := item.Key()
		if serverAd.Type == common.OriginType {
			if ns := matchesPrefix(reqPath, item.Value()); ns != nil {
				if best == nil || len(ns.Path) > len(best.Path) {
					best = ns
					// If anything was previously set by a namespace that constituted a shorter
					// prefix, we overwrite that here because we found a better ns. We also clear
					// the other slice of server ads, because we know those aren't good anymore
					originAds = append(originAds[:0], serverAd)
					cacheAds = []common.ServerAd{}
				} else if ns.Path == best.Path {
					originAds = append(originAds, serverAd)
				}
			}
			continue
		} else if serverAd.Type == common.CacheType {
			if ns := matchesPrefix(reqPath, item.Value()); ns != nil {
				if best == nil || len(ns.Path) > len(best.Path) {
					best = ns
					cacheAds = append(cacheAds[:0], serverAd)
					originAds = []common.ServerAd{}
				} else if ns.Path == best.Path {
					cacheAds = append(cacheAds, serverAd)
				}
			}
		}
	}

	if best != nil {
		originNamespace = *best
	}
	return
}
