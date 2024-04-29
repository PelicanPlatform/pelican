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
	"fmt"
	"net"
	"net/netip"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

type filterType string

const (
	permFiltered filterType = "permFiltered" // Read from Director.FilteredServers
	tempFiltered filterType = "tempFiltered" // Filtered by web UI
	tempAllowed  filterType = "tempAllowed"  // Read from Director.FilteredServers but mutated by web UI
)

var (
	serverAds            = ttlcache.New(ttlcache.WithTTL[server_structs.ServerAd, []server_structs.NamespaceAdV2](15 * time.Minute))
	filteredServers      = map[string]filterType{}
	filteredServersMutex = sync.RWMutex{}
)

func recordAd(ad server_structs.ServerAd, namespaceAds *[]server_structs.NamespaceAdV2) {
	if err := updateLatLong(&ad); err != nil {
		log.Debugln("Failed to lookup GeoIP coordinates for host", ad.URL.Host)
	}

	customTTL := param.Director_AdvertisementTTL.GetDuration()
	if customTTL == 0 {
		serverAds.Set(ad, *namespaceAds, ttlcache.DefaultTTL)
	} else {
		serverAds.Set(ad, *namespaceAds, customTTL)
	}
}

func updateLatLong(ad *server_structs.ServerAd) error {
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

func matchesPrefix(reqPath string, namespaceAds []server_structs.NamespaceAdV2) *server_structs.NamespaceAdV2 {
	var best *server_structs.NamespaceAdV2

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
				best = new(server_structs.NamespaceAdV2)
			}
			*best = namespace
		}
	}
	return best
}

func getAdsForPath(reqPath string) (originNamespace server_structs.NamespaceAdV2, originAds []server_structs.ServerAd, cacheAds []server_structs.ServerAd) {
	skippedServers := []server_structs.ServerAd{}

	// Clean the path, but re-append a trailing / to deal with some namespaces
	// from topo that have a trailing /
	reqPath = path.Clean(reqPath)
	reqPath += "/"

	// Iterate through all of the server ads. For each "item", the key
	// is the server ad itself (either cache or origin), and the value
	// is a slice of namespace prefixes are supported by that server
	var best *server_structs.NamespaceAdV2
	ads := serverAds.Keys()
	sortedAds := sortServerAdsByTopo(ads)
	for _, serverAd := range sortedAds {
		var namespaces []server_structs.NamespaceAdV2
		if serverAds.Has(serverAd) {
			namespaces = serverAds.Get(serverAd).Value()
		} else {
			continue
		}
		if filtered, ft := checkFilter(serverAd.Name); filtered {
			log.Debugf("Skipping %s server %s as it's in the filtered server list with type %s", serverAd.Type, serverAd.Name, ft)
			continue
		}
		if ns := matchesPrefix(reqPath, namespaces); ns != nil {
			if best == nil || len(ns.Path) > len(best.Path) {
				best = ns
				// If anything was previously set by a namespace that constituted a shorter
				// prefix, we overwrite that here because we found a better ns. We also clear
				// the other slice of server ads, because we know those aren't good anymore
				if serverAd.Type == server_structs.OriginType {
					originAds = []server_structs.ServerAd{serverAd}
					cacheAds = []server_structs.ServerAd{}
				} else if serverAd.Type == server_structs.CacheType {
					originAds = []server_structs.ServerAd{}
					cacheAds = []server_structs.ServerAd{serverAd}
				}
			} else if ns.Path == best.Path {
				// If the current is from Pelican but the best is from topology
				// then replace the topology best by Pelican best
				if !ns.FromTopology && best.FromTopology {
					best = ns
				}
				// We treat serverAds differently from namespace
				if serverAd.Type == server_structs.OriginType {
					// For origin, if there's no origin in the list yet, and there's a matched one from topology, then add it
					// However, if the first one is from Topology but the second matched one is from Pelican, replace it (repeat this process)
					if len(originAds) == 0 {
						originAds = append(originAds, serverAd)
					} else {
						if originAds[len(originAds)-1].FromTopology == serverAd.FromTopology {
							originAds = append(originAds, serverAd)
						} else if !serverAd.FromTopology {
							// Incoming ad is from Pelican and current last item in originAd is from Topology:
							// clear originAds and put Pelican server in
							skippedServers = append(skippedServers, originAds...)
							originAds = []server_structs.ServerAd{serverAd}
						} else {
							// Incoming ad is from Topology but current last item in originAd is from Pelican: skip
							skippedServers = append(skippedServers, serverAd)
							continue
						}
					}
				} else if serverAd.Type == server_structs.CacheType {
					// For caches, we allow both server from Topology and Pelican to serve the same namespace
					cacheAds = append(cacheAds, serverAd)
				}
			}
		}
	}

	if best != nil {
		originNamespace = *best
	}
	if len(skippedServers) > 0 {
		log.Debugf(
			"getAdsForPath: The following matched servers from OSDF topology are skipped for the request path %s: %s",
			reqPath,
			server_structs.ServerAdsToServerNameURL(skippedServers),
		)
	}
	return
}
