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
	"net"
	"net/netip"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

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
	// The in-memory cache of xrootd server advertisement, with the key being ServerAd.URL.String()
	serverAds            = ttlcache.New(ttlcache.WithTTL[string, *server_structs.Advertisement](15 * time.Minute))
	filteredServers      = map[string]filterType{} // The map holds servers that are disabled, with the key being the ServerAd.Name
	filteredServersMutex = sync.RWMutex{}
)

func recordAd(ctx context.Context, ad server_structs.ServerAd, namespaceAds *[]server_structs.NamespaceAdV2) {
	if err := updateLatLong(&ad); err != nil {
		log.Debugln("Failed to lookup GeoIP coordinates for host", ad.URL.Host)
	}

	if ad.URL.String() == "" {
		log.Errorf("The URL of the serverAd %#v is empty. Cannot set the TTL cache.", ad)
		return
	}
	// Since servers from topology always use http, while servers from Pelican always use https
	// we want to ignore the scheme difference when checking duplicates (only consider hostname:port)
	rawURL := ad.URL.String() // could be http (topology) or https (Pelican or some topology ones)
	httpURL := ad.URL.String()
	httpsURL := ad.URL.String()
	if strings.HasPrefix(rawURL, "https") {
		httpURL = "http" + strings.TrimPrefix(rawURL, "https")
	}
	if strings.HasPrefix(rawURL, "http://") {
		httpsURL = "https://" + strings.TrimPrefix(rawURL, "http://")
	}

	existing := serverAds.Get(httpURL)
	if existing == nil {
		existing = serverAds.Get(httpsURL)
	}
	if existing == nil {
		existing = serverAds.Get(rawURL)
	}

	// There's an existing ad in the cache
	if existing != nil {
		if ad.FromTopology && !existing.Value().FromTopology {
			// if the incoming is from topology but the existing is from Pelican
			log.Debugf("The ServerAd generated from topology with name %s and URL %s was ignored because there's already a Pelican ad for this server", ad.Name, ad.URL.String())
			return
		}
		if !ad.FromTopology && existing.Value().FromTopology {
			// Pelican server will overwrite topology one. We leave a message to let admin know
			log.Debugf("The existing ServerAd generated from topology with name %s and URL %s is replaced by the Pelican server with name %s", existing.Value().Name, existing.Value().URL.String(), ad.Name)
			serverAds.Delete(existing.Value().URL.String())
		}
	}

	customTTL := param.Director_AdvertisementTTL.GetDuration()
	if customTTL == 0 {
		serverAds.Set(ad.URL.String(), &server_structs.Advertisement{ServerAd: ad, NamespaceAds: *namespaceAds}, ttlcache.DefaultTTL)
	} else {
		serverAds.Set(ad.URL.String(), &server_structs.Advertisement{ServerAd: ad, NamespaceAds: *namespaceAds}, customTTL)
	}

	// Prepare `stat` call utilities
	statUtilsMutex.Lock()
	defer statUtilsMutex.Unlock()
	statUtil, ok := statUtils[ad.URL.String()]
	if !ok || statUtil.Errgroup == nil {
		baseCtx, cancel := context.WithCancel(ctx)
		concLimit := param.Director_StatConcurrencyLimit.GetInt()
		statErrGrp := errgroup.Group{}
		statErrGrp.SetLimit(concLimit)
		newUtil := serverStatUtil{
			Errgroup: &statErrGrp,
			Cancel:   cancel,
			Context:  baseCtx,
		}
		statUtils[ad.URL.String()] = newUtil
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
	ads := []*server_structs.Advertisement{}
	for _, item := range serverAds.Items() {
		ads = append(ads, item.Value())
	}
	sortedAds := sortServerAdsByTopo(ads)
	for _, ad := range sortedAds {
		if filtered, ft := checkFilter(ad.Name); filtered {
			log.Debugf("Skipping %s server %s as it's in the filtered server list with type %s", ad.Type, ad.Name, ft)
			continue
		}
		if ns := matchesPrefix(reqPath, ad.NamespaceAds); ns != nil {
			if best == nil || len(ns.Path) > len(best.Path) {
				best = ns
				// If anything was previously set by a namespace that constituted a shorter
				// prefix, we overwrite that here because we found a better ns. We also clear
				// the other slice of server ads, because we know those aren't good anymore
				if ad.Type == server_structs.OriginType {
					originAds = []server_structs.ServerAd{ad.ServerAd}
					cacheAds = []server_structs.ServerAd{}
				} else if ad.Type == server_structs.CacheType {
					originAds = []server_structs.ServerAd{}
					cacheAds = []server_structs.ServerAd{ad.ServerAd}
				}
			} else if ns.Path == best.Path {
				// If the current is from Pelican but the best is from topology
				// then replace the topology best by Pelican best
				if !ns.FromTopology && best.FromTopology {
					best = ns
				}
				// We treat serverAds differently from namespace
				if ad.Type == server_structs.OriginType {
					// For origin, if there's no origin in the list yet, and there's a matched one from topology, then add it
					// However, if the first one is from Topology but the second matched one is from Pelican, replace it (repeat this process)
					if len(originAds) == 0 {
						originAds = append(originAds, ad.ServerAd)
					} else {
						if originAds[len(originAds)-1].FromTopology == ad.FromTopology {
							originAds = append(originAds, ad.ServerAd)
						} else if !ad.FromTopology {
							// Incoming ad is from Pelican and current last item in originAd is from Topology:
							// clear originAds and put Pelican server in
							skippedServers = append(skippedServers, originAds...)
							originAds = []server_structs.ServerAd{ad.ServerAd}
						} else {
							// Incoming ad is from Topology but current last item in originAd is from Pelican: skip
							skippedServers = append(skippedServers, ad.ServerAd)
							continue
						}
					}
				} else if ad.Type == server_structs.CacheType {
					// For caches, we allow both server from Topology and Pelican to serve the same namespace
					cacheAds = append(cacheAds, ad.ServerAd)
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
