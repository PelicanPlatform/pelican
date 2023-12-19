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
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	log "github.com/sirupsen/logrus"
)

type (
	NamespaceAd struct {
		RequireToken  bool         `json:"requireToken"`
		Path          string       `json:"path"`
		Issuer        url.URL      `json:"url"`
		MaxScopeDepth uint         `json:"maxScopeDepth"`
		Strategy      StrategyType `json:"strategy"`
		BasePath      string       `json:"basePath"`
		VaultServer   string       `json:"vaultServer"`
		DirlistHost   string       `json:"dirlisthost"`
		WritebackHost string       `json:"writebackhost"`
	}

	ServerAd struct {
		Name      string
		AuthURL   url.URL
		URL       url.URL // This is server's XRootD URL for file transfer
		WebURL    url.URL // This is server's Web interface and API
		Type      ServerType
		Latitude  float64
		Longitude float64
	}

	ServerType   string
	StrategyType string
)

const (
	CacheType  ServerType = "Cache"
	OriginType ServerType = "Origin"
)

const (
	OAuthStrategy StrategyType = "OAuth2"
	VaultStrategy StrategyType = "Vault"
)

var (
	serverAds     = ttlcache.New[ServerAd, []NamespaceAd](ttlcache.WithTTL[ServerAd, []NamespaceAd](15 * time.Minute))
	serverAdMutex = sync.RWMutex{}
)

func RecordAd(ad ServerAd, namespaceAds *[]NamespaceAd) {
	if err := UpdateLatLong(&ad); err != nil {
		log.Debugln("Failed to lookup GeoIP coordinates for host", ad.URL.Host)
	}
	serverAdMutex.Lock()
	defer serverAdMutex.Unlock()
	serverAds.Set(ad, *namespaceAds, ttlcache.DefaultTTL)
}

func UpdateLatLong(ad *ServerAd) error {
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
	lat, long, err := GetLatLong(addr)
	if err != nil {
		return err
	}
	ad.Latitude = lat
	ad.Longitude = long
	return nil
}

func matchesPrefix(reqPath string, namespaceAds []NamespaceAd) *NamespaceAd {
	var best *NamespaceAd

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
				best = new(NamespaceAd)
			}
			*best = namespace
		}
	}
	return best
}

func GetAdsForPath(reqPath string) (originNamespace NamespaceAd, originAds []ServerAd, cacheAds []ServerAd) {
	serverAdMutex.RLock()
	defer serverAdMutex.RUnlock()

	// Clean the path, but re-append a trailing / to deal with some namespaces
	// from topo that have a trailing /
	reqPath = path.Clean(reqPath)
	reqPath += "/"

	// Iterate through all of the server ads. For each "item", the key
	// is the server ad itself (either cache or origin), and the value
	// is a slice of namespace prefixes are supported by that server
	var best *NamespaceAd
	for _, item := range serverAds.Items() {
		if item == nil {
			continue
		}
		serverAd := item.Key()
		if serverAd.Type == OriginType {
			if ns := matchesPrefix(reqPath, item.Value()); ns != nil {
				if best == nil || len(ns.Path) > len(best.Path) {
					best = ns
					// If anything was previously set by a namespace that constituted a shorter
					// prefix, we overwrite that here because we found a better ns. We also clear
					// the other slice of server ads, because we know those aren't good anymore
					originAds = append(originAds[:0], serverAd)
					cacheAds = []ServerAd{}
				} else if ns.Path == best.Path {
					originAds = append(originAds, serverAd)
				}
			}
			continue
		} else if serverAd.Type == CacheType {
			if ns := matchesPrefix(reqPath, item.Value()); ns != nil {
				if best == nil || len(ns.Path) > len(best.Path) {
					best = ns
					cacheAds = append(cacheAds[:0], serverAd)
					originAds = []ServerAd{}
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
