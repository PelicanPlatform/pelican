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
		RequireToken  bool
		Path          string
		Issuer        url.URL
		MaxScopeDepth uint
		Strategy      StrategyType
		BasePath      string
		VaultServer   string
	}

	ServerAd struct {
		Name      string
		AuthURL   url.URL
		URL       url.URL
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
	for _, namespace := range namespaceAds {
		serverPath := namespace.Path
		if strings.Compare(serverPath, reqPath) == 0 {
			return &namespace
		}
		// Some namespaces in Topology already have the trailing /, some don't
		// Perhaps this should be standardized, but in case it isn't we need to
		// handle it
		if serverPath[len(serverPath)-1:] != "/" {
			serverPath += "/"
		}
		if strings.HasPrefix(reqPath, serverPath) {
			return &namespace
		}
	}
	return nil
}

func GetAdsForPath(reqPath string) (originNamespace NamespaceAd, originAds []ServerAd, cacheAds []ServerAd) {
	serverAdMutex.RLock()
	defer serverAdMutex.RUnlock()
	reqPath = path.Clean(reqPath)

	for _, item := range serverAds.Items() {
		if item == nil {
			continue
		}
		serverAd := item.Key()
		if serverAd.Type == OriginType {
			ns := matchesPrefix(reqPath, item.Value())
			if ns != nil {
				originNamespace = *ns
				originAds = append(originAds, serverAd)
			}
			continue
		} else if serverAd.Type == CacheType {
			if matchesPrefix(reqPath, item.Value()) != nil {
				cacheAds = append(cacheAds, serverAd)
			}
		}
	}
	return
}

func PeriodicCacheReload() {
	for {
		// The ad cache times out every 15 minutes, so update it every
		// 10. If a key isn't updated, it will survive for 5 minutes
		// and then disappear
		time.Sleep(time.Minute * 10)
		AdvertiseOSDF()
	}
}
