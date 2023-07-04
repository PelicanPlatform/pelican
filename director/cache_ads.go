package director

import (
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

type (
	NamespaceAd struct {
		RequireToken bool
		Path string
		Issuer url.URL
		MaxScopeDepth uint
		Strategy StrategyType
		BasePath string
		VaultServer string
	}

	ServerAd struct {
		Name string
		URL url.URL
		Type ServerType
		Latitude float64
		Longitude float64
	}

	ServerType string
	StrategyType string
)

const (
	CacheType ServerType = "Cache"
	OriginType ServerType = "Origin"
)

const (
	OAuthStrategy StrategyType = "OAuth2"
	VaultStrategy StrategyType = "Vault"
)
	

var (
	serverAds = ttlcache.New[ServerAd, []NamespaceAd](ttlcache.WithTTL[ServerAd, []NamespaceAd](15 * time.Minute))
	serverAdMutex = sync.RWMutex{}
)

func matchesPrefix(reqPath string, namespaceAds []NamespaceAd) *NamespaceAd {
	for _, namespace := range namespaceAds {
		serverPath := namespace.Path
		if serverPath == reqPath {
			return &namespace
		}
		serverPath += "/"
		if strings.HasPrefix(reqPath, serverPath) {
			return &namespace
		}
	}
	return nil
}

func GetCacheAdsForPath(reqPath string) (originNamespace NamespaceAd, ads []ServerAd) {
	serverAdMutex.RLock()
	defer serverAdMutex.Unlock()
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
			}
			continue
		} else if serverAd.Type == CacheType && matchesPrefix(reqPath, item.Value()) != nil{
			ads = append(ads, serverAd)
		}
	} 
	return
}
