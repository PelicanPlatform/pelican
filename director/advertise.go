package director

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type (
	Cache struct {
		AuthEndpoint string `json:"auth_endpoint"`
		Endpoint     string `json:"endpoint"`
		Resource     string `json:"resource"`
	}

	CredentialGeneration struct {
		BasePath      string `json:"base_path"`
		Issuer        string `json:"issuer"`
		MaxScopeDepth int    `json:"max_scope_depth"`
		Strategy      string `json:"strategy"`
		VaultIssuer   string `json:"vault_issuer"`
		VaultServer   string `json:"vault_server"`
	}

	Namespace struct {
		Caches               []Cache              `json:"caches"`
		CredentialGeneration CredentialGeneration `json:"credential_generation"`
		DirlistHost          string               `json:"dirlisthost"`
		Path                 string               `json:"path"`
		ReadHTTPS            bool                 `json:"readhttps"`
		UseTokenOnRead       bool                 `json:"usetokenonread"`
		WritebackHost        string               `json:"writebackhost"`
	}

	NamespaceJSON struct {
		Caches     []Cache     `json:"caches"`
		Namespaces []Namespace `json:"namespaces"`
	}
)

func AdvertiseOSDF() error {
	namespaceURL := viper.GetString("NamespaceURL")
	if namespaceURL == "" {
		return errors.New("NamespaceURL configuration option not set")
	}

	req, err := http.NewRequest("GET", namespaceURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/json")

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var namespaces NamespaceJSON
	if err = json.Unmarshal(respBytes, &namespaces); err != nil {
		return err
	}

	cacheAdMap := make(map[ServerAd][]NamespaceAd)

	counter := 0
	for _, ns := range namespaces.Namespaces {
		counter += 1
		originAd := ServerAd{}
		originNameStr := ns.WritebackHost
		originURL, err := url.Parse(originNameStr)
		if err != nil {
			return err
		}
		// originAd.Name = originURL.Host
		// TEMPORARY HACK TO GET THINGS MOVING, DON'T FORGET TO FIX LATER
		// The issue is that originURL is the namespace's writebackHost,
		// which in most cases from topology is null. This causes problems,
		// because the ttlcache is key-value based, and all the null keys
		//
		originAd.Name = strconv.Itoa(counter)
		originAd.URL = *originURL
		originAd.Type = OriginType

		originNS := NamespaceAd{}
		originNS.RequireToken = ns.UseTokenOnRead
		originNS.Path = ns.Path
		issuerURL, err := url.Parse(ns.CredentialGeneration.Issuer)
		if err != nil {
			return err
		}
		originNS.Issuer = *issuerURL
		originNS.MaxScopeDepth = uint(ns.CredentialGeneration.MaxScopeDepth)
		originNS.Strategy = StrategyType(ns.CredentialGeneration.Strategy)
		originNS.BasePath = ns.CredentialGeneration.BasePath
		originNS.VaultServer = ns.CredentialGeneration.VaultServer

		RecordAd(originAd, &[]NamespaceAd{originNS})

		for _, cache := range ns.Caches {
			cacheAd := ServerAd{}
			cacheAd.Type = CacheType
			cacheAd.Name = cache.Resource
			// url.Parse requires that the scheme be present before the hostname,
			// but most endpoints do not have a scheme. As such, we need to add
			// a scheme. Luckily, we don't use this anywhere else (it's just to
			// make the url.Parse function behave as expected)
			if !strings.HasPrefix(cache.AuthEndpoint, "http") { // just in case there's already an http(s) tacked in front
				cache.AuthEndpoint = "https://" + cache.AuthEndpoint
			}
			if !strings.HasPrefix(cache.Endpoint, "http") { // just in case there's already an http(s) tacked in front
				cache.Endpoint = "http://" + cache.Endpoint
			}
			cacheAuthURL, err := url.Parse(cache.AuthEndpoint)
			if err != nil {
				log.Warningf("Namespace JSON returned cache %s with invalid authenticated URL %s",
					cache.Resource, cache.AuthEndpoint)
			}
			cacheAd.AuthURL = *cacheAuthURL
			// if counter < 10 {
			// 	fmt.Println("    cacheAd.AuthURL:", cacheAd.AuthURL)
			// }
			cacheURL, err := url.Parse(cache.Endpoint)
			if err != nil {
				log.Warningf("Namespace JSON returned cache %s with invalid non-authenticated URL %s",
					cache.Resource, cache.Endpoint)
			}
			cacheAd.URL = *cacheURL

			// if counter < 10 {
			// 	fmt.Println("    cacheAd.URL:", cacheAd.URL)
			// }

			cacheNS := NamespaceAd{}
			cacheNS.Path = ns.Path
			cacheNS.RequireToken = ns.UseTokenOnRead
			cacheAdMap[cacheAd] = append(cacheAdMap[cacheAd], cacheNS)

		}
	}
	for cacheAd, namespacesSlice := range cacheAdMap {
		// counter += 1
		// fmt.Println("Cache url:", cacheAd.URL)
		RecordAd(cacheAd, &namespacesSlice)
	}
	// fmt.Println(" cache counter:", counter)
	return nil
}
