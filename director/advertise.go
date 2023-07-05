package director

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"

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
		BasePath string `json:"base_path"`
		Issuer string `json:"issuer"`
		MaxScopeDepth int `json:"max_scope_depth"`
		Strategy string `json:"strategy"`
		VaultIssuer string `json:"vault_issuer"`
		VaultServer string `json:"vault_server"`
	}

	Namespace struct {
		Caches               []Cache `json:"caches"`
		CredentialGeneration CredentialGeneration `json:"credential_generation"`
		DirlistHost          string  `json:"dirlisthost"`
		Path                 string  `json:"path"`
		ReadHTTPS            bool    `json:"readhttps"`
		UseTokenOnRead       bool    `json:"usetokenonread"`
		WritebackHost        string  `json:"writebackhost"`
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

	for _, ns := range namespaces.Namespaces {
		originAd := ServerAd{}
		originNameStr := ns.WritebackHost
		originURL, err := url.Parse(originNameStr)
		if err != nil {
			return err
		}
		originAd.Name = originURL.Host
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
			cacheURL, err := url.Parse(cache.AuthEndpoint)
			if err != nil {
				log.Warningf("Namespace JSON returned cache %s with invalid URL %s",
					cache.Resource, cache.AuthEndpoint)
			}
			cacheAd.URL = *cacheURL
			cacheNS := NamespaceAd{}
			cacheNS.Path = ns.Path
			cacheNS.RequireToken = ns.UseTokenOnRead
			cacheAdMap[cacheAd] = append(cacheAdMap[cacheAd], cacheNS)
		}
	}
	return nil
}
