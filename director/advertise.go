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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type (
	Server struct {
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
		Caches               []Server             `json:"caches"`
		Origins              []Server             `json:"origins"`
		CredentialGeneration CredentialGeneration `json:"credential_generation"`
		DirlistHost          string               `json:"dirlisthost"`
		Path                 string               `json:"path"`
		ReadHTTPS            bool                 `json:"readhttps"`
		UseTokenOnRead       bool                 `json:"usetokenonread"`
		WritebackHost        string               `json:"writebackhost"`
	}

	NamespaceJSON struct {
		Caches     []Server    `json:"caches"`
		Namespaces []Namespace `json:"namespaces"`
	}
)

// Populate internal cache with origin/cache ads
func AdvertiseOSDF() error {
	namespaceURL := viper.GetString("TopologyNamespaceURL")
	if namespaceURL == "" {
		return errors.New("Topology namespaces.json configuration option (`TopologyNamespaceURL`) not set")
	}

	req, err := http.NewRequest("GET", namespaceURL, nil)
	if err != nil {
		return errors.Wrap(err, "Failure when getting OSDF namespace data from topology")
	}

	req.Header.Set("Accept", "application/json")

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "Failure when getting response for OSDF namespace data")
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		return fmt.Errorf("Error response %v from OSDF namespace endpoint: %v", resp.StatusCode, resp.Status)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "Failure when reading OSDF namespace response")
	}

	var namespaces NamespaceJSON
	if err = json.Unmarshal(respBytes, &namespaces); err != nil {
		return errors.Wrapf(err, "Failure when parsing JSON response from topology URL %v", namespaceURL)
	}

	cacheAdMap := make(map[ServerAd][]NamespaceAd)
	originAdMap := make(map[ServerAd][]NamespaceAd)
	for _, ns := range namespaces.Namespaces {
		nsAd := NamespaceAd{}
		nsAd.RequireToken = ns.UseTokenOnRead
		nsAd.Path = ns.Path
		issuerURL, err := url.Parse(ns.CredentialGeneration.Issuer)
		if err != nil {
			log.Warningf("Invalid URL %v when parsing topology response: %v\n", ns.CredentialGeneration.Issuer, err)
			continue
		}
		nsAd.Issuer = *issuerURL
		nsAd.MaxScopeDepth = uint(ns.CredentialGeneration.MaxScopeDepth)
		nsAd.Strategy = StrategyType(ns.CredentialGeneration.Strategy)
		nsAd.BasePath = ns.CredentialGeneration.BasePath
		nsAd.VaultServer = ns.CredentialGeneration.VaultServer

		// We assume each namespace may have multiple origins, although most likely will not
		// Some namespaces show up in topology but don't have an origin (perhaps because
		// they're listed as inactive by topology). These namespaces will all be mapped to the
		// same useless origin ad, resulting in a 404 for queries to those namespaces
		for _, origin := range ns.Origins {
			originAd := ServerAd{}
			originAd.Type = OriginType
			originAd.Name = origin.Resource
			// url.Parse requires that the scheme be present before the hostname,
			// but endpoints do not have a scheme. As such, we need to add one for the.
			// correct parsing. Luckily, we don't use this anywhere else (it's just to
			// make the url.Parse function behave as expected)
			if !strings.HasPrefix(origin.AuthEndpoint, "http") { // just in case there's already an http(s) tacked in front
				origin.AuthEndpoint = "https://" + origin.AuthEndpoint
			}
			if !strings.HasPrefix(origin.Endpoint, "http") { // just in case there's already an http(s) tacked in front
				origin.Endpoint = "http://" + origin.Endpoint
			}
			originAuthURL, err := url.Parse(origin.AuthEndpoint)
			if err != nil {
				log.Warningf("Namespace JSON returned origin %s with invalid authenticated URL %s",
					origin.Resource, origin.AuthEndpoint)
			}
			originAd.AuthURL = *originAuthURL
			originURL, err := url.Parse(origin.Endpoint)
			if err != nil {
				log.Warningf("Namespace JSON returned origin %s with invalid unauthenticated URL %s",
					origin.Resource, origin.Endpoint)
			}
			originAd.URL = *originURL

			originAdMap[originAd] = append(originAdMap[originAd], nsAd)
		}

		for _, cache := range ns.Caches {
			cacheAd := ServerAd{}
			cacheAd.Type = CacheType
			cacheAd.Name = cache.Resource

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

			cacheURL, err := url.Parse(cache.Endpoint)
			if err != nil {
				log.Warningf("Namespace JSON returned cache %s with invalid unauthenticated URL %s",
					cache.Resource, cache.Endpoint)
			}
			cacheAd.URL = *cacheURL

			cacheNS := NamespaceAd{}
			cacheNS.Path = ns.Path
			cacheNS.RequireToken = ns.UseTokenOnRead
			cacheAdMap[cacheAd] = append(cacheAdMap[cacheAd], cacheNS)

		}
	}

	for originAd, namespacesSlice := range originAdMap {
		RecordAd(originAd, &namespacesSlice)
	}

	for cacheAd, namespacesSlice := range cacheAdMap {
		RecordAd(cacheAd, &namespacesSlice)
	}

	return nil
}

func PeriodicCacheReload() {
	for {
		// The ad cache times out every 15 minutes, so update it every
		// 10. If a key isn't updated, it will survive for 5 minutes
		// and then disappear
		time.Sleep(time.Minute * 10)
		err := AdvertiseOSDF()
		if err != nil {
			log.Warningf("Failed to re-advertise: %s. Will try again later",
				err)
		}
	}
}
