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

	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
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

	Scitokens struct {
		BasePath   []string `json:"base_path"`
		Issuer     string   `json:"issuer"`
		Restricted []string `json:"restricted_path"`
	}

	Namespace struct {
		Caches               []Server             `json:"caches"`
		Origins              []Server             `json:"origins"`
		CredentialGeneration CredentialGeneration `json:"credential_generation"`
		DirlistHost          string               `json:"dirlisthost"`
		Path                 string               `json:"path"`
		ReadHTTPS            bool                 `json:"readhttps"`
		Scitokens            []Scitokens          `json:"scitokens"`
		UseTokenOnRead       bool                 `json:"usetokenonread"`
		WritebackHost        string               `json:"writebackhost"`
	}

	NamespaceJSON struct {
		Caches     []Server    `json:"caches"`
		Namespaces []Namespace `json:"namespaces"`
	}
)

func parseServerAd(server Server, serverType ServerType) ServerAd {
	serverAd := ServerAd{}
	serverAd.Type = serverType
	serverAd.Name = server.Resource

	// url.Parse requires that the scheme be present before the hostname,
	// but endpoints do not have a scheme. As such, we need to add one for the.
	// correct parsing. Luckily, we don't use this anywhere else (it's just to
	// make the url.Parse function behave as expected)
	if !strings.HasPrefix(server.AuthEndpoint, "http") { // just in case there's already an http(s) tacked in front
		server.AuthEndpoint = "https://" + server.AuthEndpoint
	}
	if !strings.HasPrefix(server.Endpoint, "http") { // just in case there's already an http(s) tacked in front
		server.Endpoint = "http://" + server.Endpoint
	}
	serverAuthUrl, err := url.Parse(server.AuthEndpoint)
	if err != nil {
		log.Warningf("Namespace JSON returned server %s with invalid authenticated URL %s",
			server.Resource, server.AuthEndpoint)
	}
	serverAd.AuthURL = *serverAuthUrl

	serverUrl, err := url.Parse(server.Endpoint)
	if err != nil {
		log.Warningf("Namespace JSON returned server %s with invalid unauthenticated URL %s",
			server.Resource, server.Endpoint)
	}
	serverAd.URL = *serverUrl

	// We will leave serverAd.WebURL as empty when fetched from topology

	return serverAd
}

// Populate internal cache with origin/cache ads
func AdvertiseOSDF() error {
	topoNamespaceUrl := param.Federation_TopologyNamespaceUrl.GetString()
	if topoNamespaceUrl == "" {
		return errors.New("Topology namespaces.json configuration option (`Federation.TopologyNamespaceURL`) not set")
	}

	req, err := http.NewRequest("GET", topoNamespaceUrl, nil)
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
		return errors.Wrapf(err, "Failure when parsing JSON response from topology URL %v", topoNamespaceUrl)
	}

	cacheAdMap := make(map[ServerAd][]NamespaceAd)
	originAdMap := make(map[ServerAd][]NamespaceAd)

	for _, ns := range namespaces.Namespaces {
		nsAds := []NamespaceAd{}
		requireToken := ns.UseTokenOnRead
		path := ns.Path
		dirlistHost := ns.DirlistHost

		// A token is required on read, so scitokens will be populated
		if requireToken {
			maxScopeDepth := uint(ns.CredentialGeneration.MaxScopeDepth)
			strategy := StrategyType(ns.CredentialGeneration.Strategy)
			vaultServer := ns.CredentialGeneration.VaultServer

			// Each namespace can have multiple entries into the scitoken
			// and each scitoken entry can have multiple basepaths.
			// Each basepath/issuer combo must be a seperate NamespaceAd

			for _, scitok := range ns.Scitokens {
				issuerURL, err := url.Parse(scitok.Issuer)
				if err != nil {
					log.Warningf("Invalid URL %v when parsing topology response: %v\n", ns.CredentialGeneration.Issuer, err)
					continue
				}
				issuer := *issuerURL
				for _, bp := range scitok.BasePath {
					nAd := NamespaceAd{
						RequireToken:   requireToken,
						Path:           bp,
						Issuer:         issuer,
						MaxScopeDepth:  maxScopeDepth,
						Strategy:       strategy,
						BasePath:       bp,
						VaultServer:    vaultServer,
						DirlistHost:    dirlistHost,
						RestrictedPath: scitok.Restricted,
					}
					nsAds = append(nsAds, nAd)
				}
			}
		} else {
			nAd := NamespaceAd{
				RequireToken: false,
				Path:         path,
			}
			nsAds = append(nsAds, nAd)
		}

		// We assume each namespace may have multiple origins, although most likely will not
		// Some namespaces show up in topology but don't have an origin (perhaps because
		// they're listed as inactive by topology). These namespaces will all be mapped to the
		// same useless origin ad, resulting in a 404 for queries to those namespaces
		for _, origin := range ns.Origins {
			originAd := parseServerAd(origin, OriginType)
			originAdMap[originAd] = append(originAdMap[originAd], nsAds...)
		}

		for _, cache := range ns.Caches {
			cacheAd := parseServerAd(cache, CacheType)
			cacheAdMap[cacheAd] = append(cacheAdMap[cacheAd], nsAds...)
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
