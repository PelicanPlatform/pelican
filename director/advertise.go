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
	"net/url"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
)

func parseServerAd(server utils.Server, serverType server_structs.ServerType) server_structs.ServerAd {
	serverAd := server_structs.ServerAd{}
	serverAd.Type = serverType
	serverAd.Name = server.Resource

	serverAd.Writes = param.Origin_EnableWrites.GetBool()
	serverUrl, err := url.Parse(server.Endpoint)
	if err != nil {
		log.Warningf("Namespace JSON returned server %s with invalid unauthenticated URL %s",
			server.Resource, server.Endpoint)
	}
	// Setting the scheme to http (and not https) in order to work with topology public caches and origins
	serverUrl.Scheme = "http"
	serverAd.URL = *serverUrl

	if server.AuthEndpoint != "" {
		serverAuthUrl, err := url.Parse(server.AuthEndpoint)
		if err != nil {
			log.Warningf("Namespace JSON returned server %s with invalid authenticated URL %s",
				server.Resource, server.AuthEndpoint)
		}

		serverAuthUrl.Scheme = "https"

		serverAd.AuthURL = *serverAuthUrl
	}

	// We will leave serverAd.WebURL as empty when fetched from topology

	return serverAd
}

// Populate internal cache with origin/cache ads
func AdvertiseOSDF() error {
	namespaces, err := utils.GetTopologyJSON()
	if err != nil {
		return errors.Wrapf(err, "Failed to get topology JSON")
	}

	cacheAdMap := make(map[server_structs.ServerAd][]server_structs.NamespaceAdV2)
	originAdMap := make(map[server_structs.ServerAd][]server_structs.NamespaceAdV2)
	tGen := server_structs.TokenGen{}
	for _, ns := range namespaces.Namespaces {
		requireToken := ns.UseTokenOnRead

		tokenIssuers := []server_structs.TokenIssuer{}
		// A token is required on read, so scitokens will be populated
		if requireToken {
			credUrl, err := url.Parse(ns.CredentialGeneration.Issuer)
			if err != nil {
				log.Warningf("Invalid URL %v when parsing topology response %v\n", ns.CredentialGeneration.Issuer, err)
				continue
			}

			credIssuer := *credUrl
			tGen.Strategy = server_structs.StrategyType(ns.CredentialGeneration.Strategy)
			tGen.VaultServer = ns.CredentialGeneration.VaultServer
			tGen.MaxScopeDepth = uint(ns.CredentialGeneration.MaxScopeDepth)
			tGen.CredentialIssuer = credIssuer

			// Each namespace can have multiple entries into the scitoken
			// and each scitoken entry can have multiple basepaths.
			for _, scitok := range ns.Scitokens {
				issuerURL, err := url.Parse(scitok.Issuer)
				if err != nil {
					log.Warningf("Invalid URL %v when parsing topology response: %v\n", scitok.Issuer, err)
					continue
				}
				issuer := *issuerURL
				tIssuer := server_structs.TokenIssuer{
					BasePaths:       scitok.BasePath,
					RestrictedPaths: scitok.Restricted,
					IssuerUrl:       issuer,
				}
				tokenIssuers = append(tokenIssuers, tIssuer)
			}

		}

		var write bool
		if ns.WritebackHost != "" {
			write = true
		} else {
			write = false
		}

		caps := server_structs.Capabilities{
			PublicReads: !ns.UseTokenOnRead,
			Reads:       ns.ReadHTTPS,
			Writes:      write,
		}
		nsAd := server_structs.NamespaceAdV2{
			Path:       ns.Path,
			PublicRead: !ns.UseTokenOnRead,
			Caps:       caps,
			Generation: []server_structs.TokenGen{tGen},
			Issuer:     tokenIssuers,
		}

		// We assume each namespace may have multiple origins, although most likely will not
		// Some namespaces show up in topology but don't have an origin (perhaps because
		// they're listed as inactive by topology). These namespaces will all be mapped to the
		// same useless origin ad, resulting in a 404 for queries to those namespaces
		for _, origin := range ns.Origins {
			originAd := parseServerAd(origin, server_structs.OriginType)
			originAdMap[originAd] = append(originAdMap[originAd], nsAd)
		}

		for _, cache := range ns.Caches {
			cacheAd := parseServerAd(cache, server_structs.CacheType)
			cacheAdMap[cacheAd] = append(cacheAdMap[cacheAd], nsAd)
		}
	}

	for originAd, namespacesSlice := range originAdMap {
		recordAd(originAd, &namespacesSlice)
	}

	for cacheAd, namespacesSlice := range cacheAdMap {
		recordAd(cacheAd, &namespacesSlice)
	}

	return nil
}

func PeriodicCacheReload(ctx context.Context) {
	ticker := time.NewTicker(param.Federation_TopologyReloadInterval.GetDuration())
	for {
		select {
		case <-ticker.C:
			// The ad cache times out every 15 minutes, so update it every
			// 10. If a key isn't updated, it will survive for 5 minutes
			// and then disappear
			err := AdvertiseOSDF()
			if err != nil {
				log.Warningf("Failed to re-advertise: %s. Will try again later",
					err)
			}
		case <-ctx.Done():
			return
		}
	}
}
