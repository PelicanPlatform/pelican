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
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/utils"
)

func parseServerAd(server utils.Server, serverType ServerType) ServerAd {
	serverAd := ServerAd{}
	serverAd.Type = serverType
	serverAd.Name = server.Resource

	serverAd.WriteEnabled = param.Origin_WriteEnabled.GetBool()
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
	namespaces, err := utils.GetTopologyJSON()
	if err != nil {
		return errors.Wrapf(err, "Failed to get topology JSON")
	}

	cacheAdMap := make(map[ServerAd][]NamespaceAd)
	originAdMap := make(map[ServerAd][]NamespaceAd)
	for _, ns := range namespaces.Namespaces {
		nsAd := NamespaceAd{}
		nsAd.RequireToken = ns.UseTokenOnRead
		nsAd.Path = ns.Path
		nsAd.DirlistHost = ns.DirlistHost
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
			originAd := parseServerAd(origin, OriginType)
			originAdMap[originAd] = append(originAdMap[originAd], nsAd)
		}

		for _, cache := range ns.Caches {
			cacheAd := parseServerAd(cache, CacheType)
			cacheAdMap[cacheAd] = append(cacheAdMap[cacheAd], nsAd)
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
