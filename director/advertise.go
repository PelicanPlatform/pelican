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
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
)

// Consolite two ServerAds that share the same ServerAd.URL. For all but the capability fields,
// the existing ServerAds takes precedence. For capability fields, an OR is made between two ads
// to get a union of permissions.
func consolidateDupServerAd(newAd, existingAd server_structs.ServerAd) server_structs.ServerAd {
	consolidatedAd := existingAd

	// Update new serverAd capabilities by taking the OR operation so that it's more permissive
	consolidatedAd.Caps.DirectReads = existingAd.Caps.DirectReads || newAd.Caps.DirectReads
	consolidatedAd.Caps.PublicReads = existingAd.Caps.PublicReads || newAd.Caps.PublicReads
	consolidatedAd.Caps.Reads = existingAd.Caps.Reads || newAd.Caps.Reads
	consolidatedAd.Caps.Writes = existingAd.Caps.Writes || newAd.Caps.Writes
	consolidatedAd.Caps.Listings = existingAd.Caps.Listings || newAd.Caps.Listings

	consolidatedAd.DirectReads = existingAd.DirectReads || newAd.DirectReads
	consolidatedAd.Writes = existingAd.Writes || newAd.Writes
	consolidatedAd.Listings = existingAd.Listings || newAd.Listings

	return consolidatedAd
}

// Takes in server information from topology and handles converting the necessary bits into a new Pelican
// ServerAd.
func parseServerAdFromTopology(server utils.Server, serverType server_structs.ServerType, caps server_structs.Capabilities) server_structs.ServerAd {
	serverAd := server_structs.ServerAd{}
	serverAd.Type = serverType
	serverAd.Name = server.Resource
	serverAd.IOLoad = 0.5 // We don't have the probe for topology server load, so we default to 0.5

	// Explicitly set these to false for caches, because these caps don't really translate in that case
	if serverAd.Type == server_structs.CacheType {
		serverAd.Caps = server_structs.Capabilities{}
		serverAd.Writes = false
		serverAd.Listings = false
		serverAd.DirectReads = false
	} else {
		// Until we consolidate ServerAd capabilities with NamespaceAdV2 capabilities, we'll keep setting the top-level
		// ServerAd capabilities. Eventually we should replace with the actual caps struct.
		serverAd.Writes = caps.Writes
		serverAd.Listings = caps.Listings
		serverAd.DirectReads = caps.DirectReads
		serverAd.Caps = caps
	}

	// Set FromTopology to true, which we use for filtering Pelican vs Topology origins/namespaces that might be competing.
	serverAd.FromTopology = true

	// url.Parse requires that the scheme be present before the hostname,
	// but endpoints do not have a scheme. As such, we need to add one for the.
	// correct parsing. Luckily, we don't use this anywhere else (it's just to
	// make the url.Parse function behave as expected)
	if !strings.HasPrefix(server.Endpoint, "http") { // just in case there's already an http(s) tacked in front
		// Setting the scheme to http (and not https) in order to work with topology public caches and origins
		server.Endpoint = "http://" + server.Endpoint
	}
	serverUrl, err := url.Parse(server.Endpoint)
	if err != nil {
		log.Warningf("Namespace JSON returned server %s with invalid unauthenticated URL %s",
			server.Resource, server.Endpoint)
	}
	if serverUrl != nil {
		serverAd.URL = *serverUrl
	} else {
		serverAd.URL = url.URL{}
	}

	if server.AuthEndpoint != "" {
		if !strings.HasPrefix(server.AuthEndpoint, "http") { // just in case there's already an http(s) tacked in front
			server.AuthEndpoint = "https://" + server.AuthEndpoint
		}
		serverAuthUrl, err := url.Parse(server.AuthEndpoint)
		if err != nil {
			log.Warningf("Namespace JSON returned server %s with invalid authenticated URL %s",
				server.Resource, server.AuthEndpoint)
		}

		if serverAuthUrl != nil {
			serverAd.AuthURL = *serverAuthUrl
		} else {
			serverAd.AuthURL = url.URL{}
		}
	}

	// We will leave serverAd.WebURL as empty when fetched from topology
	return serverAd
}

// Do a subtraction of excludeDowned set from the includeDowned set to find cache servers
// that are in downtime
//
// The excludeDowned is a list of running OSDF topology servers
// The includeDowned is a list of running and downed OSDF topology servers
func findDownedTopologyCache(excludeDowned, includeDowned []utils.Server) (caches []utils.Server) {
	for _, included := range includeDowned {
		found := false
		for _, excluded := range excludeDowned {
			if included == excluded {
				found = true
				break
			}
		}
		if !found {
			caches = append(caches, included)
		}
	}
	return
}

// Update filteredServers based on topology downtime
func updateDowntimeFromTopology(excludedNss, includedNss *utils.TopologyNamespacesJSON) {
	downedCaches := findDownedTopologyCache(excludedNss.Caches, includedNss.Caches)

	filteredServersMutex.Lock()
	defer filteredServersMutex.Unlock()
	// Remove existing filteredSevers that are fetched from the topology first
	for key, val := range filteredServers {
		if val == topoFiltered {
			delete(filteredServers, key)
		}
	}
	for _, dc := range downedCaches {
		if sAd := serverAds.Get(dc.Endpoint); sAd == nil {
			// The downed cache is not in the director yet
			filteredServers[dc.Resource] = topoFiltered
		} else {
			// If we have the cache in the director, use it's name as the key
			filteredServers[sAd.Value().Name] = topoFiltered
		}
	}
	log.Infof("The following servers are put in downtime: %#v", filteredServers)
}

// Populate internal cache with origin/cache ads
func AdvertiseOSDF(ctx context.Context) error {
	namespaces, err := utils.GetTopologyJSON(ctx, false)
	if err != nil {
		return errors.Wrapf(err, "Failed to get topology JSON")
	}

	// Second call to fetch all servers (including servers in downtime)
	includedNss, err := utils.GetTopologyJSON(ctx, true)
	if err != nil {
		return errors.Wrapf(err, "Failed to get topology JSON with server in downtime included (include_downed)")
	}

	updateDowntimeFromTopology(namespaces, includedNss)

	cacheAdMap := make(map[string]*server_structs.Advertisement)  // key is serverAd.URL.String()
	originAdMap := make(map[string]*server_structs.Advertisement) // key is serverAd.URL.String()
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

		listings := false
		if ns.DirlistHost != "" {
			listings = true
		}

		caps := server_structs.Capabilities{
			PublicReads: !ns.UseTokenOnRead,
			Reads:       ns.ReadHTTPS,
			Writes:      write,
			Listings:    listings,
			DirectReads: true, // Topology namespaces should probably always have this turned on
		}
		nsAd := server_structs.NamespaceAdV2{
			Path:         ns.Path,
			PublicRead:   caps.PublicReads,
			Caps:         caps,
			Generation:   []server_structs.TokenGen{tGen},
			Issuer:       tokenIssuers,
			FromTopology: true,
		}

		// We assume each namespace may have multiple origins, although most likely will not
		// Some namespaces show up in topology but don't have an origin (perhaps because
		// they're listed as inactive by topology). These namespaces will all be mapped to the
		// same useless origin ad, resulting in a 404 for queries to those namespaces

		// We further assume that with this legacy code handling, each origin exporting a given namespace
		// will have the same set of capabilities as the namespace itself. Pelican has teased apart origins
		// and namespaces, so this isn't true outside this limited context.
		for _, origin := range ns.Origins {
			originAd := parseServerAdFromTopology(origin, server_structs.OriginType, caps)
			if existingAd, ok := originAdMap[originAd.URL.String()]; ok {
				existingAd.NamespaceAds = append(existingAd.NamespaceAds, nsAd)
				consolidatedAd := consolidateDupServerAd(originAd, existingAd.ServerAd)
				existingAd.ServerAd = consolidatedAd
			} else {
				// New entry
				originAdMap[originAd.URL.String()] = &server_structs.Advertisement{ServerAd: originAd, NamespaceAds: []server_structs.NamespaceAdV2{nsAd}}
			}
		}

		for _, cache := range ns.Caches {
			cacheAd := parseServerAdFromTopology(cache, server_structs.CacheType, server_structs.Capabilities{})
			if existingAd, ok := cacheAdMap[cacheAd.URL.String()]; ok {
				existingAd.NamespaceAds = append(existingAd.NamespaceAds, nsAd)
				consolidatedAd := consolidateDupServerAd(cacheAd, existingAd.ServerAd)
				existingAd.ServerAd = consolidatedAd
			} else {
				// New entry
				cacheAdMap[cacheAd.URL.String()] = &server_structs.Advertisement{ServerAd: cacheAd, NamespaceAds: []server_structs.NamespaceAdV2{nsAd}}
			}
		}
	}

	for _, ad := range originAdMap {
		recordAd(ctx, ad.ServerAd, &ad.NamespaceAds)
	}

	for _, ad := range cacheAdMap {
		recordAd(ctx, ad.ServerAd, &ad.NamespaceAds)
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
			err := AdvertiseOSDF(ctx)
			if err != nil {
				log.Warningf("Failed to re-advertise: %s. Will try again later",
					err)
			}
		case <-ctx.Done():
			return
		}
	}
}
