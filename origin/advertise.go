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

package origin

import (
	"context"
	"fmt"
	"net/url"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/features"
	"github.com/pelicanplatform/pelican/metrics"
	pelican_oauth2 "github.com/pelicanplatform/pelican/oauth2"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
)

type (
	OriginServer struct {
		server_structs.NamespaceHolder
		pids []int
	}
)

func (server *OriginServer) GetServerType() server_structs.ServerType {
	return server_structs.OriginType
}

func (server *OriginServer) GetNamespaceAdsFromDirector() error {
	return nil
}

func (server *OriginServer) SetPids(pids []int) {
	server.pids = make([]int, len(pids))
	copy(server.pids, pids)
}

func (server *OriginServer) GetPids() (pids []int) {
	pids = make([]int, len(server.pids))
	copy(pids, server.pids)
	return
}

// Use what we know about the current origin to determine which "features"
// it requires. This gets put into the origin's advertisement to be used
// during director matchmaking.
func (server *OriginServer) GetRequiredFeatures() []features.Feature {
	var requiredFeatures []features.Feature

	// This feature was introduced in v7.16, and all origins/caches after that
	// should be able to support it.
	if param.Origin_DisableDirectClients.GetBool() {
		requiredFeatures = append(requiredFeatures, features.CacheAuthz)
	}

	return requiredFeatures
}

func (server *OriginServer) CreateAdvertisement(name, id, originUrlStr, originWebUrl string, downtimes []server_structs.Downtime) (*server_structs.OriginAdvertiseV2, error) {
	isGlobusBackend := param.Origin_StorageType.GetString() == string(server_structs.OriginStorageGlobus)
	// Here we instantiate the namespaceAd slice, but we still need to define the namespace
	serverIssuerUrlStr, err := config.GetServerIssuerURL()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get server issuer URL for the origin")
	}

	if serverIssuerUrlStr == "" {
		return nil, errors.Errorf("unable to determine the server's issuer url. Is '%s' set in the configuration?",
			param.Server_IssuerUrl.GetName())
	}

	serverIssuerUrl, err := url.Parse(serverIssuerUrlStr)
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse the server's issuer url")
	}

	var nsAds []server_structs.NamespaceAdV2
	var prefixes []string
	ost, err := server_structs.ParseOriginStorageType(param.Origin_StorageType.GetString())
	if err != nil {
		return nil, err
	}
	originExports, err := server_utils.GetOriginExports()
	if err != nil {
		return nil, err
	}

	for _, export := range originExports {
		if isGlobusBackend {
			// Do not include the export if it's an inactive Globus collection
			if !isExportActivated(export.FederationPrefix) {
				log.Debugf("Origin export %s is skipped in advertisement: inactive Globus collection", export.FederationPrefix)
				continue
			}
		}
		// PublicReads implies reads
		reads := export.Capabilities.PublicReads || export.Capabilities.Reads

		// Set up issuer URLs for the namespace. Note that this uses a single
		// base path (the fed prefix) per issuer per export even if a single issuer
		// at the origin is configured for multiple prefixes. This is because we have
		// no global concept of issuers at the Director and we store this issuer info
		// per namespace. It doesn't currently make much sense to construct the full list
		// of potential base paths in this context.
		issuerUrls := make([]server_structs.TokenIssuer, len(export.IssuerUrls))
		for i, issUrlStr := range export.IssuerUrls {
			issUrl, err := url.Parse(issUrlStr)
			if err != nil {
				return nil, errors.Wrap(err, "unable to parse issuer url")
			}
			issuerUrls[i] = server_structs.TokenIssuer{
				IssuerUrl: *issUrl,
				BasePaths: []string{export.FederationPrefix},
			}
		}

		// Populate the struct for the namespace's "token generation" field
		// TODO: It's not clear what the intended difference/abstraction between the
		// "Generation" and the "Issuer" fields is... We should define these eventually
		var tokGen server_structs.TokenGen
		if len(issuerUrls) > 0 {
			tokGen.Strategy = server_structs.OAuthStrategy
			tokGen.MaxScopeDepth = 3
			tokGen.CredentialIssuer = issuerUrls[0].IssuerUrl
		}

		nsAds = append(nsAds, server_structs.NamespaceAdV2{
			Caps: server_structs.Capabilities{
				PublicReads: export.Capabilities.PublicReads,
				Reads:       reads,
				Writes:      export.Capabilities.Writes,
				Listings:    export.Capabilities.Listings,
				DirectReads: export.Capabilities.DirectReads,
			},
			Path:       export.FederationPrefix,
			Generation: []server_structs.TokenGen{tokGen},
			Issuer:     issuerUrls,
		})
		prefixes = append(prefixes, export.FederationPrefix)
	}

	// Determine whether this origin requires any special features that may place
	// limitations on the other servers (e.g. caches) it can work with.
	requiredFeatures := server.GetRequiredFeatures()
	featureNames := make([]string, len(requiredFeatures))
	for i, feature := range requiredFeatures {
		featureNames[i] = feature.GetName()
	}

	// PublicReads implies reads
	reads := param.Origin_EnableReads.GetBool() || param.Origin_EnablePublicReads.GetBool()
	extUrlStr := param.Server_ExternalWebUrl.GetString()
	extUrl, _ := url.Parse(extUrlStr)
	// Only use hostname:port
	registryPrefix := server_structs.GetOriginNs(extUrl.Host)

	// Get the overall health status as reported by the origin.
	status := metrics.GetHealthStatus().OverallStatus

	// For POSIXv2 origins, DataURL (which becomes ServerAd.URL) should have
	// the /api/v1.0/origin/data prefix so the director redirects to the right endpoint.
	// WebURL stays as the base server URL for web browser access.
	dataUrlToAdvertise := originUrlStr
	if ost == server_structs.OriginStoragePosixv2 {
		if parsedUrl, err := url.Parse(originUrlStr); err == nil {
			parsedUrl.Path = "/api/v1.0/origin/data"
			dataUrlToAdvertise = parsedUrl.String()
		}
	}

	ad := server_structs.OriginAdvertiseV2{
		ServerID:       id,
		RegistryPrefix: registryPrefix,
		DataURL:        dataUrlToAdvertise,
		WebURL:         originWebUrl,
		Namespaces:     nsAds,
		Caps: server_structs.Capabilities{
			PublicReads: param.Origin_EnablePublicReads.GetBool(),
			Reads:       reads,
			Writes:      param.Origin_EnableWrites.GetBool(),
			DirectReads: param.Origin_EnableDirectReads.GetBool(),
			Listings:    param.Origin_EnableListings.GetBool(),
		},
		Issuer: []server_structs.TokenIssuer{{
			BasePaths: prefixes,
			// NOTE: I (Justin) am also not sure this is the correct issuer URL to assign here, but it's
			// what we've been using so I'm moving forward with it for now. In particular, as we split
			// data issuers from the server issuer (which is used to verify intra-federation tokens), I don't
			// think concepts like "base paths" really carry forward. Do they make sense outside the context of
			// reads/writes, where they're used to correctly detect token scopes? Ultimately the tokens verified
			// using this issuer will contain scopes like `pelican.advertise` and not `storage.read:/foo`.
			IssuerUrl: *serverIssuerUrl,
		}},
		StorageType:         ost,
		DisableDirectorTest: !param.Origin_DirectorTest.GetBool(),
		RequiredFeatures:    featureNames,
		Status:              status,
		Downtimes:           downtimes,
	}
	ad.Initialize(name)

	if len(prefixes) == 0 {
		if isGlobusBackend {
			activateUrl := param.Server_ExternalWebUrl.GetString() + "/view/origin/globus"
			callbackUrl, err := pelican_oauth2.GetRedirectURL(globusCallbackPath)
			errMsg := fmt.Sprintf("failed to create advertisement: no activated Globus collection. Go to %s to activate your collection", activateUrl)
			if err == nil {
				errMsg += fmt.Sprintf(". Pelican will try %q as the redirect callback URL "+
					"(this must match the redirect URL configured via Globus when setting up the OAuth client)", callbackUrl)
			} else {
				log.Errorf("failed to determine redirect URL for Globus activation: %v", err)
			}
			return nil, errors.New(errMsg)
		}

		return nil, errors.New("failed to create advertisement: no valid export")
	}

	if param.Origin_EnableBroker.GetBool() && len(prefixes) == 1 {
		var brokerUrl *url.URL
		fedInfo, err := config.GetFederation(context.Background())
		if err != nil {
			return nil, err
		}
		brokerUrl, err = url.Parse(fedInfo.BrokerEndpoint)
		if err != nil {
			return nil, errors.Wrap(err, "federation metadata discovery provided an invalid broker endpoint")
		}
		brokerUrl.Path = "/api/v1.0/broker/reverse"
		values := brokerUrl.Query()
		values.Set("origin", param.Server_Hostname.GetString())
		values.Set("prefix", prefixes[0])
		brokerUrl.RawQuery = values.Encode()
		ad.BrokerURL = brokerUrl.String()
	} else if param.Origin_EnableBroker.GetBool() && len(prefixes) > 1 {
		log.Warningf("Multiple federation prefixes are not yet supported with the broker. Skipping broker configuration")
	}

	return &ad, nil
}

// Advertisement token configuration for the origin server. Used to get Origin-specific
// config that would differ from caches.
func (server *OriginServer) GetAdTokCfg(directorUrl string) (adTokCfg server_structs.AdTokCfg, err error) {

	var directorAudience string
	directorAudience, err = token.GetWLCGAudience(directorUrl)
	if err != nil {
		err = errors.Wrap(err, "failed to determine correct token audience for director")
		return
	}

	adTokCfg.Audience = directorAudience
	adTokCfg.Subject = param.Origin_Url.GetString()
	adTokCfg.Issuer = param.Server_IssuerUrl.GetString()

	return
}

func (server *OriginServer) GetFedTokLocation() string {
	return param.Origin_FedTokenLocation.GetString()
}
