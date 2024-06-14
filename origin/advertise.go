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
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

type (
	OriginServer struct {
		server_structs.NamespaceHolder
		pids []int
	}
)

func (server *OriginServer) GetServerType() config.ServerType {
	return config.OriginType
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

func (server *OriginServer) CreateAdvertisement(name, originUrlStr, originWebUrl string) (*server_structs.OriginAdvertiseV2, error) {
	isGlobusBackend := param.Origin_StorageType.GetString() == string(server_utils.OriginStorageGlobus)
	// Here we instantiate the namespaceAd slice, but we still need to define the namespace
	issuerUrlStr, err := config.GetServerIssuerURL()
	if err != nil {
		err = errors.Wrap(err, "Unable to get server issuer URL for the origin")
		return nil, err
	}

	if issuerUrlStr == "" {
		err = errors.New("No IssuerUrl is set")
		return nil, err
	}

	issuerUrl, err := url.Parse(issuerUrlStr)
	if err != nil {
		err = errors.Wrap(err, "Unable to parse issuer url")
		return nil, err
	}

	var nsAds []server_structs.NamespaceAdV2
	var prefixes []string
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
		nsAds = append(nsAds, server_structs.NamespaceAdV2{
			PublicRead: export.Capabilities.PublicReads,
			Caps: server_structs.Capabilities{
				PublicReads: export.Capabilities.PublicReads,
				Reads:       reads,
				Writes:      export.Capabilities.Writes,
				Listings:    export.Capabilities.Listings,
				DirectReads: export.Capabilities.DirectReads,
			},
			Path: export.FederationPrefix,
			Generation: []server_structs.TokenGen{{
				Strategy:         server_structs.StrategyType("OAuth2"),
				MaxScopeDepth:    3,
				CredentialIssuer: *issuerUrl,
			}},
			Issuer: []server_structs.TokenIssuer{{
				BasePaths: []string{export.FederationPrefix},
				IssuerUrl: *issuerUrl,
			}},
		})
		prefixes = append(prefixes, export.FederationPrefix)
	}

	// PublicReads implies reads
	reads := param.Origin_EnableReads.GetBool() || param.Origin_EnablePublicReads.GetBool()
	extUrlStr := param.Server_ExternalWebUrl.GetString()
	extUrl, _ := url.Parse(extUrlStr)
	// Only use hostname:port
	registryPrefix := server_structs.GetOriginNs(extUrl.Host)
	ad := server_structs.OriginAdvertiseV2{
		Name:           name,
		RegistryPrefix: registryPrefix,
		DataURL:        originUrlStr,
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
			IssuerUrl: *issuerUrl,
		}},
	}

	if len(prefixes) == 0 {
		if isGlobusBackend {
			activateUrl := param.Server_ExternalWebUrl.GetString() + "/view/origin/globus"
			return nil, fmt.Errorf("failed to create advertisement: no activated Globus collection. Go to %s to activate your collection.", activateUrl)
		} else {
			return nil, errors.New("failed to create advertisement: no valid export")
		}
	} else if len(prefixes) == 1 {
		if param.Origin_EnableBroker.GetBool() {
			var brokerUrl *url.URL
			fedInfo, err := config.GetFederation(context.Background())
			if err != nil {
				return nil, err
			}
			brokerUrl, err = url.Parse(fedInfo.BrokerEndpoint)
			if err != nil {
				err = errors.Wrap(err, "Invalid Broker URL")
				return nil, err
			}
			brokerUrl.Path = "/api/v1.0/broker/reverse"
			values := brokerUrl.Query()
			values.Set("origin", param.Server_Hostname.GetString())
			values.Set("prefix", prefixes[0])
			brokerUrl.RawQuery = values.Encode()
			ad.BrokerURL = brokerUrl.String()
		}
	} else {
		log.Warningf("Multiple prefixes are not yet supported with the broker. Skipping broker configuration")
	}
	return &ad, nil
}

// Return a list of paths where the origin's issuer is authoritative.
//
// Used to calculate the base_paths in the scitokens.cfg, for eaxmple
func (server *OriginServer) GetAuthorizedPrefixes() ([]string, error) {
	var prefixes []string
	originExports, err := server_utils.GetOriginExports()
	if err != nil {
		return nil, err
	}

	for _, export := range originExports {
		if (export.Capabilities.Reads && !export.Capabilities.PublicReads) || export.Capabilities.Writes {
			prefixes = append(prefixes, export.FederationPrefix)
		}
	}

	return prefixes, nil
}
