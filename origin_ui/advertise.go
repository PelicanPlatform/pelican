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

package origin_ui

import (
	"net/url"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/common"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

type (
	OriginServer struct {
		server_utils.NamespaceHolder
	}
)

func (server *OriginServer) GetServerType() config.ServerType {
	return config.OriginType
}

func (server *OriginServer) GetNamespaceAdsFromDirector() error {
	return nil
}

func (server *OriginServer) CreateAdvertisement(name string, originUrlStr string, originWebUrl string) (*common.OriginAdvertiseV2, error) {
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

	originUrlURL, err := url.Parse(originUrlStr)
	if err != nil {
		err = errors.Wrap(err, "Invalid Origin Url")
		return nil, err
	}

	var nsAds []common.NamespaceAdV2
	var prefixes []string
	originExports, err := common.GetOriginExports()
	if err != nil {
		return nil, err
	}

	for _, export := range *originExports {
		nsAds = append(nsAds, common.NamespaceAdV2{
			PublicRead: export.Capabilities.PublicReads,
			Caps: common.Capabilities{
				PublicReads: export.Capabilities.PublicReads,
				Reads:       true,
				Writes:      export.Capabilities.Writes,
			},
			Path: export.FederationPrefix,
			Generation: []common.TokenGen{{
				Strategy:         common.StrategyType("OAuth2"),
				MaxScopeDepth:    3,
				CredentialIssuer: *originUrlURL,
			}},
			Issuer: []common.TokenIssuer{{
				BasePaths: []string{export.FederationPrefix},
				IssuerUrl: *issuerUrl,
			}},
		})
		prefixes = append(prefixes, export.FederationPrefix)
	}

	ad := common.OriginAdvertiseV2{
		Name:       name,
		DataURL:    originUrlStr,
		WebURL:     originWebUrl,
		Namespaces: nsAds,
		Caps: common.Capabilities{
			PublicReads: param.Origin_EnablePublicReads.GetBool(),
			Reads:       true,
			Writes:      param.Origin_EnableWrites.GetBool(),
			DirectReads: param.Origin_EnableDirectReads.GetBool(),
		},
		Issuer: []common.TokenIssuer{{
			BasePaths: prefixes,
			IssuerUrl: *issuerUrl,
		}},
	}

	if len(prefixes) == 1 {
		if param.Origin_EnableBroker.GetBool() {
			var brokerUrl *url.URL
			brokerUrl, err = url.Parse(param.Federation_BrokerUrl.GetString())
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
	originExports, err := common.GetOriginExports()
	if err != nil {
		return nil, err
	}

	for _, export := range *originExports {
		if !export.Capabilities.PublicReads || export.Capabilities.Writes {
			prefixes = append(prefixes, export.FederationPrefix)
		}
	}

	return prefixes, nil
}
