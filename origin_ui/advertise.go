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

package origin_ui

import (
	"fmt"
	"net/url"

	"github.com/pelicanplatform/pelican/common"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pkg/errors"
)

type (
	OriginServer struct {
		server_utils.NamespaceHolder
	}
)

func (server *OriginServer) GetServerType() config.ServerType {
	return config.OriginType
}

func (server *OriginServer) CreateAdvertisement(name string, originUrlStr string, originWebUrl string) (common.OriginAdvertiseV2, error) {
	ad := common.OriginAdvertiseV2{}

	// Here we instantiate the namespaceAd slice, but we still need to define the namespace
	issuerUrl := url.URL{}
	issuerUrl.Scheme = "https"
	issuerUrl.Host = fmt.Sprintf("%v:%v", param.Server_Hostname.GetString(), param.Xrootd_Port.GetInt())

	if issuerUrl.String() == "" {
		return ad, errors.New("No IssuerUrl is set")
	}

	prefix := param.Origin_NamespacePrefix.GetString()

	originUrlURL, err := url.Parse(originUrlStr)
	if err != nil {
		return ad, errors.New("Invalid Origin Url")
	}
	// TODO: Need to figure out where to get some of these values
	// 		 so that they aren't hardcoded...

	nsAd := common.NamespaceAdV2{
		PublicRead: param.Origin_EnablePublicReads.GetBool(),
		Caps: common.Capabilities{
			PublicRead: param.Origin_EnablePublicReads.GetBool(),
			Read:       true,
			Write:      param.Origin_EnableWrite.GetBool(),
		},
		Path: prefix,
		Generation: []common.TokenGen{{
			Strategy:         common.StrategyType("OAuth2"),
			MaxScopeDepth:    3,
			CredentialIssuer: *originUrlURL,
		}},
		Issuer: []common.TokenIssuer{{
			BasePaths: []string{prefix},
			IssuerUrl: issuerUrl,
		}},
	}
	ad = common.OriginAdvertiseV2{
		Name:       name,
		DataURL:    originUrlStr,
		WebURL:     originWebUrl,
		Namespaces: []common.NamespaceAdV2{nsAd},
		Caps: common.Capabilities{
			PublicRead:   param.Origin_EnablePublicReads.GetBool(),
			Read:         true,
			Write:        param.Origin_EnableWrite.GetBool(),
			FallBackRead: param.Origin_EnableFallbackRead.GetBool(),
		},
		Issuer: []common.TokenIssuer{{
			BasePaths: []string{prefix},
			IssuerUrl: issuerUrl,
		}},
	}

	return ad, nil
}

// Return a list of paths where the origin's issuer is authoritative.
//
// Used to calculate the base_paths in the scitokens.cfg, for eaxmple
func (server *OriginServer) GetAuthorizedPrefixes() []string {
	// For now, just a single path.  In the future, we will allow
	// multiple.
	if param.Origin_EnablePublicReads.GetBool() {
		return []string{}
	}

	return []string{param.Origin_NamespacePrefix.GetString()}
}
