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

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/director"
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

func (server *OriginServer) CreateAdvertisement(name string, originUrl string, originWebUrl string) (director.ServerAdvertise, error) {
	ad := director.ServerAdvertise{}

	// Here we instantiate the namespaceAd slice, but we still need to define the namespace
	issuerUrl := url.URL{}
	issuerUrl.Scheme = "https"
	issuerUrl.Host = fmt.Sprintf("%v:%v", param.Server_Hostname.GetString(), param.Xrootd_Port.GetInt())

	if issuerUrl.String() == "" {
		return ad, errors.New("No IssuerUrl is set")
	}

	prefix := param.Origin_NamespacePrefix.GetString()

	writeEnabled := param.Origin_WriteEnabled.GetBool()
	// TODO: Need to figure out where to get some of these values
	// 		 so that they aren't hardcoded...
	nsAd := director.NamespaceAd{
		RequireToken:  true,
		Path:          prefix,
		Issuer:        issuerUrl,
		MaxScopeDepth: 3,
		Strategy:      "OAuth2",
		BasePath:      prefix,
	}
	ad = director.ServerAdvertise{
		Name:         name,
		URL:          originUrl,
		WebURL:       originWebUrl,
		Namespaces:   []director.NamespaceAd{nsAd},
		WriteEnabled: writeEnabled,
	}

	return ad, nil
}

// Return a list of paths where the origin's issuer is authoritative.
//
// Used to calculate the base_paths in the scitokens.cfg, for eaxmple
func (server *OriginServer) GetAuthorizedPrefixes() []string {
	// For now, just a single path.  In the future, we will allow
	// multiple.
	return []string{param.Origin_NamespacePrefix.GetString()}
}
