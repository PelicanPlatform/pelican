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

	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pkg/errors"
)

func CreateOriginAdvertisement(name string, originUrl string, originWebUrl string, server server_utils.XRootDServer) (director.OriginAdvertise, error) {
	ad := director.OriginAdvertise{}

	// Here we instantiate the namespaceAd slice, but we still need to define the namespace
	issuerUrl := url.URL{}
	issuerUrl.Scheme = "https"
	issuerUrl.Host = fmt.Sprintf("%v:%v", param.Server_Hostname.GetString(), param.Xrootd_Port.GetInt())

	if issuerUrl.String() == "" {
		return ad, errors.New("No IssuerUrl is set")
	}

	prefix := param.Origin_NamespacePrefix.GetString()

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
	ad = director.OriginAdvertise{
		Name:       name,
		URL:        originUrl,
		WebURL:     originWebUrl,
		Namespaces: []director.NamespaceAd{nsAd},
	}

	return ad, nil
}
