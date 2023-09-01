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

package oauth2

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

type OauthIssuer struct {
	Issuer          string   `json:"issuer"`
	AuthURL         string   `json:"authorization_endpoint"`
	DeviceAuthURL   string   `json:"device_authorization_endpoint"`
	TokenURL        string   `json:"token_endpoint"`
	RegistrationURL string   `json:"registration_endpoint"`
	GrantTypes      []string `json:"grant_types_supported"`
}

func GetIssuerMetadata(issuer_url string) (*OauthIssuer, error) {
	wellKnownUrl := strings.TrimSuffix(issuer_url, "/") + "/.well-known/openid-configuration"

	resp, err := http.Get(wellKnownUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, errors.New("Failed to retrieve issuer metadata")
	}

	issuer := &OauthIssuer{}
	err = json.Unmarshal(body, issuer)
	return issuer, err
}
