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
	"net/url"
	"os"
	"strings"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

// ServerOIDCClient loads the OIDC client configuration for
// the pelican server
func ServerOIDCClient() (result Config, err error) {
	// Load OIDC.ClientID
	OIDCClientIDFile := param.OIDC_ClientIDFile.GetString()
	OIDCClientIDFromEnv := viper.GetString("OIDCCLIENTID")
	if OIDCClientIDFromEnv != "" {
		result.ClientID = OIDCClientIDFromEnv
	} else if OIDCClientIDFile != "" {
		var contents []byte
		contents, err = os.ReadFile(OIDCClientIDFile)
		if err != nil {
			err = errors.Wrapf(err, "Failed reading provided OIDC.ClientIDFile %s", OIDCClientIDFile)
			return
		}
		result.ClientID = strings.TrimSpace(string(contents))
	} else {
		err = errors.New("An OIDC Client Identity file must be specified in the config (OIDC.ClientIDFile)," +
			" or the identity must be provided via the environment variable PELICAN_OIDCCLIENTID")
		return
	}

	// load OIDC.ClientSecret
	OIDCClientSecretFile := param.OIDC_ClientSecretFile.GetString()
	OIDCClientSecretFromEnv := viper.GetString("OIDCCLIENTSECRET")
	if OIDCClientSecretFromEnv != "" {
		result.ClientSecret = OIDCClientSecretFromEnv
	} else if OIDCClientSecretFile != "" {
		var contents []byte
		contents, err = os.ReadFile(OIDCClientSecretFile)
		if err != nil {
			err = errors.Wrapf(err, "Failed reading provided OIDC.ClientSecretFile %s", OIDCClientSecretFile)
			return
		}
		result.ClientSecret = strings.TrimSpace(string(contents))
	} else {
		err = errors.New("An OIDC Client Secret file must be specified in the config (OIDC.ClientSecretFile)," +
			" or the secret must be provided via the environment variable PELICAN_OIDCCLIENTSECRET")
		return
	}

	// Load OIDC.DeviceAuthEndpoint
	deviceAuthEndpoint := param.OIDC_DeviceAuthEndpoint.GetString()
	if deviceAuthEndpoint == "" {
		err = errors.New("Nothing set for config parameter OIDC.DeviceAuthEndpoint")
		return
	}
	deviceAuthEndpointURL, err := url.Parse(deviceAuthEndpoint)
	if err != nil {
		err = errors.New("Failed to parse URL for parameter OIDC.DeviceAuthEndpoint")
		return
	}
	result.Endpoint.DeviceAuthURL = deviceAuthEndpointURL.String()

	// Load OIDC.TokenEndpoint
	tokenEndpoint := param.OIDC_TokenEndpoint.GetString()
	if tokenEndpoint == "" {
		err = errors.New("Nothing set for config parameter OIDC.TokenEndpoint")
		return
	}
	tokenAuthEndpointURL, err := url.Parse(tokenEndpoint)
	if err != nil {
		err = errors.New("Failed to parse URL for parameter OIDC.TokenEndpoint")
		return
	}
	result.Endpoint.TokenURL = tokenAuthEndpointURL.String()

	// Load OIDC.UserInfoEndpoint
	userInfoEndpoint := param.OIDC_UserInfoEndpoint.GetString()
	if userInfoEndpoint == "" {
		err = errors.New("Nothing set for config parameter OIDC.UserInfoEndpoint")
		return
	}
	userInfoEndpointURL, err := url.Parse(userInfoEndpoint)
	if err != nil {
		err = errors.New("Failed to parse URL for parameter OIDC.UserInfoEndpoint")
		return
	}
	result.Endpoint.UserInfoURL = userInfoEndpointURL.String()

	// Set the scope
	result.Scopes = []string{"openid", "profile", "email", "org.cilogon.userinfo"}

	return
}
