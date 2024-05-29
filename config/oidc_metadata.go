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

package config

import (
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/param"
)

type OIDCProvider string

const (
	CILogon         OIDCProvider = "CILogon"
	Globus          OIDCProvider = "Globus"
	UnknownProvider OIDCProvider = "Unknown"
)

var (
	onceMetadata  sync.Once
	metadataError error
	oidcMetadata  *OauthIssuer

	onceClient   sync.Once
	clientError  error
	clientID     string
	clientSecret string
)

func getMetadata() {

	issuerUrl := param.OIDC_Issuer.GetString()
	if issuerUrl == "" {
		metadataError = errors.New("OIDC.Issuer is not set; unable to do metadata discovery")
		return
	}
	// url.Parse doesn't like urls without protocol, so we want to fix this
	if !strings.HasPrefix(issuerUrl, "https://") && !strings.HasPrefix(issuerUrl, "http://") {
		issuerUrl = "https://" + issuerUrl
	}
	if _, err := url.Parse(issuerUrl); err != nil {
		metadataError = errors.Wrap(err, "OIDC.Issuer is not a valid URL; unable to do metadata discovery")
		return
	}
	log.Debugln("Getting OIDC issuer metadata via URL", issuerUrl)
	metadata, err := GetIssuerMetadata(issuerUrl)
	if err != nil {
		log.Warningf("Failed to get OIDC issuer metadata with error %v. Fall back to CILogon endpoints for OIDC authentication if individual OIDC endpoints are not set.", err)
		metadataError = err
		return
	}
	oidcMetadata = metadata

	// We don't check if the endpoint(s) are set. Just overwrite to ensure
	// our default values are not being used if the issuer is not CILogon
	viper.Set("OIDC.DeviceAuthEndpoint", metadata.DeviceAuthURL)
	viper.Set("OIDC.TokenEndpoint", metadata.TokenURL)
	viper.Set("OIDC.UserInfoEndpoint", metadata.UserInfoURL)
	viper.Set("OIDC.AuthorizationEndpoint", metadata.AuthURL)
}

func getMetadataValue(stringParam param.StringParam) (result string, err error) {
	onceMetadata.Do(getMetadata)
	result = stringParam.GetString()
	// Assume if the OIDC value is set then that was from the config file
	// so we skip any errors
	if result == "" {
		// A hacky way to allow Globus as an auth server
		if param.OIDC_Issuer.IsSet() {
			issuerUrl, _ := url.Parse(param.OIDC_Issuer.GetString())
			if issuerUrl != nil && issuerUrl.Hostname() == "auth.globus.org" && stringParam.GetName() == param.OIDC_DeviceAuthEndpoint.GetName() {
				log.Warning("You are using Globus as the auth privider. Although it does not support OAuth device flow used by Pelican registry, you may use it for other Pelican servers. OIDC.DeviceAuthEndpoint is set to https://auth.globus.org/")
				result = "https://auth.globus.org/"
				return
			}
		}

		if metadataError == nil {
			err = errors.Errorf("Required OIDC endpoint %s is not set and OIDC discovery at %s doesn't have the endpoint in the metadata. Your authentication server may not support OAuth2 authorization flow that is required by Pelican.",
				stringParam.GetName(),
				param.OIDC_Issuer.GetString(),
			)
		} else {
			err = errors.Wrapf(metadataError,
				"Required OIDC endpoint %s is not set and OIDC discovery failed to request metadata from OIDC.Issuer",
				stringParam.GetName(),
			)
		}
	}
	return
}

// Get from the config parameters the OIDC provider
func GetOIDCProdiver() (pvd OIDCProvider, err error) {
	authURLStr := param.OIDC_AuthorizationEndpoint.GetString()
	if authURLStr == "" {
		authURLStr = param.OIDC_Issuer.GetString()
		if authURLStr == "" {
			err = errors.New("can't determine OIDC provider: nothing set for config parameter OIDC.IssuerUrl or OIDC.AuthorizationEndpoint")
			return
		}
	}
	// url.Parse doesn't like urls without protocol, so we want to fix this
	if !strings.HasPrefix(authURLStr, "https://") && !strings.HasPrefix(authURLStr, "http://") {
		authURLStr = "https://" + authURLStr
	}
	authURL, err := url.Parse(authURLStr)
	if err != nil {
		err = errors.Wrap(err, "can't determine OIDC provider: failed to parse OIDC.AuthorizationEndpoint")
		return
	}

	// We get the provider based on the hostname of the authorization endpoint
	if authURL.Hostname() == "auth.globus.org" {
		pvd = Globus
	} else if authURL.Hostname() == "cilogon.org" {
		pvd = CILogon
	} else {
		pvd = UnknownProvider
	}
	return
}

func GetOIDCDeviceAuthEndpoint() (result string, err error) {
	return getMetadataValue(param.OIDC_DeviceAuthEndpoint)
}

func GetOIDCTokenEndpoint() (result string, err error) {
	return getMetadataValue(param.OIDC_TokenEndpoint)
}

func GetOIDCUserInfoEndpoint() (result string, err error) {
	return getMetadataValue(param.OIDC_UserInfoEndpoint)
}

func GetOIDCAuthorizationEndpoint() (result string, err error) {
	return getMetadataValue(param.OIDC_AuthorizationEndpoint)
}

func GetOIDCSupportedScopes() (results []string, err error) {
	onceMetadata.Do(getMetadata)
	err = metadataError
	if err != nil {
		return
	}
	results = make([]string, len(oidcMetadata.ScopesSupported))
	copy(results, oidcMetadata.ScopesSupported)
	return
}

func getClientID() {
	if envID := viper.GetString("OIDCCLIENTID"); envID != "" {
		clientID = envID
		return
	}

	if result := param.OIDC_ClientID.GetString(); result != "" {
		clientID = result
		return
	}

	clientFile := param.OIDC_ClientIDFile.GetString()
	if clientFile == "" {
		clientError = errors.New("ClientID is not available; set one of OIDC.ClientID, OIDC.ClientIDFile, or the environment variable PELICAN_OIDCCLIENTID")
		return
	}
	contents, err := os.ReadFile(clientFile)
	if err != nil {
		clientError = errors.Wrapf(err, "Failed reading provided OIDC.ClientIDFile %s", clientFile)
		return
	}
	clientID = strings.TrimSpace(string(contents))
}

func getClientSecret() {
	if envSecret := viper.GetString("OIDCCLIENTSECRET"); envSecret != "" {
		clientSecret = envSecret
		return
	}

	clientFile := param.OIDC_ClientSecretFile.GetString()
	if clientFile == "" {
		clientError = errors.New("An OIDC Client Secret file must be specified in the config " +
			"(OIDC.ClientSecretFile), or the secret must be provided via the environment " +
			"variable PELICAN_OIDCCLIENTSECRET")
		return
	}
	contents, err := os.ReadFile(clientFile)
	if err != nil {
		clientError = errors.Wrapf(err, "Failed reading provided OIDC.ClientSecretFile %s",
			clientFile)
		return
	}
	clientSecret = strings.TrimSpace(string(contents))
}

func getClient() {
	getClientID()
	if clientError == nil {
		getClientSecret()
	}
}

func GetOIDCClientID() (result string, err error) {
	onceClient.Do(getClient)
	err = clientError
	result = clientID
	return
}

func GetOIDCClientSecret() (result string, err error) {
	onceClient.Do(getClient)
	err = clientError
	result = clientSecret
	return
}
