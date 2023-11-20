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

package config

import (
	"os"
	"strings"
	"sync"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
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
	log.Debugln("Getting OIDC issuer metadata via URL", issuerUrl)
	metadata, err := GetIssuerMetadata(issuerUrl)
	if err != nil {
		metadataError = err
		return
	}
	oidcMetadata = metadata

	if param.OIDC_DeviceAuthEndpoint.GetString() == "" {
		viper.Set("OIDC.DeviceAuthEndpoint", metadata.DeviceAuthURL)
	}
	if param.OIDC_TokenEndpoint.GetString() == "" {
		viper.Set("OIDC.TokenEndpoint", metadata.TokenURL)
	}
	if param.OIDC_UserInfoEndpoint.GetString() == "" {
		viper.Set("OIDC.UserInfoEndpoint", metadata.UserInfoURL)
	}
	if param.OIDC_AuthorizationEndpoint.GetString() == "" {
		viper.Set("OIDC.AuthorizationEndpoint", metadata.AuthURL)
	}
}

func getMetadataValue(metadataFunc func() string) (result string, err error) {
	onceMetadata.Do(getMetadata)
	result = metadataFunc()
	// Assume if the OIDC value is set then that was from the config file
	// so we skip any errors
	if result == "" {
		err = metadataError
	}
	return
}

func GetOIDCDeviceAuthEndpoint() (result string, err error) {
	return getMetadataValue(param.OIDC_DeviceAuthEndpoint.GetString)
}

func GetOIDCTokenEndpoint() (result string, err error) {
	return getMetadataValue(param.OIDC_TokenEndpoint.GetString)
}

func GetOIDCUserInfoEndpoint() (result string, err error) {
	return getMetadataValue(param.OIDC_UserInfoEndpoint.GetString)
}

func GetOIDCAuthorizationEndpoint() (result string, err error) {
	return getMetadataValue(param.OIDC_AuthorizationEndpoint.GetString)
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
	if clientFile != "" {
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
