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
	"sync"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

var (
	onceMetadata  sync.Once
	metadataError error
)

func getMetadata() {
	if param.OIDC_DeviceAuthEndpoint.GetString() != "" &&
		param.OIDC_TokenEndpoint.GetString() != "" &&
		param.OIDC_UserInfoEndpoint.GetString() != "" {
		return
	}

	issuerUrl := param.OIDC_Issuer.GetString()
	if issuerUrl == "" {
		metadataError = errors.New("OIDC.Issuer is not set; unable to do metadata discovery")
		return
	}
	metadata, err := GetIssuerMetadata(issuerUrl)
	if err != nil {
		metadataError = err
		return
	}

	if param.OIDC_DeviceAuthEndpoint.GetString() == "" {
		viper.Set("OIDC.DeviceAuthEndpoint", metadata.DeviceAuthURL)
	}
	if param.OIDC_TokenEndpoint.GetString() != "" {
		viper.Set("OIDC.TokenEndpoint", metadata.TokenURL)
	}
	if param.OIDC_UserInfoEndpoint.GetString() != "" {
		viper.Set("OIDC.UserInfoEndpoint", metadata.UserInfoURL)
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
	return getMetadataValue(param.OIDC_DeviceAuthEndpoint.GetString)
}

func GetOIDCUserInfoEndpoint() (result string, err error) {
	return getMetadataValue(param.OIDC_UserInfoEndpoint.GetString)
}
