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

package server_utils

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestGetNSIssuerURL(t *testing.T) {
	viper.Reset()
	viper.Set("ConfigDir", t.TempDir())
	config.InitConfig()
	require.NoError(t, config.InitClient())

	viper.Set("Federation.RegistryUrl", "https://registry.com:8446")
	url, err := GetNSIssuerURL("/test-prefix")
	assert.Equal(t, nil, err)
	assert.Equal(t, "https://registry.com:8446/api/v1.0/registry/test-prefix", url)
	viper.Reset()
}

func TestGetJWKSURLFromIssuerURL(t *testing.T) {
	viper.Reset()
	viper.Set("ConfigDir", t.TempDir())
	config.InitConfig()
	require.NoError(t, config.InitClient())

	registry := test_utils.RegistryMockup(t, "/test-prefix")
	defer registry.Close()
	viper.Set("Federation.RegistryUrl", registry.URL)
	expectedIssuerUrl := registry.URL + "/api/v1.0/registry/test-prefix"
	url, err := GetNSIssuerURL("/test-prefix")
	assert.Equal(t, nil, err)
	assert.Equal(t, expectedIssuerUrl, url)

	keyLoc, err := GetJWKSURLFromIssuerURL(url)
	assert.Equal(t, nil, err)
	assert.Equal(t, "https://registry.com:8446/api/v1.0/registry/test-prefix/.well-known/issuer.jwks", keyLoc)
}
