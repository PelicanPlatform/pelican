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
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

func TestGetOIDCProvider(t *testing.T) {
	t.Cleanup(func() {
		viper.Reset()
	})
	t.Run("empty-endpoints-gives-error", func(t *testing.T) {
		viper.Reset()
		get, err := GetOIDCProdiver()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nothing set for config parameter OIDC.IssuerUrl or OIDC.AuthorizationEndpoint")
		assert.Empty(t, get)
	})

	t.Run("auth-endpoint-gives-correct-result", func(t *testing.T) {
		viper.Reset()
		viper.Set(param.OIDC_AuthorizationEndpoint.GetName(), "https://example.com/authorization")
		get, err := GetOIDCProdiver()
		require.NoError(t, err)
		assert.Equal(t, UnknownProvider, get)

		// CILogon
		viper.Set(param.OIDC_AuthorizationEndpoint.GetName(), "https://cilogon.org/api/v1.0/authorization")
		get, err = GetOIDCProdiver()
		require.NoError(t, err)
		assert.Equal(t, CILogon, get)

		// Globus
		viper.Set(param.OIDC_AuthorizationEndpoint.GetName(), "https://auth.globus.org/api/v1.0/authorization")
		get, err = GetOIDCProdiver()
		require.NoError(t, err)
		assert.Equal(t, Globus, get)
	})

	t.Run("issuer-endpoint-gives-correct-result", func(t *testing.T) {
		viper.Reset()
		viper.Set(param.OIDC_Issuer.GetName(), "https://example.com")
		get, err := GetOIDCProdiver()
		require.NoError(t, err)
		assert.Equal(t, UnknownProvider, get)

		// CILogon
		viper.Set(param.OIDC_AuthorizationEndpoint.GetName(), "https://cilogon.org")
		get, err = GetOIDCProdiver()
		require.NoError(t, err)
		assert.Equal(t, CILogon, get)

		// CILogon no protocol
		viper.Set(param.OIDC_AuthorizationEndpoint.GetName(), "cilogon.org")
		get, err = GetOIDCProdiver()
		require.NoError(t, err)
		assert.Equal(t, CILogon, get)

		// Globus no protocol
		viper.Set(param.OIDC_AuthorizationEndpoint.GetName(), "auth.globus.org")
		get, err = GetOIDCProdiver()
		require.NoError(t, err)
		assert.Equal(t, Globus, get)
	})
}
