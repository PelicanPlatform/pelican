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

package oauth2

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

func TestGetRedirectURL(t *testing.T) {
	viper.Reset()
	t.Cleanup(func() {
		viper.Reset()
	})
	t.Run("no-redirect-host-no-cb-path-set", func(t *testing.T) {
		viper.Reset()
		viper.Set(param.Server_ExternalWebUrl.GetName(), "https://localhost:8888")
		get, err := GetRedirectURL("")
		require.NoError(t, err)
		assert.Equal(t, "https://localhost:8888", get)
	})

	t.Run("no-redirect-host-cp-path-set", func(t *testing.T) {
		viper.Reset()
		viper.Set(param.Server_ExternalWebUrl.GetName(), "https://localhost:8888")
		get, err := GetRedirectURL("/new/url")
		require.NoError(t, err)
		assert.Equal(t, "https://localhost:8888/new/url", get)
	})

	t.Run("redirect-host-cp-path-set", func(t *testing.T) {
		viper.Reset()
		viper.Set(param.Server_ExternalWebUrl.GetName(), "https://ea123fsac:8888")
		viper.Set("Server.WebPort", 8888)
		viper.Set(param.OIDC_ClientRedirectHostname.GetName(), "localhost")
		get, err := GetRedirectURL("/new/url")
		require.NoError(t, err)
		assert.Equal(t, "https://localhost:8888/new/url", get)
	})
}
