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
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

func exportOpenIDConfig(c *gin.Context) {
	issuerURL, _ := url.Parse(param.Server_ExternalWebUrl.GetString())
	jwksUri, _ := url.JoinPath(issuerURL.String(), "/.well-known/issuer.jwks")
	jsonData := gin.H{
		"issuer":   issuerURL.String(),
		"jwks_uri": jwksUri,
	}

	c.JSON(http.StatusOK, jsonData)
}

func exportIssuerJWKS(c *gin.Context) {
	keys, _ := config.GetIssuerPublicJWKS()
	buf, _ := json.MarshalIndent(keys, "", " ")

	c.Data(http.StatusOK, "application/json; charset=utf-8", buf)
}

func RegisterOIDCAPI(engine *gin.Engine) {
	group := engine.Group("/.well-known")
	{
		group.GET("/openid-configuration", exportOpenIDConfig)
		group.GET("/issuer.jwks", exportIssuerJWKS)
	}
}
