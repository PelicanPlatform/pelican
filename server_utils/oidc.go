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
	"strings"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

const (
	jwksPath string = "/.well-known/issuer.jwks"
)

// The director will prefer the federation's public endpoint instead of its own
// public endpoint.  In almost all cases, these will be the same thing; this is
// just providing some flexibility.
func getDirectorBaseUrl(ctx *gin.Context) (directorUrl *url.URL) {
	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		log.Error("Bad server configuration: Federation discovery could not resolve:", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Bad server configuration: Federation discovery could not resolve",
			})
		return
	}
	directorUrlStr := fedInfo.DirectorEndpoint
	if directorUrlStr == "" {
		log.Error("Bad server configuration: Federation.DirectorUrl is not set")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Bad server configuration: director URL is not set",
		})
		return
	}
	directorUrl, err = url.Parse(directorUrlStr)
	if err != nil {
		log.Error("Bad server configuration: invalid URL from Federation.DirectorUrl: ", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Bad server configuration: director URL is not valid",
		})
		return
	}
	if directorUrl.Scheme != "https" {
		directorUrl.Scheme = "https"
	}
	if directorUrl.Port() == "443" {
		directorUrl.Host = strings.TrimSuffix(directorUrl.Host, ":443")
	}

	return
}

func createOidcConfigExporter(isDirector bool) func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		var issuerStr string
		if isDirector {
			if issuerUrl := getDirectorBaseUrl(ctx); issuerUrl == nil {
				return
			} else {
				issuerStr = issuerUrl.String()
			}
		} else {
			issuerStr = param.Server_ExternalWebUrl.GetString()
		}
		jwskUrl, err := url.JoinPath(issuerStr, jwksPath)
		if err != nil {
			log.Errorf("Bad server configuration: failed to construct jwks URL from issuer URL %s and JWKS path %s: %s", issuerStr, jwksPath, err)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Bad server configuration: cannot generate JWKs URL",
			})
			return
		}

		cfg := server_structs.OpenIdDiscoveryResponse{
			Issuer:  issuerStr,
			JwksUri: jwskUrl,
		}
		// If we have the built-in issuer enabled, fill in the URLs for OA4MP
		if param.Origin_EnableIssuer.GetBool() {
			serviceUri := issuerStr + "/api/v1.0/issuer"
			cfg.TokenEndpoint = serviceUri + "/token"
			cfg.UserInfoEndpoint = serviceUri + "/userinfo"
			cfg.RevocationEndpoint = serviceUri + "/revoke"
			cfg.GrantTypesSupported = []string{"refresh_token", "urn:ietf:params:oauth:grant-type:device_code", "authorization_code"}
			cfg.ScopesSupported = []string{"openid", "offline_access", "wlcg", "storage.read:/",
				"storage.modify:/", "storage.create:/"}
			cfg.TokenAuthMethods = []string{"client_secret_basic", "client_secret_post"}
			cfg.RegistrationEndpoint = serviceUri + "/oidc-cm"
			cfg.DeviceEndpoint = serviceUri + "/device_authorization"
		}

		ctx.Header("Content-Disposition", "attachment; filename=pelican-oidc-configuration.json")

		ctx.JSON(http.StatusOK, cfg)
	}
}

func exportIssuerJWKS(ctx *gin.Context) {
	key, err := config.GetIssuerPublicJWKS()
	if err != nil {
		log.Errorf("Failed to load server's public key: %v", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to load server's public key",
		})
	} else {
		jsonData, err := json.MarshalIndent(key, "", "  ")
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Failed to marshal server's public key",
			})
			return
		}
		// Append a new line to the JSON data
		jsonData = append(jsonData, '\n')
		ctx.Header("Content-Disposition", "attachment; filename=public-signing-key.jwks")
		ctx.Data(200, "application/json", jsonData)
	}
}

func RegisterOIDCAPI(engine *gin.RouterGroup, isDirector bool) {
	group := engine.Group("/.well-known")
	{
		group.GET("/openid-configuration", createOidcConfigExporter(isDirector))
		group.GET("/issuer.jwks", exportIssuerJWKS)
	}
}
