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

package director

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	log "github.com/sirupsen/logrus"
)

type OpenIdDiscoveryResponse struct {
	Issuer  string `json:"issuer"`
	JwksUri string `json:"jwks_uri"`
}

const (
	oidcDiscoveryPath       string = "/.well-known/openid-configuration"
	federationDiscoveryPath string = "/.well-known/pelican-configuration"
	directorJWKSPath        string = "/.well-known/issuer.jwks"
)

func federationDiscoveryHandler(ctx *gin.Context) {
	directorUrlStr := param.Federation_DirectorUrl.GetString()
	if !param.Federation_DirectorUrl.IsSet() || len(directorUrlStr) == 0 {
		log.Error("Bad server configuration: Federation.DirectorUrl is not set")
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Bad server configuration: director URL is not set"})
		return
	}
	directorUrl, err := url.Parse(directorUrlStr)
	if err != nil {
		log.Error("Bad server configuration: invalid URL from Federation.DirectorUrl: ", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Bad server configuration: director URL is not valid"})
		return
	}
	if directorUrl.Scheme != "https" {
		directorUrl.Scheme = "https"
	}
	if directorUrl.Port() == "443" {
		directorUrl.Host = strings.TrimSuffix(directorUrl.Host, ":443")
	}
	registryUrlStr := param.Federation_RegistryUrl.GetString()
	if !param.Federation_RegistryUrl.IsSet() || len(registryUrlStr) == 0 {
		log.Error("Bad server configuration: Federation.RegistryUrl is not set")
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Bad server configuration: registry URL is not set"})
		return
	}
	registryUrl, err := url.Parse(registryUrlStr)
	if err != nil {
		log.Error("Bad server configuration: invalid URL from Federation.RegistryUrl: ", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Bad server configuration: director URL is not valid"})
		return
	}
	if registryUrl.Scheme != "https" {
		registryUrl.Scheme = "https"
	}
	if registryUrl.Port() == "443" {
		registryUrl.Host = strings.TrimSuffix(registryUrl.Host, ":443")
	}

	brokerUrl := param.Federation_BrokerUrl.GetString()

	jwksUri, err := url.JoinPath(directorUrl.String(), directorJWKSPath)
	if err != nil {
		log.Error("Bad server configuration: fail to generate JwksUri: ", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Bad server configuration: JwksUri is not valid"})
		return
	}

	rs := config.FederationDiscovery{
		DirectorEndpoint:              directorUrl.String(),
		NamespaceRegistrationEndpoint: registryUrl.String(),
		JwksUri:                       jwksUri,
		BrokerEndpoint:                brokerUrl,
	}

	jsonData, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to marshal federation's discovery response"})
		return
	}
	// Append a new line to the JSON data
	jsonData = append(jsonData, '\n')
	ctx.Header("Content-Disposition", "attachment; filename=pelican-configuration.json")
	ctx.Data(http.StatusOK, "application/json", jsonData)
}

// Director metadata discovery endpoint for OpenID style
// token authentication, providing issuer endpoint and director's jwks endpoint
func oidcDiscoveryHandler(ctx *gin.Context) {
	directorUrlStr := param.Federation_DirectorUrl.GetString()
	if !param.Federation_DirectorUrl.IsSet() || len(directorUrlStr) == 0 {
		log.Error("Bad server configuration: Federation.DirectorUrl is not set")
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Bad server configuration: director URL is not set"})
		return
	}
	directorUrl, err := url.Parse(directorUrlStr)
	if err != nil {
		log.Error("Bad server configuration: invalid URL from Federation.DirectorUrl: ", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Bad server configuration: director URL is not valid"})
		return
	}
	if directorUrl.Scheme != "https" {
		directorUrl.Scheme = "https"
	}
	if directorUrl.Port() == "443" {
		directorUrl.Host = strings.TrimSuffix(directorUrl.Host, ":443")
	}
	jwskUrl, err := url.JoinPath(directorUrl.String(), directorJWKSPath)
	if err != nil {
		log.Errorf("Bad server configuration: cannot join %s to Federation.DirectorUrl: %s for jwks URL: %v", directorJWKSPath, directorUrl.String(), err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Bad server configuration: cannot generate JWKs URL"})
		return
	}
	rs := OpenIdDiscoveryResponse{
		Issuer:  directorUrl.String(),
		JwksUri: jwskUrl,
	}
	jsonData, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to marshal director's discovery response"})
		return
	}
	// Append a new line to the JSON data
	jsonData = append(jsonData, '\n')
	ctx.Header("Content-Disposition", "attachment; filename=pelican-director-configuration.json")
	ctx.Data(200, "application/json", jsonData)
}

// Returns director's public key
func jwksHandler(ctx *gin.Context) {
	key, err := config.GetIssuerPublicJWKS()
	if err != nil {
		log.Errorf("Failed to load director's public key: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load director's public key"})
	} else {
		jsonData, err := json.MarshalIndent(key, "", "  ")
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to marshal director's public key"})
			return
		}
		// Append a new line to the JSON data
		jsonData = append(jsonData, '\n')
		ctx.Header("Content-Disposition", "attachment; filename=public-signing-key.jwks")
		ctx.Data(200, "application/json", jsonData)
	}
}

func RegisterDirectorAuth(router *gin.RouterGroup) {
	router.GET(federationDiscoveryPath, federationDiscoveryHandler)
	router.GET(oidcDiscoveryPath, oidcDiscoveryHandler)
	router.GET(directorJWKSPath, jwksHandler)
}
