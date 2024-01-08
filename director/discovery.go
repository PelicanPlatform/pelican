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

package director

import (
	"encoding/json"

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
	openIdDiscoveryPath     string = "/.well-known/openid-configuration"
	federationDiscoveryPath string = "/.well-known/pelican-configuration"
	directorJWKSPath        string = "/.well-known/issuer.jwks"
)

func federationDiscoveryHandler(ctx *gin.Context) {
	directorUrl := param.Federation_DirectorUrl.GetString()
	if len(directorUrl) == 0 {
		ctx.JSON(500, gin.H{"error": "Bad server configuration: Director URL is not set"})
		return
	}
	registryUrl := param.Federation_RegistryUrl.GetString()
	if len(registryUrl) == 0 {
		ctx.JSON(500, gin.H{"error": "Bad server configuration: Registry URL is not set"})
		return
	}

	rs := config.FederationDiscovery{
		DirectorEndpoint:              directorUrl,
		NamespaceRegistrationEndpoint: registryUrl,
		JwksUri:                       directorUrl + directorJWKSPath,
	}

	jsonData, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		ctx.JSON(500, gin.H{"error": "Failed to marshal federation's discovery response"})
		return
	}
	// Append a new line to the JSON data
	jsonData = append(jsonData, '\n')
	ctx.Header("Content-Disposition", "attachment; filename=pelican-configuration.json")
	ctx.Data(200, "application/json", jsonData)
}

// Director metadata discovery endpoint for OpenID style
// token authentication, providing issuer endpoint and director's jwks endpoint
func openIdDiscoveryHandler(ctx *gin.Context) {
	directorUrl := param.Federation_DirectorUrl.GetString()
	if len(directorUrl) == 0 {
		ctx.JSON(500, gin.H{"error": "Bad server configuration: Director URL is not set"})
		return
	}
	rs := OpenIdDiscoveryResponse{
		Issuer:  directorUrl,
		JwksUri: directorUrl + directorJWKSPath,
	}
	jsonData, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		ctx.JSON(500, gin.H{"error": "Failed to marshal director's discovery response"})
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
		ctx.JSON(500, gin.H{"error": "Failed to load director's public key"})
	} else {
		jsonData, err := json.MarshalIndent(key, "", "  ")
		if err != nil {
			ctx.JSON(500, gin.H{"error": "Failed to marshal director's public key"})
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
	router.GET(openIdDiscoveryPath, openIdDiscoveryHandler)
	router.GET(directorJWKSPath, jwksHandler)
}
