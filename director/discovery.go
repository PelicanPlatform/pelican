/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/utils"
)

const (
	oidcDiscoveryPath       string = "/.well-known/openid-configuration"
	federationDiscoveryPath string = "/.well-known/pelican-configuration"
	directorJWKSPath        string = "/.well-known/issuer.jwks"
)

// Director hosts a discovery endpoint at federationDiscoveryPath to provide URLs to various
// Pelican central servers in a federation.
func federationDiscoveryHandler(ctx *gin.Context) {
	// Because of the class of bugs related to federation metadata hosting at the Director, we record
	// who's trying to access this endpoint as a prometheus metric
	ipAddr := utils.ClientIPAddr(ctx)
	network, ok := utils.ApplyIPMask(ipAddr.String())
	if !ok {
		log.Warningf("Failed to apply IP mask to address %s", ipAddr.String())
		network = "unknown"
	}

	// A hacky way to bootstrap service type ("who's" contacting the Director) from the user agent -- we don't use
	// the raw user agent because we must protect against cardinality explosion in prometheus.
	var serviceType string
	userAgents := ctx.Request.Header.Values("User-Agent")
	for _, ua := range userAgents {
		uaLower := strings.ToLower(ua)
		switch {
		case strings.Contains(uaLower, "director"):
			serviceType = "director"
		case strings.Contains(uaLower, "registry"):
			serviceType = "registry"
		case strings.Contains(uaLower, "origin"):
			serviceType = "origin"
		case strings.Contains(uaLower, "cache"):
			serviceType = "cache"
		}
		if serviceType != "" {
			break
		}
	}
	if serviceType == "" {
		serviceType = "unknown"
	}

	labels := prometheus.Labels{
		"network":      network,
		"service_type": serviceType,
	}
	metrics.PelicanDirectorFederationMetadataRequestsTotal.With(labels).Inc()

	// If federation metadata hosting is disabled, return an error
	if !param.Director_EnableFederationMetadataHosting.GetBool() {
		// Use 410 Gone to indicate that the resource is no longer available.
		// While it's possible it was _never_ available (an argument to use 404), 410 is a
		// louder signal to clients that they should _quit_ trying to access this endpoint.
		ctx.JSON(http.StatusGone,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg: fmt.Sprintf("This Director is configured to disallow federation metadata hosting; "+
					"your service is likely misconfigured to use a Director as its %s URL", param.Federation_DiscoveryUrl.GetName()),
			})
		return
	}

	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		log.Errorln("Bad server configuration: Federation discovery could not resolve:", err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Bad server configuration: Federation discovery could not resolve",
			})
		return
	}

	discoveryUrlStr := fedInfo.DiscoveryEndpoint
	discoveryUrl, err := url.Parse(discoveryUrlStr)
	if err != nil {
		log.Errorf("Bad server configuration: invalid URL from %s: %v", param.Federation_DiscoveryUrl.GetName(), err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Bad server configuration: discovery URL is not valid",
		})
		return
	}
	if discoveryUrl.Scheme != "https" {
		discoveryUrl.Scheme = "https"
	}

	directorUrlStr := fedInfo.DirectorEndpoint
	if directorUrlStr == "" {
		log.Error("Bad server configuration: Federation.DirectorUrl is not set")
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Bad server configuration: director URL is not set",
		})
		return
	}
	directorUrl, err := url.Parse(directorUrlStr)
	if err != nil {
		log.Error("Bad server configuration: invalid URL from Federation.DirectorUrl: ", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
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

	if discoveryUrl.String() == "" && directorUrl.String() != "" {
		// If DiscoveryUrl is not set, default to DirectorUrl because it hosts all this info
		discoveryUrl = directorUrl
	}

	registryUrlStr := fedInfo.RegistryEndpoint
	if registryUrlStr == "" {
		log.Error("Bad server configuration: Federation.RegistryUrl is not set")
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Bad server configuration: registry URL is not set",
		})
		return
	}
	registryUrl, err := url.Parse(registryUrlStr)
	if err != nil {
		log.Error("Bad server configuration: Federation.RegistryUrl is an invalid URL: ", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Bad server configuration: registry URL is not valid",
		})
		return
	}
	if registryUrl.Scheme != "https" {
		registryUrl.Scheme = "https"
	}
	if registryUrl.Port() == "443" {
		registryUrl.Host = strings.TrimSuffix(registryUrl.Host, ":443")
	}

	brokerUrl := fedInfo.BrokerEndpoint

	jwksUri := fedInfo.JwksUri
	if jwksUri == "" {
		log.Error("Bad server configuration: fail to get JwksUri: ", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Bad server configuration: unable to get JwksUri",
		})
		return
	}

	rs := pelican_url.FederationDiscovery{
		DiscoveryEndpoint:          discoveryUrl.String(),
		DirectorEndpoint:           directorUrl.String(),
		RegistryEndpoint:           registryUrl.String(),
		JwksUri:                    jwksUri,
		BrokerEndpoint:             brokerUrl,
		DirectorAdvertiseEndpoints: param.Server_DirectorUrls.GetStringSlice(),
	}

	jsonData, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to marshal federation's discovery response",
		})
		return
	}
	// Append a new line to the JSON data
	jsonData = append(jsonData, '\n')
	ctx.Header("Content-Disposition", "attachment; filename=pelican-configuration.json")
	ctx.Data(http.StatusOK, "application/json", jsonData)
}

func RegisterDirectorOIDCAPI(router *gin.RouterGroup) {
	server_utils.RegisterOIDCAPI(router, true)
}

// Register the federation metadata hosting endpoint -- we do this even if the fed metadata hosting is disabled
// because the endpoint handler will still record metrics about the attempted access (which can be used by fed
// operators to detect misconfigurations).
func RegisterFedMetadata(router *gin.RouterGroup) {
	router.GET(federationDiscoveryPath, federationDiscoveryHandler)
}
