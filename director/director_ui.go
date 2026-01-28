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
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
	"github.com/pelicanplatform/pelican/web_ui"
)

type (
	listServerRequest struct {
		ServerType string `form:"server_type"` // "cache" or "origin"
	}

	// A response struct for a server Ad that provides a minimal view into the servers data
	listServerResponse struct {
		Name                string                           `json:"name"`
		ServerID            string                           `json:"serverId"`
		StorageType         server_structs.OriginStorageType `json:"storageType"`
		DisableDirectorTest bool                             `json:"disableDirectorTest"`
		// AuthURL is Deprecated. For Pelican severs, URL is used as the base URL for object access.
		// This is to maintain compatibility with the topology servers, where it uses AuthURL for
		// accessing protected objects and URL for public objects.
		AuthURL      string                      `json:"authUrl"`
		BrokerURL    string                      `json:"brokerUrl"`
		URL          string                      `json:"url"`    // This is server's XRootD URL for file transfer
		WebURL       string                      `json:"webUrl"` // This is server's Web interface and API
		Type         string                      `json:"type"`
		Coordinate   server_structs.Coordinate   `json:"coordinate"`
		Latitude     float64                     `json:"latitude"`
		Longitude    float64                     `json:"longitude"`
		Caps         server_structs.Capabilities `json:"capabilities"`
		Filtered     bool                        `json:"filtered"`
		FilteredType string                      `json:"filteredType"`
		Downtimes    []server_structs.Downtime   `json:"downtimes"`
		FromTopology bool                        `json:"fromTopology"`
		// HealthStatus and ServerStatus should really have been the same concept
		// (some component of the server can indicate its health, affecting the
		// overall server's health), but it looks like they grew organically and
		// bringing them into a single concept would be a breaking change.
		// HealthStatus is for the director-->XRootDServer health test, while
		// ServerStatus is for the Origin/Cache to report other aspects of its health
		HealthStatus           HealthTestStatus `json:"healthStatus"`
		ServerStatus           string           `json:"serverStatus"`
		IOLoad                 float64          `json:"ioLoad"`
		StatusWeight           float64          `json:"statusWeight"`           // The current EWMA-derived weight for this server's status, populated by the Director
		StatusWeightLastUpdate int64            `json:"statusWeightLastUpdate"` // The last time the status weight was updated, in epoch seconds
		RegistryPrefix         string           `json:"registryPrefix"`
		NamespacePrefixes      []string         `json:"namespacePrefixes"`
		Version                string           `json:"version"`
	}

	// A response struct for a server Ad that provides a detailed view into the servers data
	// ** BE WARNED **
	// This struct and associated functions need to be kept in sync with BOTH the listServerResponse
	// and the server_structs.ServerAd.
	serverResponse struct {
		Name                string                           `json:"name"`
		ServerID            string                           `json:"serverId"`
		RegistryPrefix      string                           `json:"registryPrefix"`
		StorageType         server_structs.OriginStorageType `json:"storageType"`
		DisableDirectorTest bool                             `json:"disableDirectorTest"`
		// AuthURL is Deprecated. For Pelican severs, URL is used as the base URL for object access.
		// This is to maintain compatibility with the topology servers, where it uses AuthURL for
		// accessing protected objects and URL for public objects.
		AuthURL                string                      `json:"authUrl"`
		BrokerURL              string                      `json:"brokerUrl"`
		URL                    string                      `json:"url"`    // This is server's XRootD URL for file transfer
		WebURL                 string                      `json:"webUrl"` // This is server's Web interface and API
		Type                   string                      `json:"type"`
		Coordinate             server_structs.Coordinate   `json:"coordinate"`
		Latitude               float64                     `json:"latitude"`
		Longitude              float64                     `json:"longitude"`
		Caps                   server_structs.Capabilities `json:"capabilities"`
		Filtered               bool                        `json:"filtered"`
		FilteredType           string                      `json:"filteredType"`
		Downtimes              []server_structs.Downtime   `json:"downtimes"`
		FromTopology           bool                        `json:"fromTopology"`
		HealthStatus           HealthTestStatus            `json:"healthStatus"`
		ServerStatus           string                      `json:"serverStatus"` // see comment in listServerResponse
		IOLoad                 float64                     `json:"ioLoad"`
		StatusWeight           float64                     `json:"statusWeight"`           // The current EWMA-derived weight for this server's status, populated by the Director
		StatusWeightLastUpdate int64                       `json:"statusWeightLastUpdate"` // The last time the status weight was updated, in epoch seconds
		Namespaces             []NamespaceAdV2Response     `json:"namespaces"`
		Version                string                      `json:"version"`
	}

	// TokenIssuerResponse creates a response struct for TokenIssuer
	TokenIssuerResponse struct {
		BasePaths       []string `json:"basePaths"`
		RestrictedPaths []string `json:"restrictedPaths"`
		IssuerUrl       string   `json:"issuer"`
	}

	// TokenGenResponse creates a response struct for TokenGen
	TokenGenResponse struct {
		Strategy         server_structs.StrategyType `json:"strategy"`
		VaultServer      string                      `json:"vaultServer"`
		MaxScopeDepth    uint                        `json:"maxScopeDepth"`
		CredentialIssuer string                      `json:"issuer"`
	}

	// NamespaceAdV2Response creates a response struct for NamespaceAdV2
	NamespaceAdV2Response struct {
		Path         string                      `json:"path"`
		Caps         server_structs.Capabilities `json:"capabilities"`
		Generation   []TokenGenResponse          `json:"tokenGeneration"`
		Issuer       []TokenIssuerResponse       `json:"tokenIssuer"`
		FromTopology bool                        `json:"fromTopology"`
	}

	// NamespaceAdV2MappedResponse creates a response struct for NamespaceAdV2 with mapped origins and caches
	NamespaceAdV2MappedResponse struct {
		Path         string                      `json:"path"`
		Caps         server_structs.Capabilities `json:"capabilities"`
		Generation   []TokenGenResponse          `json:"tokenGeneration"`
		Issuer       []TokenIssuerResponse       `json:"tokenIssuer"`
		FromTopology bool                        `json:"fromTopology"`
		Origins      []string                    `json:"origins"`
		Caches       []string                    `json:"caches"`
	}

	statRequest struct {
		MinResponses int `form:"min_responses"`
		MaxResponses int `form:"max_responses"`
	}

	supportContactRes struct {
		Email string `json:"email"`
		Url   string `json:"url"`
	}
)

func (req listServerRequest) ToInternalServerType() server_structs.ServerType {
	if req.ServerType == strings.ToLower(server_structs.CacheType.String()) {
		return server_structs.CacheType
	}
	if req.ServerType == strings.ToLower(server_structs.OriginType.String()) {
		return server_structs.OriginType
	}
	return server_structs.ServerType(0)
}

func listServers(ctx *gin.Context) {
	queryParams := listServerRequest{}
	if ctx.ShouldBindQuery(&queryParams) != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid query parameters",
		})
		return
	}
	var servers []*server_structs.Advertisement
	if queryParams.ServerType != "" {
		if !strings.EqualFold(queryParams.ServerType, server_structs.OriginType.String()) && !strings.EqualFold(queryParams.ServerType, server_structs.CacheType.String()) {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Invalid server type",
			})
			return
		}
		servers = listAdvertisement([]server_structs.ServerType{server_structs.ServerType(queryParams.ToInternalServerType())})
	} else {
		servers = listAdvertisement([]server_structs.ServerType{server_structs.OriginType, server_structs.CacheType})
	}
	healthTestUtilsMutex.RLock()
	defer healthTestUtilsMutex.RUnlock()
	resList := make([]listServerResponse, 0)
	for _, server := range servers {
		res := advertisementToServerResponse(server)
		listRes := serverResponseToListServerResponse(res)
		resList = append(resList, listRes)
	}
	ctx.JSON(http.StatusOK, resList)
}

// Convert NamespaceAdV2 to namespaceResponse
func namespaceAdV2ToResponse(ns *server_structs.NamespaceAdV2) NamespaceAdV2Response {
	res := NamespaceAdV2Response{
		Path:         ns.Path,
		Caps:         ns.Caps,
		FromTopology: ns.FromTopology,
	}
	for _, gen := range ns.Generation {
		res.Generation = append(res.Generation, TokenGenResponse{
			Strategy:         gen.Strategy,
			VaultServer:      gen.VaultServer,
			MaxScopeDepth:    gen.MaxScopeDepth,
			CredentialIssuer: gen.CredentialIssuer.String(),
		})
	}
	for _, issuer := range ns.Issuer {
		res.Issuer = append(res.Issuer, TokenIssuerResponse{
			BasePaths:       issuer.BasePaths,
			RestrictedPaths: issuer.RestrictedPaths,
			IssuerUrl:       issuer.IssuerUrl.String(),
		})
	}
	return res
}

// namespaceAdV2ToMappedResponse converts a NamespaceAdV2 to a NamespaceAdV2MappedResponse
func namespaceAdV2ToMappedResponse(ns *server_structs.NamespaceAdV2) NamespaceAdV2MappedResponse {
	nsRes := namespaceAdV2ToResponse(ns)
	return NamespaceAdV2MappedResponse{
		Path:       nsRes.Path,
		Caps:       nsRes.Caps,
		Generation: nsRes.Generation,
		Issuer:     nsRes.Issuer,
		Origins:    []string{},
		Caches:     []string{},
	}
}

// Convert Advertisement to serverResponse
func advertisementToServerResponse(ad *server_structs.Advertisement) serverResponse {
	healthStatus := HealthStatusUnknown
	healthUtil, ok := healthTestUtils[ad.URL.String()]
	if ok {
		healthStatus = healthUtil.Status
	} else {
		if ad.DisableDirectorTest {
			healthStatus = HealthStatusDisabled
		} else {
			if !ad.FromTopology {
				log.Debugf("advertisementToServerResponse: healthTestUtils not found for server at %s", ad.URL.String())
			}
		}
	}
	filtered, ft := checkFilter(ad.Name)
	res := serverResponse{
		Name:                ad.Name,
		ServerID:            ad.ServerID,
		RegistryPrefix:      ad.RegistryPrefix,
		StorageType:         ad.StorageType,
		DisableDirectorTest: ad.DisableDirectorTest,
		BrokerURL:           ad.BrokerURL.String(),
		AuthURL:             ad.AuthURL.String(),
		URL:                 ad.URL.String(),
		WebURL:              ad.WebURL.String(),
		Type:                ad.Type,
		Latitude:            ad.Latitude,
		Longitude:           ad.Longitude,
		Caps:                ad.Caps,
		Filtered:            filtered,
		FilteredType:        ft.String(),
		Downtimes:           ad.Downtimes,
		FromTopology:        ad.FromTopology,
		HealthStatus:        healthStatus,
		ServerStatus:        ad.Status,
		IOLoad:              ad.GetIOLoad(),
		Version:             ad.Version,
	}
	for _, ns := range ad.NamespaceAds {
		nsRes := namespaceAdV2ToResponse(&ns)
		res.Namespaces = append(res.Namespaces, nsRes)
	}
	return res
}

// Convert serverResponse to a listServerResponse
func serverResponseToListServerResponse(res serverResponse) listServerResponse {
	listRes := listServerResponse{
		Name:                res.Name,
		ServerID:            res.ServerID,
		RegistryPrefix:      res.RegistryPrefix,
		StorageType:         res.StorageType,
		DisableDirectorTest: res.DisableDirectorTest,
		BrokerURL:           res.BrokerURL,
		AuthURL:             res.AuthURL,
		URL:                 res.URL,
		WebURL:              res.WebURL,
		Type:                res.Type,
		Latitude:            res.Latitude,
		Longitude:           res.Longitude,
		Caps:                res.Caps,
		Filtered:            res.Filtered,
		FilteredType:        res.FilteredType,
		Downtimes:           res.Downtimes,
		FromTopology:        res.FromTopology,
		HealthStatus:        res.HealthStatus,
		ServerStatus:        res.ServerStatus,
		IOLoad:              res.IOLoad,
		Version:             res.Version,
	}
	for _, ns := range res.Namespaces {
		listRes.NamespacePrefixes = append(listRes.NamespacePrefixes, ns.Path)
	}
	return listRes
}

// Given a server name returns the server advertisement
func getServer(serverName string) *server_structs.Advertisement {
	servers := listAdvertisement([]server_structs.ServerType{server_structs.OriginType, server_structs.CacheType})
	for _, server := range servers {
		if server.Name == serverName {
			return server
		}
	}
	return nil
}

// API wrapper around getServer to return a serverResponse
func getServerHandler(ctx *gin.Context) {
	serverName := ctx.Param("name")
	if serverName == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Server name is required",
		})
		return
	}
	server := getServer(serverName)
	if server == nil {
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Server not found",
		})
		return
	}
	serverResponse := advertisementToServerResponse(server)
	ctx.JSON(http.StatusOK, serverResponse)
}

// Get all namespaces for a server
func listServerNamespaces(ctx *gin.Context) {
	serverName := ctx.Param("name")
	if serverName == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Server name is required",
		})
		return
	}
	server := getServer(serverName)
	if server == nil {
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Server not found",
		})
		return
	}
	var nsRes []NamespaceAdV2Response
	for _, n := range server.NamespaceAds {
		nsRes = append(nsRes, namespaceAdV2ToResponse(&n))
	}
	ctx.JSON(http.StatusOK, nsRes)
}

// Get list of all namespaces as a response
func listNamespaceResponses() []NamespaceAdV2MappedResponse {

	namespaceMap := make(map[string]NamespaceAdV2MappedResponse)

	for _, a := range listAdvertisement([]server_structs.ServerType{server_structs.OriginType, server_structs.CacheType}) {
		s := a.ServerAd
		for _, ns := range a.NamespaceAds {

			// If the namespace is not in the map, add it
			if _, ok := namespaceMap[ns.Path]; !ok {
				namespaceMap[ns.Path] = namespaceAdV2ToMappedResponse(&ns)
			}

			// Add the server name to its type
			nsRes := namespaceMap[ns.Path]
			if s.Type == server_structs.OriginType.String() {
				nsRes.Origins = append(nsRes.Origins, s.Name)
			} else if s.Type == server_structs.CacheType.String() {
				nsRes.Caches = append(nsRes.Caches, s.Name)
			}
			namespaceMap[ns.Path] = nsRes
		}
	}

	return utils.MapToSlice(namespaceMap)
}

// Get list of all namespaces
func listNamespacesHandler(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, listNamespaceResponses())
}

// Issue a stat query to origins for an object and return which origins serve the object
func queryOrigins(ctx *gin.Context) {
	requestId := getRequestID(ctx)
	path := getObjectPathFromRequest(ctx)
	if path == "" || strings.HasSuffix(path, "/") {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Path should not be empty or ended with slash '/': Request ID: " + requestId.String(),
		})
		return
	}
	queryParams := statRequest{}
	if ctx.ShouldBindQuery(&queryParams) != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid query parameters: Request ID: " + requestId.String(),
		})
		return
	}
	token := ""
	authHeader := ctx.Request.Header.Get("Authorization")
	if authHeader != "" {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	}

	oAds, _, err := getSortedAds(ctx, requestId)
	if err != nil {
		switch err.(type) {
		case noOriginsForNsErr:
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("No origins found for the requested path: %v: Request ID: %s", err, requestId.String()),
			})
		case noOriginsForReqErr:
			ctx.JSON(http.StatusMethodNotAllowed, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg: fmt.Sprintf("Discovered origins for the namespace, but none support the request: %v: "+
					"See '%s' to troubleshoot available origins/caches and their capabilities: Request ID: %s", err, param.Server_ExternalWebUrl.GetString(), requestId.String()),
			})
		case objectNotFoundErr:
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("No origins reported possession of the object: %v: Are you sure it exists?: Request ID: %s", err, requestId.String()),
			})
		case directorStartupErr:
			ctx.JSON(http.StatusTooManyRequests, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("%v: Request ID: %s", err, requestId.String()),
			})
		default:
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to get/sort origin ads for the requested path: %v: Request ID: %s", err, requestId.String()),
			})
		}
	}

	origins := make([]server_structs.ServerAd, 0, len(oAds))
	for _, oAd := range oAds {
		origins = append(origins, oAd.ServerAd)
	}

	qr := NewObjectStat().Query(
		ctx,
		path,
		server_structs.OriginType,
		queryParams.MinResponses,
		queryParams.MaxResponses,
		WithToken(token),
		withOriginAds(origins),
	)
	if qr.Status == querySuccessful {
		ctx.JSON(http.StatusOK, qr)
		return
	} else if qr.Status != queryFailed {
		log.Errorf("Unknown stat call status: %#v", qr)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Server error with stat call. Unknown stat call status: " + string(qr.Status),
		})
		return
	}
	// This is the case where qr.Status == queryFailed
	if qr.ErrorType == "" {
		log.Errorf("A failed stat call doesn't contain error: %#v", qr)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Server error with stat call. A failed stat call doesn't contain error.",
		})
	}
	switch qr.ErrorType {
	case queryNoPrefixMatchErr:
		ctx.JSON(http.StatusNotFound, qr)
		return
	case queryParameterErr:
		ctx.JSON(http.StatusBadRequest, qr)
		return
	case queryInsufficientResErr:
		if len(qr.Objects) == 0 {
			ctx.JSON(http.StatusNotFound, qr)
			return
		}
		ctx.JSON(http.StatusOK, qr)
		return
	default:
		errMsg := fmt.Sprintf("Unknown error type %q from the stat call with path: %s, min responses: %d, max responses: %d.", qr.ErrorType, path, queryParams.MinResponses, queryParams.MaxResponses)
		log.Error(errMsg)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    errMsg,
		})
		return
	}
}

// Endpoint for director support contact information
func handleDirectorContact(ctx *gin.Context) {
	email := param.Director_SupportContactEmail.GetString()
	url := param.Director_SupportContactUrl.GetString()

	ctx.JSON(http.StatusOK, supportContactRes{Email: email, Url: url})
}

// List in-memory downtimes for all servers.
// Aggregate downtimes from registry, topology and origin/cache servers.
func listDowntimeDetails(ctx *gin.Context) {
	downtimes, err := getCachedDowntimes("")
	if err != nil {
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Server not found: " + err.Error(),
		})
		return
	}
	ctx.JSON(http.StatusOK, downtimes)
}

// Get in-memory downtimes for a specific server.
// Aggregate downtimes from registry, topology and origin/cache servers.
func getDowntimeDetails(ctx *gin.Context) {
	serverName := ctx.Param("name")
	downtimes, err := getCachedDowntimes(serverName)
	if err != nil {
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Server not found: " + err.Error(),
		})
		return
	}
	ctx.JSON(http.StatusOK, downtimes)
}

// Get the current federation metadata discrepancy status.
// This compares what the Director serves vs what the Discovery URL serves.
func getFederationDiscrepancy(ctx *gin.Context) {
	discrepancy := GetMetadataDiscrepancy()
	ctx.JSON(http.StatusOK, discrepancy)
}

func RegisterDirectorWebAPI(router *gin.RouterGroup) {
	directorWebAPI := router.Group("/api/v1.0/director_ui")
	// Follow RESTful schema
	{
		directorWebAPI.GET("/servers", listServers)
		directorWebAPI.GET("/servers/:name", getServerHandler)
		directorWebAPI.GET("/servers/:name/namespaces", listServerNamespaces)
		directorWebAPI.GET("/servers/:name/downtimes", getDowntimeDetails)
		directorWebAPI.GET("/servers/origins/stat/*path", web_ui.AuthHandler, queryOrigins)
		directorWebAPI.HEAD("/servers/origins/stat/*path", web_ui.AuthHandler, queryOrigins)
		directorWebAPI.GET("/namespaces", listNamespacesHandler)
		directorWebAPI.GET("/contact", handleDirectorContact)
		directorWebAPI.GET("/downtimes", listDowntimeDetails)
		directorWebAPI.GET("/federation/discrepancy", web_ui.AuthHandler, web_ui.AdminAuthHandler, getFederationDiscrepancy)
	}
}
