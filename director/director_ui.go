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
	"path"
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
		StorageType         server_structs.OriginStorageType `json:"storageType"`
		DisableDirectorTest bool                             `json:"disableDirectorTest"`
		// AuthURL is Deprecated. For Pelican severs, URL is used as the base URL for object access.
		// This is to maintain compatibility with the topology servers, where it uses AuthURL for
		// accessing protected objects and URL for public objects.
		AuthURL           string                      `json:"authUrl"`
		BrokerURL         string                      `json:"brokerUrl"`
		URL               string                      `json:"url"`    // This is server's XRootD URL for file transfer
		WebURL            string                      `json:"webUrl"` // This is server's Web interface and API
		Type              string                      `json:"type"`
		Latitude          float64                     `json:"latitude"`
		Longitude         float64                     `json:"longitude"`
		Caps              server_structs.Capabilities `json:"capabilities"`
		Filtered          bool                        `json:"filtered"`
		FilteredType      string                      `json:"filteredType"`
		FromTopology      bool                        `json:"fromTopology"`
		HealthStatus      HealthTestStatus            `json:"healthStatus"`
		IOLoad            float64                     `json:"ioLoad"`
		NamespacePrefixes []string                    `json:"namespacePrefixes"`
	}

	// A response struct for a server Ad that provides a detailed view into the servers data
	serverResponse struct {
		Name                string                           `json:"name"`
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
		Latitude     float64                     `json:"latitude"`
		Longitude    float64                     `json:"longitude"`
		Caps         server_structs.Capabilities `json:"capabilities"`
		Filtered     bool                        `json:"filtered"`
		FilteredType string                      `json:"filteredType"`
		FromTopology bool                        `json:"fromTopology"`
		HealthStatus HealthTestStatus            `json:"healthStatus"`
		IOLoad       float64                     `json:"ioLoad"`
		Namespaces   []NamespaceAdV2Response     `json:"namespaces"`
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
		FromTopology:        ad.FromTopology,
		HealthStatus:        healthStatus,
		IOLoad:              ad.GetIOLoad(),
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
		FromTopology:        res.FromTopology,
		HealthStatus:        res.HealthStatus,
		IOLoad:              res.IOLoad,
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
	pathParam := ctx.Param("path")
	path := path.Clean(pathParam)
	if path == "" || strings.HasSuffix(path, "/") {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Path should not be empty or ended with slash '/'",
		})
		return
	}
	queryParams := statRequest{}
	if ctx.ShouldBindQuery(&queryParams) != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid query parameters",
		})
		return
	}
	token := ""
	authHeader := ctx.Request.Header.Get("Authorization")
	if authHeader != "" {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	}
	qr := NewObjectStat().Query(
		ctx,
		path,
		server_structs.OriginType,
		queryParams.MinResponses,
		queryParams.MaxResponses,
		WithToken(token),
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

// A gin route handler that given a server hostname through path variable `name`,
// checks and adds the server to a list of servers to be bypassed when the director redirects
// object requests from the client
func handleFilterServer(ctx *gin.Context) {
	sn := strings.TrimPrefix(ctx.Param("name"), "/")
	if sn == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "'name' is a required path parameter",
		})
		return
	}
	filtered, filterType := checkFilter(sn)
	if filtered {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprint("Can't filter a server that already has been filtered with type ", filterType),
		})
		return
	}
	filteredServersMutex.Lock()
	defer filteredServersMutex.Unlock()

	// Backup the original filter type to revert in case of failure
	originalFilterType, hasOriginalFilter := filteredServers[sn]

	// Decide new filter type and update map
	// If we previously temporarily allowed a server, we switch to permFiltered (reset)
	newFilterType := tempFiltered
	if filterType == tempAllowed {
		newFilterType = permFiltered
	}
	filteredServers[sn] = newFilterType

	// Attempt to persist change in the database
	if err := setServerDowntimeFn(sn, newFilterType); err != nil {
		// Revert the change in filteredServers if SetServerDowntime fails
		if hasOriginalFilter {
			filteredServers[sn] = originalFilterType
		} else {
			delete(filteredServers, sn)
		}

		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to persist server downtime due to database error",
		})
		return
	}

	ctx.JSON(http.StatusOK, server_structs.SimpleApiResp{Status: server_structs.RespOK, Msg: "success"})
}

// A gin route handler that given a server hostname through path variable `name`,
// checks and removes the server from a list of servers to be bypassed when the director redirects
// object requests from the client
func handleAllowServer(ctx *gin.Context) {
	sn := strings.TrimPrefix(ctx.Param("name"), "/")
	if sn == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "'name' is a required path parameter",
		})
		return
	}
	filtered, ft := checkFilter(sn)
	if !filtered {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Can't allow server %s that is not being filtered", sn),
		})
		return
	}

	filteredServersMutex.Lock()
	defer filteredServersMutex.Unlock()

	// Backup the original filter (downtime) type to revert in case of failure
	originalFilterType, hasOriginalFilter := filteredServers[sn]

	// Perform actions based on the current filter type
	if ft == tempFiltered {
		// Temporarily filtered server: allow it by removing from map
		delete(filteredServers, sn)

		if err := deleteServerDowntimeFn(sn); err != nil {
			// Revert the change in filteredServers if DeleteServerDowntime fails
			if hasOriginalFilter {
				filteredServers[sn] = originalFilterType
			} else {
				delete(filteredServers, sn)
			}

			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to remove the downtime of server %s in director db", sn),
			})
			return
		}
	} else if ft == permFiltered {
		// Permanently filtered server: temporarily allow it
		filteredServers[sn] = tempAllowed

		if err := setServerDowntimeFn(sn, tempAllowed); err != nil {
			// Revert the change in filteredServers if SetServerDowntime fails
			if hasOriginalFilter {
				filteredServers[sn] = originalFilterType
			} else {
				delete(filteredServers, sn)
			}

			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to remove the downtime of server %s in director db", sn),
			})
			return
		}
	} else if ft == topoFiltered {
		// Server is disabled by OSG Topology
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Can't allow server %s that is disabled by the OSG Topology. Contact OSG admin at support@osg-htc.org to enable the server.", sn),
		})
		return
	}
	ctx.JSON(http.StatusOK, server_structs.SimpleApiResp{Status: server_structs.RespOK, Msg: "success"})
}

// Endpoint for director support contact information
func handleDirectorContact(ctx *gin.Context) {
	email := param.Director_SupportContactEmail.GetString()
	url := param.Director_SupportContactUrl.GetString()

	ctx.JSON(http.StatusOK, supportContactRes{Email: email, Url: url})
}

func RegisterDirectorWebAPI(router *gin.RouterGroup) {
	directorWebAPI := router.Group("/api/v1.0/director_ui")
	// Follow RESTful schema
	{
		directorWebAPI.GET("/servers", listServers)
		directorWebAPI.GET("/servers/:name", getServerHandler)
		directorWebAPI.GET("/servers/:name/namespaces", listServerNamespaces)
		directorWebAPI.PATCH("/servers/filter/*name", web_ui.AuthHandler, web_ui.AdminAuthHandler, handleFilterServer)
		directorWebAPI.PATCH("/servers/allow/*name", web_ui.AuthHandler, web_ui.AdminAuthHandler, handleAllowServer)
		directorWebAPI.GET("/servers/origins/stat/*path", web_ui.AuthHandler, queryOrigins)
		directorWebAPI.HEAD("/servers/origins/stat/*path", web_ui.AuthHandler, queryOrigins)
		directorWebAPI.GET("/namespaces", listNamespacesHandler)
		directorWebAPI.GET("/contact", handleDirectorContact)
	}
}
