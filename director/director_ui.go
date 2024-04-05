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
	"net/url"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/web_ui"
	log "github.com/sirupsen/logrus"
)

type (
	listServerRequest struct {
		ServerType string `form:"server_type"` // "cache" or "origin"
	}

	listServerResponse struct {
		Name         string                    `json:"name"`
		AuthURL      string                    `json:"authUrl"`
		BrokerURL    string                    `json:"brokerUrl"`
		URL          string                    `json:"url"`    // This is server's XRootD URL for file transfer
		WebURL       string                    `json:"webUrl"` // This is server's Web interface and API
		Type         server_structs.ServerType `json:"type"`
		Latitude     float64                   `json:"latitude"`
		Longitude    float64                   `json:"longitude"`
		Writes       bool                      `json:"enableWrite"`
		DirectReads  bool                      `json:"enableFallbackRead"`
		Filtered     bool                      `json:"filtered"`
		FilteredType filterType                `json:"filteredType"`
		Status       HealthTestStatus          `json:"status"`
	}

	statResponse struct {
		OK       bool              `json:"ok"`
		Message  string            `json:"message"`
		Metadata []*objectMetadata `json:"metadata"`
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
	if req.ServerType == "cache" {
		return server_structs.CacheType
	}
	if req.ServerType == "origin" {
		return server_structs.OriginType
	}
	return ""
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
	var servers []server_structs.ServerAd
	if queryParams.ServerType != "" {
		if !strings.EqualFold(queryParams.ServerType, string(server_structs.OriginType)) && !strings.EqualFold(queryParams.ServerType, string(server_structs.CacheType)) {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Invalid server type",
			})
			return
		}
		servers = listServerAds([]server_structs.ServerType{server_structs.ServerType(queryParams.ToInternalServerType())})
	} else {
		servers = listServerAds([]server_structs.ServerType{server_structs.OriginType, server_structs.CacheType})
	}
	healthTestUtilsMutex.RLock()
	defer healthTestUtilsMutex.RUnlock()
	resList := make([]listServerResponse, 0)
	for _, server := range servers {
		healthStatus := HealthStatusUnknown
		healthUtil, ok := healthTestUtils[server]
		if ok {
			healthStatus = healthUtil.Status
		}
		filtered, ft := checkFilter(server.Name)
		var auth_url string
		if server.AuthURL == (url.URL{}) {
			auth_url = server.URL.String()
		} else {
			auth_url = server.AuthURL.String()
		}
		res := listServerResponse{
			Name:         server.Name,
			BrokerURL:    server.BrokerURL.String(),
			AuthURL:      auth_url,
			URL:          server.URL.String(),
			WebURL:       server.WebURL.String(),
			Type:         server.Type,
			Latitude:     server.Latitude,
			Longitude:    server.Longitude,
			Writes:       server.Writes,
			DirectReads:  server.DirectReads,
			Filtered:     filtered,
			FilteredType: ft,
			Status:       healthStatus,
		}
		resList = append(resList, res)
	}
	ctx.JSON(http.StatusOK, resList)
}

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
	meta, msg, err := NewObjectStat().Query(path, ctx, queryParams.MinResponses, queryParams.MaxResponses)
	if err != nil {
		if err == NoPrefixMatchError {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    err.Error(),
			})
			return
		} else if err == ParameterError {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    err.Error(),
			})
			return
		} else if err == InsufficientResError {
			// Insufficient response does not cause a 500 error, but OK field in reponse is false
			if len(meta) < 1 {
				ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    msg + " If no object is available, please check if the object is in a public namespace.",
				})
				return
			}
			res := statResponse{Message: msg, Metadata: meta, OK: false}
			ctx.JSON(http.StatusOK, res)
		} else {
			log.Errorf("Error in NewObjectStat with path: %s, min responses: %d, max responses: %d. %v", path, queryParams.MinResponses, queryParams.MaxResponses, err)
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    err.Error(),
			})
			return
		}
	}
	if len(meta) < 1 {
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error() + " If no object is available, please check if the object is in a public namespace.",
		})
	}
	res := statResponse{Message: msg, Metadata: meta, OK: true}
	ctx.JSON(http.StatusOK, res)
}

// A gin route handler that given a server hostname through path variable `name`,
// checks and adds the server to a list of servers to be bypassed when the director redirects
// object requests from the client
func handleFilterServer(ctx *gin.Context) {
	sn := strings.TrimPrefix(ctx.Param("name"), "/")
	if sn == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "name is a required path parameter",
		})
		return
	}
	filtered, filterType := checkFilter(sn)
	if filtered {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprint("Can't filter a server that already has been fitlered with type ", filterType),
		})
		return
	}
	filteredServersMutex.Lock()
	defer filteredServersMutex.Unlock()

	// If we previously temporarily allowed a server, we switch to permFiltered (reset)
	if filterType == tempAllowed {
		filteredServers[sn] = permFiltered
	} else {
		filteredServers[sn] = tempFiltered
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
			Msg:    "name is a required path parameter",
		})
		return
	}
	filtered, ft := checkFilter(sn)
	if !filtered {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprint("Can't allow a server that is not being filtered: ", ft),
		})
		return
	}

	filteredServersMutex.Lock()
	defer filteredServersMutex.Unlock()

	if ft == tempFiltered {
		// For temporarily filtered server, allowing them by removing the server from the map
		delete(filteredServers, sn)
	} else if ft == permFiltered {
		// For servers to filter from the config, temporarily allow the server
		filteredServers[sn] = tempAllowed
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
		directorWebAPI.PATCH("/servers/filter/*name", web_ui.AuthHandler, web_ui.AdminAuthHandler, handleFilterServer)
		directorWebAPI.PATCH("/servers/allow/*name", web_ui.AuthHandler, web_ui.AdminAuthHandler, handleAllowServer)
		directorWebAPI.GET("/servers/origins/stat/*path", web_ui.AuthHandler, queryOrigins)
		directorWebAPI.HEAD("/servers/origins/stat/*path", web_ui.AuthHandler, queryOrigins)
		directorWebAPI.GET("/contact", handleDirectorContact)
	}
}
