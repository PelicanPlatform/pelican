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
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/common"
	"github.com/pelicanplatform/pelican/web_ui"
	log "github.com/sirupsen/logrus"
)

type (
	listServerRequest struct {
		ServerType string `form:"server_type"` // "cache" or "origin"
	}

	listServerResponse struct {
		Name      string            `json:"name"`
		AuthURL   string            `json:"authUrl"`
		URL       string            `json:"url"`    // This is server's XRootD URL for file transfer
		WebURL    string            `json:"webUrl"` // This is server's Web interface and API
		Type      common.ServerType `json:"type"`
		Latitude  float64           `json:"latitude"`
		Longitude float64           `json:"longitude"`
		Status    HealthTestStatus  `json:"status"`
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
)

func (req listServerRequest) ToInternalServerType() common.ServerType {
	if req.ServerType == "cache" {
		return common.CacheType
	}
	if req.ServerType == "origin" {
		return common.OriginType
	}
	return ""
}

func listServers(ctx *gin.Context) {
	queryParams := listServerRequest{}
	if ctx.ShouldBindQuery(&queryParams) != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid query parameters"})
		return
	}
	var servers []common.ServerAd
	if queryParams.ServerType != "" {
		if !strings.EqualFold(queryParams.ServerType, string(common.OriginType)) && !strings.EqualFold(queryParams.ServerType, string(common.CacheType)) {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server type"})
			return
		}
		servers = listServerAds([]common.ServerType{common.ServerType(queryParams.ToInternalServerType())})
	} else {
		servers = listServerAds([]common.ServerType{common.OriginType, common.CacheType})
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
		res := listServerResponse{
			Name:      server.Name,
			AuthURL:   server.AuthURL.String(),
			URL:       server.URL.String(),
			WebURL:    server.WebURL.String(),
			Type:      server.Type,
			Latitude:  server.Latitude,
			Longitude: server.Longitude,
			Status:    healthStatus,
		}
		resList = append(resList, res)
	}
	ctx.JSON(http.StatusOK, resList)
}

func queryOrigins(ctx *gin.Context) {
	pathParam := ctx.Param("path")
	path := path.Clean(pathParam)
	if path == "" || strings.HasSuffix(path, "/") {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Path should not be empty or ended with slash '/'"})
		return
	}
	queryParams := statRequest{}
	if ctx.ShouldBindQuery(&queryParams) != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid query parameters"})
		return
	}
	meta, msg, err := NewObjectStat().Query(path, ctx, queryParams.MinResponses, queryParams.MaxResponses)
	if err != nil {
		if err == NoPrefixMatchError {
			ctx.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		} else if err == ParameterError {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		} else if err == InsufficientResError {
			// Insufficient response does not cause a 500 error, but OK field in reponse is false
			if len(meta) < 1 {
				ctx.JSON(http.StatusNotFound, gin.H{"error": msg + " If no object is available, please check if the object is in a public namespace."})
				return
			}
			res := statResponse{Message: msg, Metadata: meta, OK: false}
			ctx.JSON(http.StatusOK, res)
		} else {
			log.Errorf("Error in NewObjectStat with path: %s, min responses: %d, max responses: %d. %v", path, queryParams.MinResponses, queryParams.MaxResponses, err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	if len(meta) < 1 {
		ctx.JSON(http.StatusNotFound, gin.H{"error": err.Error() + " If no object is available, please check if the object is in a public namespace."})
	}
	res := statResponse{Message: msg, Metadata: meta, OK: true}
	ctx.JSON(http.StatusOK, res)
}

func RegisterDirectorWebAPI(router *gin.RouterGroup) {
	directorWebAPI := router.Group("/api/v1.0/director_ui")
	// Follow RESTful schema
	{
		directorWebAPI.GET("/servers", listServers)
		directorWebAPI.GET("/servers/origins/stat/*path", web_ui.AuthHandler, queryOrigins)
		directorWebAPI.HEAD("/servers/origins/stat/*path", web_ui.AuthHandler, queryOrigins)
	}
}
